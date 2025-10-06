// Command merge-sql-schemas applies all SQL up migrations against an in-memory
// SQLite database and exports a consolidated schema with a deterministic order.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // Register the pure-Go SQLite driver.
)

func main() {
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

const (
	sqldbDir       = "wallet/internal/db"
	migrationDir   = sqldbDir + "/migrations/sqlite"
	schemaOutDir   = sqldbDir + "/schemas"
	schemaFilename = "generated_sqlite_schema.sql"

	dirPerm        = 0o750
	filePerm       = 0o600
	defaultTimeout = 3 * time.Minute
)

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return fmt.Errorf("failed to open in-memory db: %w", err)
	}

	defer func() { _ = db.Close() }()

	upFiles, err := collectMigrationFiles(migrationDir)
	if err != nil {
		return err
	}

	err = applyMigrations(ctx, db, migrationDir, upFiles)
	if err != nil {
		return err
	}

	schema, err := extractSchema(ctx, db)
	if err != nil {
		return err
	}

	outPath := filepath.Join(schemaOutDir, schemaFilename)

	err = writeSchema(outPath, schema)
	if err != nil {
		return err
	}

	log.Printf("Final consolidated schema written to %s", outPath)

	return nil
}

func collectMigrationFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read migration dir: %w", err)
	}

	var upFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			upFiles = append(upFiles, e.Name())
		}
	}

	sort.Strings(upFiles)

	return upFiles, nil
}

func applyMigrations(
	ctx context.Context,
	db *sql.DB,
	dir string,
	files []string,
) error {

	for _, fname := range files {
		path := filepath.Join(dir, fname)
		// #nosec G304 -- Path is built from a known base directory
		// and filenames discovered via os.ReadDir within the repo.
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf(
				"failed to read migration %s: %w",
				fname, err,
			)
		}

		_, err = db.ExecContext(ctx, string(data))
		if err != nil {
			return fmt.Errorf(
				"failed to exec migration %s: %w",
				fname, err,
			)
		}
	}

	return nil
}

func extractSchema(ctx context.Context, db *sql.DB) (string, error) {
	rows, err := db.QueryContext(ctx, `
        SELECT type, name, sql FROM sqlite_master
        WHERE type IN ('table','view','index') AND sql IS NOT NULL
        ORDER BY
            CASE type
                WHEN 'table' THEN 1
                WHEN 'view' THEN 2
                WHEN 'index' THEN 3
                ELSE 4
            END,
            name`)
	if err != nil {
		return "", fmt.Errorf("failed to query schema: %w", err)
	}

	defer func() { _ = rows.Close() }()

	var b strings.Builder
	for rows.Next() {
		var typ, name, sqlDef string

		err := rows.Scan(&typ, &name, &sqlDef)
		if err != nil {
			return "", fmt.Errorf(
				"failed to scan schema row: %w",
				err,
			)
		}

		b.WriteString(sqlDef)
		b.WriteString(";\n")
	}

	err = rows.Err()
	if err != nil {
		return "", fmt.Errorf("failed to iterate schema rows: %w", err)
	}

	return b.String(), nil
}

func writeSchema(outPath, schema string) error {
	outDir := filepath.Dir(outPath)

	// Ensure the destination directory exists.
	err := os.MkdirAll(outDir, dirPerm)
	if err != nil {
		return fmt.Errorf("failed to create schema dir: %w", err)
	}

	err = os.WriteFile(outPath, []byte(schema), filePerm)
	if err != nil {
		return fmt.Errorf("failed to write schema file: %w", err)
	}

	return nil
}
