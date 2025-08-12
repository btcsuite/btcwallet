# sqltest

The `sqltest` package provides utilities for writing database integration tests that work consistently across multiple database engines (PostgreSQL and SQLite).

## Basic Usage

The primary entry point is `RunDatabaseTest`, which runs your test function against both PostgreSQL and SQLite databases:

```go
func TestMyDatabaseCode(t *testing.T) {
    sqltest.RunDatabaseTest(t, func(t *testing.T, dbFactory sqltest.DBFactory) {
        // Get a fresh database connection
        db := dbFactory(t)

        // Use `db` to perform your database operations
    })
}
```

See `db_test.go` for complete examples, including:
- `TestDatabaseIsolation`: Demonstrates parallel test isolation
- `TestDatabaseMultipleRecordsOps`: Shows CRUD operations

## Test Isolation

Each test gets its own isolated database:
- **PostgreSQL**: A new database is created in the shared container
- **SQLite**: A new file-based database is created in a temp directory

Databases are automatically cleaned up when tests complete.


## Performance Considerations

- PostgreSQL container is shared across all tests in a package
- Database names are deterministic based on test names for proper Go test caching
- Tests can run in parallel safely
