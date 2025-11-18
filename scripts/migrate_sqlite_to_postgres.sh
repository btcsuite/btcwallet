#!/usr/bin/env bash
# Migrate data from SQLite to PostgreSQL using pgloader
#
# Usage:
#   ./scripts/migrate_sqlite_to_postgres.sh /path/to/wallet.db postgresql://user:pass@localhost:5432/dbname
#   ./scripts/migrate_sqlite_to_postgres.sh  # Uses defaults from environment variables
#
# Environment variables:
#   SQLITE_DB_PATH    - Path to SQLite database file (default: ./wallet.db)
#   POSTGRES_URL      - PostgreSQL connection URL (default: postgresql://localhost/btcwallet)

set -e

# Default values
SQLITE_DB="${1:-${SQLITE_DB_PATH:-./wallet.db}}"
POSTGRES_URL="${2:-${POSTGRES_URL:-postgresql://localhost/btcwallet}}"

# Validate SQLite database exists
if [[ ! -f "${SQLITE_DB}" ]]; then
    echo "Error: SQLite database not found at '${SQLITE_DB}'"
    echo ""
    echo "Usage:"
    echo "  $0 /path/to/wallet.db postgresql://user:pass@host:port/dbname"
    echo ""
    echo "Or set environment variables:"
    echo "  export SQLITE_DB_PATH=/path/to/wallet.db"
    echo "  export POSTGRES_URL=postgresql://user:pass@host:port/dbname"
    echo "  $0"
    exit 1
fi

echo "================================================"
echo "SQLite to PostgreSQL Migration"
echo "================================================"
echo "Source (SQLite):      ${SQLITE_DB}"
echo "Destination (PostgreSQL): ${POSTGRES_URL}"
echo ""
echo "Starting migration using pgloader..."
echo ""

# Check if pgloader is installed
if ! command -v pgloader &> /dev/null; then
    echo "Error: pgloader is not installed."
    echo ""
    echo "Install it with:"
    echo "  macOS:    brew install pgloader"
    echo "  Ubuntu:   sudo apt-get install pgloader"
    echo "  Arch:     sudo pacman -S pgloader"
    echo "  Docker:   Add pgloader to tools/Dockerfile"
    exit 1
fi

# Run pgloader
# The --verbose flag provides detailed output
# --no-ssl-cert-verification is often needed for local development
pgloader --verbose \
    --with "batch rows = 1000" \
    --with "batch size = 10MB" \
    "sqlite://${SQLITE_DB}" \
    "${POSTGRES_URL}"

EXIT_CODE=$?

echo ""
echo "================================================"
if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo "✓ Migration completed successfully!"
else
    echo "✗ Migration failed with exit code ${EXIT_CODE}"
fi
echo "================================================"

exit ${EXIT_CODE}
