#!/bin/bash

# Filter coverage files to exclude opposite backend implementations
# Usage: filter_coverage.sh <db_type>
# Where db_type is 'sqlite' or 'postgres'

set -e

DB_TYPE="$1"
if [ "$DB_TYPE" != "sqlite" ] && [ "$DB_TYPE" != "postgres" ]; then
	echo "Usage: $0 <sqlite|postgres>"
	exit 1
fi

COVERAGE_FILE="coverage-itest-${DB_TYPE}.txt"
if [ ! -f "$COVERAGE_FILE" ]; then
	echo "Coverage file $COVERAGE_FILE not found"
	exit 1
fi

# Create filtered version
FILTERED_FILE="${COVERAGE_FILE}.filtered"

# Keep the mode line, filter out opposite backend files
head -1 "$COVERAGE_FILE" >"$FILTERED_FILE"

if [ "$DB_TYPE" = "sqlite" ]; then
	# For sqlite: exclude postgres files
	tail -n +2 "$COVERAGE_FILE" | grep -Ev 'pg|postgres'	>>"$FILTERED_FILE"
else
	# For postgres: exclude sqlite files
	tail -n +2 "$COVERAGE_FILE" | grep -Ev 'sqlite' >>"$FILTERED_FILE"
fi

# Replace original with filtered
mv "$FILTERED_FILE" "$COVERAGE_FILE"

# Output the filtered coverage percentage
go tool cover -func="$COVERAGE_FILE" |
	awk '/^total:/ { print "Filtered test coverage for '"$DB_TYPE"': " $3 }'
