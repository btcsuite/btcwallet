#!/bin/bash

set -e

# Directory of the script file, independent of where it's called from.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# restore_files is a function to restore original schema files.
restore_files() {
	echo "Restoring SQLite bigint patch..."
	for file in $DIR/../migrations/*.up.sql.bak; do
		mv "$file" "${file%.bak}"
	done
}

# Set trap to call restore_files on script exit. This makes sure the old files
# are always restored.
trap restore_files EXIT

# SQLite doesn't support "BIGINT PRIMARY KEY" for auto-incrementing primary
# keys, only "INTEGER PRIMARY KEY". Internally it uses 64-bit integers for
# numbers anyway, independent of the column type. So we can just use
# "INTEGER PRIMARY KEY" and it will work the same under the hood, giving us
# auto incrementing 64-bit integers.
# _BUT_, sqlc will generate Go code with int32 if we use "INTEGER PRIMARY KEY",
# even though we want int64. So before we run sqlc, we need to patch the
# source schema SQL files to use "BIGINT PRIMARY KEY" instead of "INTEGER
# PRIMARY KEY".
echo "Applying SQLite bigint patch..."
for file in $DIR/../migrations/*.up.sql; do
	echo "Patching $file"
	sed -i.bak -E 's/INTEGER PRIMARY KEY/BIGINT PRIMARY KEY/g' "$file"
done

echo "Generating sql models and queries in go..."

# Run the script to generate the new generated code. Once the script exits, we
# use `trap` to make sure all files are restored.
# Go tool is only available executing from the module root, and also versioned
# from there.
go tool sqlc generate -f $DIR/sqlc.yaml

# Because we're using the Postgres dialect of sqlc, we can't use sqlc.slice()
# normally, because sqlc just thinks it can pass the Golang slice directly to
# the database driver. So it doesn't put the /*SLICE:<field_name>*/ workaround
# comment into the actual SQL query. But we add the comment ourselves and now
# just need to replace the '$X/*SLICE:<field_name>*/' placeholders with the
# actual placeholder that's going to be replaced by the sqlc generated code.
echo "Applying sqlc.slice() workaround..."
for file in $DIR/*.sql.go; do
  echo "Patching $file"

  # First, we replace the `$X/*SLICE:<field_name>*/` placeholders with
  # the actual placeholder that sqlc will use: `/*SLICE:<field_name>*/?`.
  sed -i.bak -E 's/\$([0-9]+)\/\*SLICE:([a-zA-Z_][a-zA-Z0-9_]*)\*\//\/\*SLICE:\2\*\/\?/g' "$file"

  # Then, we replace the `strings.Repeat(",?", len(arg.<golang_name>))[1:]` with
  # a function call that generates the correct number of placeholders:
  # `makeQueryParams(len(queryParams), len(arg.<golang_name>))`.
  sed -i.bak -E 's/strings\.Repeat\(",\?", len\(([^)]+)\)\)\[1:\]/makeQueryParams(len(queryParams), len(\1))/g' "$file"

  rm "$file.bak"
done