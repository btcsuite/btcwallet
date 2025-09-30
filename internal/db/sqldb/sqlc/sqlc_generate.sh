#!/bin/bash

set -e

# Directory of the script file, independent of where it's called from.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# restore_files restore original schema files.
function restore_files() {
	echo "Restoring SQLite bigint patch..."
	for file in "$DIR"/../migrations/*.up.sql.original; do
		mv "$file" "${file%.original}"
	done
}

# Set trap to call restore_files on script exit. This makes sure the old files
# are always restored.
trap restore_files EXIT

# SQLite requires `INTEGER PRIMARY KEY` for autoincrement, but SQLC emits Go
# int32 for that type. We temporarily patch schemas to `BIGINT PRIMARY KEY` so
# SQLC generates int64, then restore the originals via the trap. When migrating
# in postgres, the type should be replaced to `BIGINT` to support int64.
echo "Applying SQLite bigint patch..."
for file in "$DIR"/../migrations/*.up.sql; do
	echo "Patching $file"
	sed -i.original -E 's/INTEGER PRIMARY KEY/BIGINT PRIMARY KEY/g' "$file"
done

echo "Generating sql models and queries in go..."

# Generate code via sqlc
sqlc generate -f "$DIR"/sqlc.yaml

# Because we're using the Postgres dialect of SQLC, we can't use sqlc.slice()
# normally, because SQLC just thinks it can pass the Golang slice directly to
# the database driver. So it doesn't put the /*SLICE:<field_name>*/ workaround
# comment into the actual SQL query. But we add the comment ourselves and now
# just need to replace the '$X/*SLICE:<field_name>*/' placeholders with the
# actual placeholder that's going to be replaced by the SQLC generated code.
echo "Applying sqlc.slice() workaround..."
for file in "$DIR"/*.sql.go; do
  echo "Patching $file"

  # This sed invocation transforms SQLC placeholders for slices. SQLC writes
  # placeholders such as '$1/*SLICE:ids*/' where '$1' is a numeric placeholder
  # and 'ids' is the slice name.
  # The search pattern looks for a dollar sign and number followed by the
  # '/*SLICE:name*/' comment.
  # In the pattern:
  #   \$([0-9]+) captures the number; we ignore this capture.
  #   /\*SLICE: matches the literal comment start.
  #   ([a-zA-Z_][a-zA-Z0-9_]*) captures the slice name.
  #   \*/ matches the end of the comment.
  # The replacement rebuilds the comment using the captured name and appends a
  # '?' so that makeQueryParams can replace it.
  # We pick '#' as the sed delimiter to avoid escaping the slashes in the
  # comment markers.
  sed -i.original -E "s#\$([0-9]+)/\*SLICE:([a-zA-Z_][a-zA-Z0-9_]*)\*/#/*SLICE:\2*/?#g" "$file"

  # Next we replace the code that uses strings.Repeat to build a list of '?'
  # markers for an IN clause with a call to makeQueryParams.
  # The search pattern `strings\.Repeat\(",\?", len\(([^)]+)\)\)\[1:\]`
  # matches expressions like `strings.Repeat(",?", len(arg.Scids))[1:]`.
  #   strings\.Repeat\(",\?", len\( matches the literal prefix.
  #   ([^)]+) captures the expression inside len(), such as arg.Scids.
  #   \)\)\[1:\] matches the closing brackets and slice notation.
  # The replacement `makeQueryParams(len(queryParams), len(\1))` constructs a
  # call to our helper using the captured argument and the current parameter
  # count.
  sed -i.original -E 's/strings\.Repeat\(",\?", len\(([^)]+)\)\)\[1:\]/makeQueryParams(len(queryParams), len(\1))/g' "$file"

  rm "$file.original"
done
