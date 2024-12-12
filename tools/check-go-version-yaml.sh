#!/bin/bash

# Function to check if the YAML file contains the specified Go version after 'GO_VERSION:'
check_go_version() {
    local yamlfile="$1"
    local required_go_version="$2"

    # Use grep to find lines with 'GO_VERSION:'
    local go_lines=$(grep -i 'GO_VERSION:' "$yamlfile" || true)  # Ignore grep exit status

    # Check if any lines specify the Go version
    if [ -n "$go_lines" ]; then
        # Extract the Go version from the file's lines. Example matching strings:
        # GO_VERSION: "1.21.0"
        # GO_VERSION: '1.21.0'
        # GO_VERSION: 1.21.0
        # GO_VERSION:1.21.0
        #   GO_VERSION:1.21.0
        local extracted_go_version=$(echo "$go_lines" | sed -n 's/^[[:space:]]*GO_VERSION:[[:space:]]*\(['\''"]\?\)\?\([0-9]\+\.[0-9]\+\.[0-9]\+\)\(['\''"]\?\)\?/\2/p')

        # Check if the extracted Go version matches the required version
        if [ "$extracted_go_version" != "$required_go_version" ]; then
            echo "Error: $yamlfile specifies Go version '$extracted_go_version', but not version '$required_go_version'."
            exit 1
        else
            echo "$yamlfile specifies Go version $required_go_version."
        fi
    fi
}

# Check if the target Go version argument is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_go_version>"
    exit 1
fi

target_go_version="$1"

# We find target files using the 'find' command in conjunction with the 'read'
# command. We exclude some directories from the search.
#
# We use the 'read' command to help ensure that we correctly handle filenames
# with spaces, newlines, and special characters. The '-print0' option in 'find'
# outputs filenames separated by a null character. This allows the 'read'
# command in the while loop to accurately distinguish each filename. The
# 'target_files' array is then populated, preserving the integrity of each
# filename. This approach ensures safe handling of filenames, regardless of
# their complexity.
while IFS= read -r -d '' file; do
    target_files+=("$file")
done < <(find . \
    -path ./vendor -prune -o \
    -type f \
    \( -name "*.yaml" -o -name "*.yml" \) \
    -print0 \
)

# Check for the expected Go version in each file.
for file in "${target_files[@]}"; do
    check_go_version "$file" "$target_go_version"
done

echo "All YAML files pass the Go version check for Go version $target_go_version."
