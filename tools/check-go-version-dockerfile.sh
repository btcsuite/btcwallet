#!/bin/bash

# Function to check if the Dockerfile contains only the specified Go version
check_go_version() {
    local dockerfile="$1"
    local required_go_version="$2"

    # Use grep to find lines with 'FROM golang:'
    local go_lines=$(grep -i '^FROM golang:' "$dockerfile")

    # Check if all lines have the required Go version
    if echo "$go_lines" | grep -q -v "$required_go_version"; then
        echo "Error: $dockerfile does not use Go version $required_go_version exclusively."
        exit 1
    else
        echo "$dockerfile is using Go version $required_go_version."
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
    \( -name "*.Dockerfile" -o -name "Dockerfile" \) \
    -print0 \
)

# Check for the expected Go version in each file.
for file in "${target_files[@]}"; do
    check_go_version "$file" "$target_go_version"
done


echo "All Dockerfiles pass the Go version check for Go version $target_go_version."
