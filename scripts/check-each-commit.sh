#!/bin/bash
if [[ "$1" = "" ]]; then
	echo "USAGE: $0 remote/head_branch"
	echo "eg $0 upstream/master"
	exit 1
fi

set -e
set -x

if ! git merge-base --is-ancestor "$1" HEAD; then
	echo "It seems like the current checked-out commit is not based on $1"
	exit 1
fi

commit_count=$(git rev-list --count "$1"..HEAD)
echo "Checking $commit_count commit(s) above $1"

git rebase --exec scripts/check-commit.sh "$1"
