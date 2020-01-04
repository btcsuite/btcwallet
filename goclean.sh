#!/bin/bash
# The script does automatic checking on a Go package and its sub-packages, including:
# 1. go fmt        (http://golang.org/cmd/gofmt/)
# 2. golint        (https://github.com/golang/lint)
# 3. go vet        (http://golang.org/cmd/vet)
# 4. race detector (http://blog.golang.org/race-detector)

set -ex

test_targets=$(go list -deps ./... | grep 'btcwallet')

# Automatic checks
test -z "$(go fmt $test_targets | tee /dev/stderr)"

# test -z "$(goimports -l -w . | tee /dev/stderr)"
test -z "$(for package in $test_targets; do golint $package; done | grep -v 'ALL_CAPS\|OP_\|NewFieldVal\|RpcCommand\|RpcRawCommand\|RpcSend\|Dns\|api.pb.go\|StartConsensusRpc\|factory_test.go\|legacy\|UnstableAPI' | tee /dev/stderr)"

test -z "$(go vet $test_targets 2>&1 | grep -v '^exit status \|Example\|newestSha\| not a string in call to Errorf$' | tee /dev/stderr)"

env GORACE="history_size=7 halt_on_errors=1" go test -v -race $test_targets

# Run test coverage on each subdirectories and merge the coverage profile.

#set +x
#echo "mode: count" > profile.cov

# Standard go tooling behavior is to ignore dirs with leading underscores.
#for dir in $(find . -maxdepth 10 -not -path '.' -not -path './.git*' \
#    -not -path '*/_*' -not -path './cmd*' -not -path './release*' -type d)
#do
#if ls $dir/*.go &> /dev/null; then
#  go test -covermode=count -coverprofile=$dir/profile.tmp $dir
#  if [ -f $dir/profile.tmp ]; then
#    cat $dir/profile.tmp | tail -n +2 >> profile.cov
#    rm $dir/profile.tmp
#  fi
#fi
#done

# To submit the test coverage result to coveralls.io,
# use goveralls (https://github.com/mattn/goveralls)
# goveralls -coverprofile=profile.cov -service=travis-ci
