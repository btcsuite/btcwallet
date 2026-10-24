#!/usr/bin/env bash

# Run selected benchmarks in the pinned client environment. Setup remains
# inside its benchmark fixture, outside timing; profiles use separate runs.
set -euo pipefail
bench_method=${1:-}
bench_db=${2:-}
bench_workload=${3:-smoke}
bench_profile=${4:-}
bench_duration=${5:-}
bench_out=${6:-/tmp/btcwallet-bench}

# Explicit package and pattern selection makes the command usable before a
# method adds friendly selectors. The method label groups its artifacts.
bench_pkg=${BENCH_PACKAGE:-}
bench_case=${BENCH_CASE:-}
if [[ -z "$bench_method" ]]; then
    echo 'Select a method label' >&2
    exit 1
fi

case "$bench_workload" in
    smoke) bench_duration=${bench_duration:-1x} ;;
    small-node|medium-node|large-node) bench_duration=${bench_duration:-3s} ;;
    *) echo 'Select case=smoke|small-node|medium-node|large-node' >&2; exit 1 ;;
esac
case "$bench_profile" in
    ''|cpu|mem) ;;
    *) echo 'Select profile=cpu|mem|all, or omit it for timing' >&2; exit 1 ;;
esac


# Each invocation owns one backend's fixture and one complete benchmark leaf.
# Reject empty selection before Docker can run unrelated benchmark methods.
case "$bench_db" in
    legacy|kvdb|sqlite|postgres) ;;
    *) echo 'Select db=legacy|kvdb|sqlite|postgres' >&2; exit 1 ;;
esac
if [[ -z "$bench_pkg" || -z "$bench_case" ]]; then
    echo 'Set BENCH_PACKAGE and BENCH_CASE for the selected entrypoint' >&2
    exit 1
fi

# Keep smoke artifacts separate from full measurements. Build caching avoids
# recompiling unchanged packages; database fixtures use their own Docker volume.
bench_out="$bench_out/$bench_method/$bench_workload/$bench_db/${bench_profile:-timing}"
mkdir -p "$bench_out" /tmp/go-build-cache/benchmark
bench_out=$(cd "$bench_out" && pwd)
# The shared lnd base is prepared once per backend/size, independently of the
# method consuming it. Bump its revision for fixture inputs or storage changes;
# query/runtime changes must keep reusing the saved dataset.
bench_fixture_revision=v1
bench_schema=
case "$bench_db" in
    sqlite) bench_schema=sqlite ;;
    postgres) bench_schema=pg ;;
esac
bench_gateway=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
bench_image=golang:1.25.11-bookworm@sha256:b96f24a8d7d010ea0acb9c3ba99064740f02b6b984612b28bd3c9c5ab9453e38

# Mount source read-only and give every client the same build/resource limits.
# The Docker socket lets the SQL fixture provision PostgreSQL independently.
git rev-parse HEAD
docker run --rm --cpus=1 --memory=4g --memory-swap=4g \
    -v "$(pwd):/build:ro" -w /build \
    -v /tmp/go-build-cache/benchmark:/cache \
    -v btcwallet-bench-fixtures:/fixtures \
    -v "$bench_out:/artifacts" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e GOMAXPROCS=1 -e CGO_ENABLED=0 \
    -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod \
    -e GOFLAGS='-buildvcs=false -trimpath -p=1' \
    -e TESTCONTAINERS_HOST_OVERRIDE="$bench_gateway" \
    -e BENCH_PACKAGE="$bench_pkg" -e BENCH_CASE="$bench_case" \
    -e BENCH_DURATION="$bench_duration" \
    -e BENCH_FIXTURE_REVISION="$bench_fixture_revision" \
    -e BENCH_SCHEMA="$bench_schema" \
    -e BTCWALLET_BENCH_PROFILE="$bench_profile" \
    -e BTCWALLET_BENCH_PROFILE_DIR=/artifacts \
    "$bench_image" sh -ec '
        go version
        go test -c -o /artifacts/benchmark.test "$BENCH_PACKAGE"
        # SQL storage compatibility follows bootstrap/migration contents, not
        # queries or executable identity. Legacy and maintained share kvdb.
        fixture_key="lnd-wallet/$BENCH_FIXTURE_REVISION"
        if [ -n "$BENCH_SCHEMA" ]; then
            schema_key=$(cat wallet/internal/sql/"$BENCH_SCHEMA"/bootstrap/*.sql \
                wallet/internal/sql/"$BENCH_SCHEMA"/migrations/*.sql | sha256sum)
            fixture_key="$fixture_key/${schema_key%% *}"
        fi
        export BTCWALLET_BENCH_FIXTURE_DIR=/fixtures/$fixture_key
        /artifacts/benchmark.test -test.run="^$" \
            -test.bench="$BENCH_CASE" -test.benchtime="$BENCH_DURATION" \
            -test.count=1 -test.cpu=1 -test.benchmem -test.timeout=20m
        # Analyze only completed diagnostic captures, after benchmark cleanup.
        # Heap subtraction separates allocation traffic from retained Go heap.
        case "$BTCWALLET_BENCH_PROFILE" in
            cpu)
                go tool pprof -top /artifacts/benchmark.test /artifacts/cpu.pprof
                ;;
            mem)
                for sample in alloc_space inuse_space; do
                    go tool pprof -top -sample_index="$sample" \
                        -base /artifacts/heap-before.pprof \
                        /artifacts/benchmark.test /artifacts/heap-after.pprof
                done
                ;;
        esac'
