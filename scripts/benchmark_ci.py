#!/usr/bin/env python3
"""Collect and report the existing SQL smoke benchmarks for CI."""

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

PACKAGE = "github.com/btcsuite/btcwallet/wallet/bench"
SELECTOR = "^Benchmark(Get|List).*/^smoke$"
# Six short samples bound opt-in cost at the expense of statistical power;
# noisy intervals remain inconclusive until the hosted profile is calibrated.
SAMPLES = 6
DURATION = "10x"
# Benchstat normalizes native ns/op to sec/op. Relative budgets require a
# significant change too; absolute allocation floors avoid tiny-cost alerts.
LIMITS = {"sec/op": (0.20, 0), "B/op": (0.25, 1024), "allocs/op": (0.25, 1)}


def _comparison_mode(sources):
    """_comparison_mode distinguishes trends from unusable paired baselines."""
    if "base" not in sources:
        return "trend"
    if not sources["base"]["common"] or not sources["base"]["requests"]:
        return "unavailable"
    if sources["base"]["common"] != sources["head"]["common"]:
        return "incompatible"
    return "paired"


def read_samples(output, role, expected):
    """read_samples validates whole invocations before normalizing Go output."""
    headers, lines = {}, []
    if not expected:
        raise ValueError("empty SQL benchmark selection")

    for index in range(SAMPLES):
        seen = set()
        for line in (output / f"{role}-{index}.log").read_text().splitlines():
            # Retain native runtime identity; setup diagnostics are not samples.
            key, separator, value = line.partition(": ")
            if separator and key in ("goos", "goarch", "pkg", "cpu"):
                if key in headers and headers[key] != value:
                    raise ValueError("inconsistent benchmark runtime identity")
                headers[key] = value

            match = re.match(r"^(Benchmark\S+)\s+(\d+)\s+(.*)$", line)
            if not match:
                continue

            name, iterations, metrics = match.groups()
            if not re.fullmatch(r"Benchmark(?:Get|List)\w+/smoke(?:-1)?", name):
                raise ValueError(f"unexpected benchmark: {name}")
            name = re.sub(r"-1$", "", name[9:])
            fields = metrics.split()
            values = dict(zip(fields[1::2], map(float, fields[::2])))
            if (int(iterations) < 2 or len(fields) != 6
                    or set(values) != {"ns/op", "B/op", "allocs/op"}
                    or any(not math.isfinite(v) or v < 0 for v in values.values())):
                raise ValueError(f"invalid repeated timing: {name}")

            if name in seen:
                raise ValueError(f"duplicate benchmark: {name}")
            seen.add(name)
            lines.append(f"Benchmark{name} {iterations} {metrics}\n")

        if seen != set(expected):
            raise ValueError(f"incomplete SQL selection in {role}-{index}.log")

    if headers.get("pkg") != PACKAGE or not {"goos", "goarch"} <= headers.keys():
        raise ValueError("missing SQL benchmark runtime identity")

    return headers, "".join(f"{k}: {v}\n" for k, v in headers.items()) + "".join(lines)


def compare_results(output, enforce=False):
    """compare_results reports upstream statistics and applies practical budgets."""
    metadata = json.loads((output / "metadata.json").read_text())
    if not metadata["complete"] or metadata["profile"]["samples"] != SAMPLES:
        raise ValueError("incomplete or incompatible collection profile")

    sources = metadata["sources"]
    mode = _comparison_mode(sources)
    roles = ["base", "head"] if mode == "paired" else ["head"]
    identity, inputs = None, []
    for role in roles:
        headers, normalized = read_samples(output, role, sources[role]["requests"])
        if identity is not None and identity != headers:
            raise ValueError("base/candidate runtime identities differ")
        identity = headers
        path = output / f"{role}.txt"
        path.write_text(normalized)
        inputs.append(f"{role}={path}")

    # Keep the statistical implementation and its warnings in the pinned tool.
    statistics = {}
    for form in ("text", "csv"):
        result = subprocess.run(
            ["benchstat", "-alpha", "0.01", "-confidence", "0.95",
             "-format", form, *inputs],
            check=True, capture_output=True, text=True,
        )
        (output / f"benchstat.{form}").write_text(result.stdout)
        statistics[form] = result

    (output / "benchstat.warnings").write_text(statistics["csv"].stderr)

    summary = [
        f"# SQL benchmarks ({metadata['backend']})\n",
        "Enforced\n" if enforce else "Report-only\n",
        (
            f"Profile: smoke, {SAMPLES} samples, "
            f"{metadata['profile']['duration']}; comparison: {mode}.\n"
        ),
        *[f"- {role}: `{source['revision']}`" for role, source in sources.items()],
        "\n| Benchmark | Metric | Base | Candidate | Change | Result |",
        "| --- | --- | ---: | ---: | ---: | --- |",
    ]

    base = sources.get("base", {}).get("requests", {})
    head = sources["head"]["requests"]
    missing = set(base) - set(head)
    failure = bool(missing) or mode in ("unavailable", "incompatible")
    for name in sorted(missing):
        summary.append(f"| {name} | — | — | — | — | missing |")

    observed, unit = set(), None
    for row in csv.reader(statistics["csv"].stdout.splitlines()):
        if len(row) > 1 and row[1] in LIMITS:
            unit = row[1]
        if not row or row[0] not in head or unit is None:
            continue

        name = row[0]
        paired = mode == "paired" and name in base
        position = 3 if mode == "paired" else 1
        new = float(row[position])
        old = float(row[1]) if paired else None
        change = row[5] if paired else "—"
        status = mode if mode != "paired" else "new"

        if paired:
            # Compare unrounded centers; '~' is benchstat's significance verdict.
            ranges = (row[2], row[4])
            noisy = any("∞" in v or float(v.rstrip("%")) > 10 for v in ranges)
            limit, floor = LIMITS[unit]
            boundary = old * (1 + limit)
            # CSV conversion and boundary arithmetic can shift exact limits by
            # a few ULPs. Preserve unrounded centers and ignore only that error.
            tolerance = 8 * max(math.ulp(new), math.ulp(boundary))
            regression = (change != "~" and new - boundary > tolerance
                          and new - old >= floor)
            status = "inconclusive" if noisy else (
                "regression" if regression else "within budget"
            )

            if base[name] != head[name]:
                status = "incompatible"
                change = "—"
            failure |= status in ("regression", "incompatible")

        scale = 1e9 if unit == "sec/op" else 1
        display_unit = "ns/op" if unit == "sec/op" else unit
        old_text = f"{old * scale:g}" if old is not None else "—"
        summary.append(
            f"| {name} | {display_unit} | {old_text} | {new * scale:g} "
            f"| {change} | {status} |"
        )
        observed.add((name, unit))

    if observed != {(name, metric) for name in head for metric in LIMITS}:
        raise ValueError("benchstat omitted expected benchmark metrics")

    if statistics["csv"].stderr:
        summary.extend(["\nStatistical warnings:", *[
            f"> {line}" for line in statistics["csv"].stderr.splitlines()
        ]])

    (output / "summary.md").write_text("\n".join(summary) + "\n")
    return int(enforce and failure)


def harness_fingerprint(source, backend):
    """harness_fingerprint identifies datasets and requests, not query code."""
    def digest(paths):
        """digest binds ordered relative paths and contents across checkouts."""
        data = b"".join(
            str(path.relative_to(source)).encode() + b"\0" + path.read_bytes()
            for path in sorted(paths)
        )
        return hashlib.sha256(data).hexdigest()

    common = [source / path for path in (
        "wallet/bench/setup_test.go", f"wallet/bench/setup_{backend}_test.go",
        "wallet/internal/bwtest/bench_cases.go", "wallet/internal/bwtest/profile.go",
    )]
    requests = {}
    for path in sorted((source / "wallet/bench").glob("*_test.go")):
        for name in re.findall(r"^func Benchmark((?:Get|List)\w*)\(",
                               path.read_text(), re.MULTILINE):
            # The point-read helpers live with address reads; include only the
            # demonstrated cross-file edges, not a general dependency graph.
            inputs = [path]
            if (name.endswith(("Different", "NotFound"))
                    and name.startswith(("GetTx", "GetUtxo"))):
                inputs.append(source / "wallet/bench/get_address_info_test.go")
            requests[name + "/smoke"] = digest(set(inputs))

    schema = source / "wallet/internal/sql" / (
        "pg" if backend == "postgres" else "sqlite"
    )
    return {
        "common": digest(common) if all(path.is_file() for path in common) else None,
        "requests": requests,
        # Schema hashes select separate native fixtures; index changes remain
        # comparable when logical workload and request definitions still match.
        "schema": digest([*schema.glob("bootstrap/*.sql"),
                          *schema.glob("migrations/*.sql")]),
    }


def collect(head, base, backend, output):
    """collect runs serial paired samples through the unchanged Docker runner."""
    head = head.resolve()
    runner = Path(__file__).resolve().with_name("benchmark.sh")
    output.mkdir(parents=True, exist_ok=False)
    locations = {"head": head}
    if base is not None:
        locations["base"] = base.resolve()

    # Bind collection to Git revisions while keeping file identities usable
    # independently of repository state, including in temporary test fixtures.
    sources = {}
    for role, location in locations.items():
        sources[role] = harness_fingerprint(location, backend)
        sources[role]["revision"] = subprocess.check_output(
            ["git", "-C", str(location), "rev-parse", "HEAD"], text=True,
        ).strip()

    if not sources["head"]["common"] or not sources["head"]["requests"]:
        raise ValueError("candidate SQL benchmark harness is unavailable")

    mode = _comparison_mode(sources)
    roles = ["base", "head"] if mode == "paired" else ["head"]
    cpu_command = ["lscpu"] if sys.platform == "linux" else [
        "sysctl", "-n", "machdep.cpu.brand_string",
    ]
    metadata = {
        "backend": backend, "sources": sources, "complete": False, "runs": [],
        "profile": {
            "samples": SAMPLES, "duration": DURATION, "selector": SELECTOR,
            "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
        },
        "environment": {
            "host": platform.platform(),
            "cpu": subprocess.check_output(cpu_command, text=True).strip(),
            "docker": subprocess.check_output(["docker", "version"], text=True),
            "runner_image": {key: os.getenv(key) for key in (
                "ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH",
                "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
            )},
        },
        "pull_request": {
            "head": os.getenv("PR_HEAD_SHA"),
            "payload_base": os.getenv("PR_PAYLOAD_BASE"),
            "payload_base_matches": os.getenv("PR_PAYLOAD_BASE") ==
            sources.get("base", {}).get("revision"),
        },
    }

    metadata_path = output / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2))
    environment = {**os.environ, "BENCH_PACKAGE": "./wallet/bench",
                   "BENCH_CASE": SELECTOR}

    # Preparation uses the same private restoration path but supplies no timing
    # evidence. Every subsequent pair has balanced early/late source positions.
    invocations = [(role, "prepare", "1x") for role in roles]
    for index in range(SAMPLES):
        order = roles if index % 2 == 0 else list(reversed(roles))
        invocations.extend((role, str(index), DURATION) for role in order)

    for role, sample, duration in invocations:
        print(f"{backend}: {role} {sample}", flush=True)
        started = time.monotonic()
        with (output / f"{role}-{sample}.log").open("w") as log:
            result = subprocess.run(
                ["bash", str(runner), "sql-ci", backend, "smoke", "", duration,
                 str(output / role)], cwd=locations[role], env=environment,
                stdout=log, stderr=subprocess.STDOUT, check=False,
            )

        metadata["runs"].append({
            "role": role, "sample": sample, "returncode": result.returncode,
            "elapsed_seconds": time.monotonic() - started,
        })
        metadata_path.write_text(json.dumps(metadata, indent=2))
        if result.returncode:
            raise ValueError(f"{role}-{sample} failed; inspect its raw log")

    metadata["complete"] = True
    metadata_path.write_text(json.dumps(metadata, indent=2))
    return 0


def main():
    """main exposes report status without treating failed evidence as success."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    report = commands.add_parser("report")
    report.add_argument("--out", type=Path, required=True)
    report.add_argument("--enforce", action="store_true")

    collection = commands.add_parser("collect")
    collection.add_argument("--head", type=Path, required=True)
    collection.add_argument("--base", type=Path)
    collection.add_argument("--backend", choices=("sqlite", "postgres"), required=True)
    collection.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()

    try:
        if arguments.command == "collect":
            return collect(arguments.head, arguments.base, arguments.backend,
                           arguments.out.resolve())
        return compare_results(arguments.out, arguments.enforce)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        if arguments.command == "report":
            arguments.out.mkdir(parents=True, exist_ok=True)
            (arguments.out / "summary.md").write_text(
                f"# Measurement error\n\n{error}\n"
            )
        print(f"benchmark CI: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    # Preserve separate verdict (1) and invalid-measurement (2) exit statuses.
    sys.exit(main())
