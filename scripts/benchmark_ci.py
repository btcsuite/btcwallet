#!/usr/bin/env python3
"""Collect and report the existing SQL smoke benchmarks for CI."""

import math
import re

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
