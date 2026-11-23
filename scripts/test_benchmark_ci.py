"""Exercise benchmark reporting through real files and the pinned benchstat."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import benchmark_ci as ci


class BenchmarkCITest(unittest.TestCase):
    """BenchmarkCITest checks externally observable reports and exit codes."""

    def setUp(self):
        """setUp gives each report an independent collection directory."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def evidence(self, base, head, iterations=100, complete=True):
        """evidence writes native benchmark text and matching source identities."""
        output = self.root / str(len(list(self.root.iterdir())))
        output.mkdir()
        sources = {}
        for role, rows in (("base", base), ("head", head)):
            if rows is None:
                continue
            sources[role] = {
                "revision": role,
                "common": "fixture",
                "requests": dict.fromkeys(rows, "request"),
            }
            for index, measurements in enumerate(zip(*rows.values())):
                lines = ["goos: linux", "goarch: amd64", f"pkg: {ci.PACKAGE}"]
                for name, (latency, memory, allocations) in zip(rows, measurements):
                    lines.append(
                        f"Benchmark{name} {iterations} {latency} ns/op "
                        f"{memory} B/op {allocations} allocs/op"
                    )
                (output / f"{role}-{index}.log").write_text("\n".join(lines))
        metadata = {
            "backend": "sqlite",
            "sources": sources,
            "profile": {"samples": ci.SAMPLES, "duration": ci.DURATION},
            "complete": complete,
        }
        (output / "metadata.json").write_text(json.dumps(metadata))
        return output

    def report(self, output, enforce=True):
        """report invokes the public command so its status is tested too."""
        command = [sys.executable, ci.__file__, "report", "--out", str(output)]
        if enforce:
            command.append("--enforce")
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def testReportAppliesRegressionBudgets(self):
        """testReportAppliesRegressionBudgets separates effect size from noise."""
        # Arrange: Keep six native samples per side; vary only the metric whose
        # practical threshold, absolute floor or confidence must decide gating.
        cases = [
            {
                "name": "improvement",
                "base": [(100, 2048, 8)] * 6,
                "head": [(90, 2048, 8)] * 6,
                "expected": (0, "within budget"),
            },
            {
                "name": "latency regression",
                "base": [(100, 2048, 8)] * 6,
                "head": [(150, 2048, 8)] * 6,
                "expected": (1, "regression"),
            },
            {
                "name": "byte regression",
                "base": [(100, 2048, 8)] * 6,
                "head": [(100, 4096, 8)] * 6,
                "expected": (1, "regression"),
            },
            {
                "name": "allocation regression",
                "base": [(100, 2048, 8)] * 6,
                "head": [(100, 2048, 12)] * 6,
                "expected": (1, "regression"),
            },
            {
                "name": "significant within latency budget",
                "base": [(100, 2048, 8)] * 6,
                "head": [(115, 2048, 8)] * 6,
                "expected": (0, "within budget"),
            },
            {
                "name": "exact latency conversion boundary",
                "base": [(100, 2048, 8)] * 6,
                "head": [(120, 2048, 8)] * 6,
                "expected": (0, "within budget"),
            },
            {
                "name": "exact latency boundary",
                "base": [(1020, 2048, 8)] * 6,
                "head": [(1224, 2048, 8)] * 6,
                "expected": (0, "within budget"),
            },
            {
                "name": "below byte floor",
                "base": [(100, 100, 8)] * 6,
                "head": [(100, 200, 8)] * 6,
                "expected": (0, "within budget"),
            },
            {
                "name": "below allocation floor",
                "base": [(100, 2048, 0)] * 6,
                "head": [(100, 2048, 0.5)] * 6,
                "expected": (0, "within budget"),
            },
            {
                "name": "zero allocation baseline",
                "base": [(100, 0, 0)] * 6,
                "head": [(100, 2048, 2)] * 6,
                "expected": (1, "regression"),
            },
            {
                "name": "large noisy change",
                "base": [(n, 2048, 8) for n in (20, 60, 90, 120, 160, 200)],
                "head": [(n, 2048, 8) for n in (30, 90, 135, 180, 240, 300)],
                "expected": (0, "inconclusive"),
            },
        ]
        for case in cases:
            with self.subTest(case=case["name"]):
                output = self.evidence(
                    {"GetTx/smoke": case["base"]},
                    {"GetTx/smoke": case["head"]},
                )

                # Act: Run the same pinned statistical command used by CI.
                result = self.report(output)

                # Assert: A significant result alone cannot fail a budget;
                # each independent practical/noise rule controls its verdict.
                self.assertEqual(result.returncode, case["expected"][0], result.stderr)
                summary = (output / "summary.md").read_text()
                self.assertIn(case["expected"][1], summary)

    def testReportOnlyRetainsRegressionEvidence(self):
        """testReportOnlyRetainsRegressionEvidence checks rollout suppression."""
        # Arrange: Supply an unambiguous regression but leave enforcement off.
        output = self.evidence(
            {"GetTx/smoke": [(100, 2048, 8)] * 6},
            {"GetTx/smoke": [(150, 2048, 8)] * 6},
        )

        # Act: Exercise the default public reporting mode.
        result = self.report(output, enforce=False)

        # Assert: Preserve the measured regression and median while returning
        # success, rather than hiding it or failing the report-only rollout.
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = (output / "summary.md").read_text()
        self.assertIn("Report-only", summary)
        self.assertIn("regression", summary)
        self.assertIn("| 150 |", summary)

    def testReportClassifiesCoverage(self):
        """testReportClassifiesCoverage keeps absent results out of ratios."""
        # Arrange: Use identical samples so only source availability changes.
        rows = [(100, 2048, 8)] * 6
        known = {"GetTx/smoke": rows}
        extended = {**known, "ListUnspent/smoke": rows}
        cases = [
            {
                "name": "new",
                "base": known,
                "head": extended,
                "expected": (0, "new"),
            },
            {
                "name": "missing",
                "base": extended,
                "head": known,
                "expected": (1, "missing"),
            },
            {
                "name": "unavailable",
                "base": {},
                "head": known,
                "expected": (1, "unavailable"),
            },
            {
                "name": "trend",
                "base": None,
                "head": known,
                "expected": (0, "trend"),
            },
        ]
        for case in cases:
            with self.subTest(case=case["name"]):
                output = self.evidence(case["base"], case["head"])

                # Act: Request enforcement to expose missing coverage failures.
                result = self.report(output)

                # Assert: A new benchmark and an intentional trend are usable;
                # missing or unavailable paired coverage is reported distinctly.
                self.assertEqual(result.returncode, case["expected"][0], result.stderr)
                self.assertIn(case["expected"][1], (output / "summary.md").read_text())

    def testReportRejectsInvalidEvidence(self):
        """testReportRejectsInvalidEvidence keeps data errors out of verdicts."""
        # Arrange: Vary only input data for a missing sample, single-iteration
        # result, nonfinite metric, or completion failure after native cleanup.
        cases = [
            {
                "name": "incomplete",
                "samples": 5,
            },
            {
                "name": "single iteration",
                "iterations": 1,
            },
            {
                "name": "nonfinite metric",
                "latency": "NaN",
            },
            {
                "name": "failed cleanup",
                "complete": False,
            },
        ]
        for case in cases:
            with self.subTest(case=case["name"]):
                rows = [(case.get("latency", 100), 2048, 8)] * case.get("samples", 6)
                output = self.evidence(
                    None, {"GetTx/smoke": rows},
                    iterations=case.get("iterations", 100),
                    complete=case.get("complete", True),
                )

                # Act: Analyze corrupted evidence with enforcement disabled.
                result = self.report(output, enforce=False)

                # Assert: Report-only still fails data errors and leaves a
                # visible diagnostic instead of a successful timing verdict.
                self.assertEqual(result.returncode, 2, result.stderr)
                diagnostic = (output / "summary.md").read_text().splitlines()[0]
                self.assertEqual(diagnostic, "# Measurement error")

    def testReportChecksSourceComparability(self):
        """testReportChecksSourceComparability separates requests from storage."""
        # Arrange: These real files model only the demonstrated harness edges;
        # the independent account must stay comparable after a point-helper change.
        files = {
            "wallet/bench/setup_test.go": "seed",
            "wallet/bench/setup_sqlite_test.go": "sqlite fixture",
            "wallet/internal/bwtest/bench_cases.go": "workload",
            "wallet/internal/bwtest/profile.go": "measurement boundary",
            "wallet/bench/get_tx_test.go": "func BenchmarkGetTxDifferent(b *testing.B) {}",
            "wallet/bench/get_address_info_test.go":
                "func BenchmarkGetAddressInfoDifferent(b *testing.B) {}",
            "wallet/bench/get_account_test.go":
                "func BenchmarkGetAccountDifferent(b *testing.B) {}",
            "wallet/internal/sql/sqlite/bootstrap/schema.sql": "schema",
        }
        cases = [
            {
                "name": "fixture",
                "path": "wallet/internal/bwtest/bench_cases.go",
                "point": "incompatible",
                "account": "incompatible",
                "change": "—",
                "exit": 1,
            },
            {
                "name": "request",
                "path": "wallet/bench/get_tx_test.go",
                "point": "incompatible",
                "account": "within budget",
                "change": "—",
                "exit": 1,
            },
            {
                "name": "shared request helper",
                "path": "wallet/bench/get_address_info_test.go",
                "point": "incompatible",
                "account": "within budget",
                "change": "—",
                "exit": 1,
            },
            {
                "name": "schema",
                "path": "wallet/internal/sql/sqlite/bootstrap/schema.sql",
                "point": "within budget",
                "account": "within budget",
                "change": "~",
                "exit": 0,
            },
        ]
        for index, case in enumerate(cases):
            with self.subTest(case=case["name"]):
                base = self.root / f"base-{index}"
                for name, contents in files.items():
                    path = base / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(contents)
                head = self.root / f"head-{index}"
                shutil.copytree(base, head)
                changed = head / case["path"]
                changed.write_text(changed.read_text() + "\n// changed input\n")
                sources = {
                    role: {"revision": role, **ci.harness_fingerprint(path, "sqlite")}
                    for role, path in (("base", base), ("head", head))
                }
                rows = dict.fromkeys(sources["head"]["requests"], [(100, 2048, 8)] * 6)
                output = self.evidence(rows, rows)
                metadata = json.loads((output / "metadata.json").read_text())
                metadata["sources"] = sources
                (output / "metadata.json").write_text(json.dumps(metadata))

                # Act: Classify actual source fingerprints through the report CLI.
                result = self.report(output)

                # Assert: Dataset/request edits invalidate affected comparisons;
                # SQL schema edits retain their independent native fixture keys.
                self.assertEqual(result.returncode, case["exit"], result.stderr)
                summary = (output / "summary.md").read_text().splitlines()
                point = next(line for line in summary if line.startswith(
                    "| GetTxDifferent/smoke | ns/op |"
                ))
                account = next(line for line in summary if line.startswith(
                    "| GetAccountDifferent/smoke | ns/op |"
                ))
                self.assertIn(f"| {case['point']} |", point)
                self.assertIn(f"| {case['account']} |", account)
                self.assertEqual(point.split("|")[5].strip(), case["change"])


if __name__ == "__main__":
    # Permit direct execution as well as repository-scoped unittest discovery.
    unittest.main()
