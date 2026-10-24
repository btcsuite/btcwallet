# <Method>

<Describe the completed native API request and its filters.>
Measured source(s): `<full actual measured SHA(s)>`.
<Identify implementations when their measured source revisions differ.>
[Methodology](methodology.md),
[reproducibility](reproducibility.md#docker-environment) and
[commands](reproducibility.md#run-and-repeat).

🟢 below baseline; 🔴 above baseline; ⚪ baseline/equal.

### Benchmark Results

Baseline: <Name the implementation used for this request.>

#### <Dataset name>

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | ... | ... | ... | ... | ... | ... |
| Maintained kvdb | ... | ... | ... | ... | ... | ... |
| PostgreSQL | ... | ... | ... | ... | ... | ... |
| SQLite | ... | ... | ... | ... | ... | ... |

<Use a separate table per dataset, with whole-number metrics and thousands
separators. For repeated-read groups, take the median of accepted unprofiled
samples separately for each metric, normally eight samples; keep separate
collections and single-call diagnostics identifiable. Compute ratios from
unrounded medians: baseline/value below baseline, value/baseline above it.
Each ratio cell has only a colored dot and two-decimal number; mark baseline
and equal cells ⚪ 1.00. Exclude smoke results. Keep measured source revisions
above the tables.>

### Notes

<Keep short notes on native request semantics, comparison limits and material
measurement exceptions. Identify unavailable or unmatched implementations
without inventing metrics. Keep routine setup/timer policy, run labels/dates,
serial orders and profile paths in shared docs or evidence, not this report.>
