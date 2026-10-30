# SPARC analysis results view

The user approved the graphical-analysis audit recommendation: immediately reveal completed results, separate Performance and Avalanche views, make charts readable and show variability and run context. This is a refinement of the existing Tk analysis laboratory, implemented solo in its current worktree.

## Approach

Keep native ttk controls and the shared Canvas/SVG drawing model. Moving charts alone would leave the long form and details competing with results; introducing an external chart library would add packaging and rendering dependencies. A dedicated Results workspace best fits the approved recommendation. Implementation choices below are the builder's calls within that scope.

Experiments remains a scrollable configuration view. Results has Performance, Avalanche, Details and Operation metrics tabs. Benchmark and sensitivity completion select the relevant graph tab automatically; other results select Details. Details retain raw measurements and CSV export. Performance and Avalanche each retain their latest run, explicitly identified by run context; starting another experiment does not relabel older measurements.

## Charts and context

- Performance: duration with mean and dashed p95 curves; throughput/goodput separate. A numeric logarithmic payload axis shows the allowed workloads. Missing/failed measurements remain gaps. State that p95 is a sample percentile, not a confidence interval.
- Avalanche: categorical dot plots with observed min/max ranges for bit, byte and hex change, preserving separate model expectations and the coursework byte target. Add a bit-change histogram and output-bit change-frequency chart for batches. Single trials show observations without pretending to estimate a distribution.
- Include available run ID, UTC, environment, warmups, repetitions, sample counts and evidence mode for benchmarks; seed, cases, retained trials and completion for sensitivity. Unknown context stays explicitly unavailable. Export the same context with SVGs. Never include keys or raw synthetic operands in graph metadata.
- Use readable native chart fonts, responsive label margins and a bounded plot width; charts scroll vertically. Operation filters appear only for local performance results. No chart implies that observed avalanche establishes cryptographic security.

## Constraints and verification

Python >=3.10; no new dependencies or protocol/security changes. Keep CSV behavior, cancellation, closing and all existing experimental controls. Preserve unrelated traffic files and documentation. Verify data transformations with hand-checked fixtures, GUI navigation/export with real Tk, and native screenshots at ordinary and wide window sizes. Run the full suite and report the known traffic baseline failures separately from changes introduced here.
