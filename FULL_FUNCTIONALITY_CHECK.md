# Full Functionality Check Plan

Date: 2026-04-05
Repository: Hack2Future
Goal: verify the core backend, API, CLI, temporal, export, and frontend functionality that must work for demo/readiness.

## 1. Verification Scope

### Core features that must work
- CLI execution and argument parsing.
- Ingestion modes:
  - mock ingestion (`--ingestor mock`)
  - graph replay (`--graph-in`)
  - live kubectl path via test coverage (API/backend tests)
- Graph analysis algorithms:
  - Dijkstra shortest attack path
  - BFS blast radius
  - DFS cycle detection
  - Critical-node impact analysis
- Report output modes:
  - full report
  - focused report flags (`--attack-path`, `--blast-radius`, `--cycles`, `--critical-node`)
- Artifact export:
  - normalized graph JSON (`--graph-out`)
  - PDF report (`--pdf-out`)
- Temporal engine:
  - snapshot save/list/detail/rollback (covered by backend tests)
  - temporal diff in report payload/output
- API contract and endpoint behavior.
- Frontend build integrity.

## 2. Command Plan

### Environment and dependencies
1. Backend dependency sync
```bash
cd tool
uv sync
```

2. Frontend dependency install
```bash
cd frontend
npm install
```

### Automated test suite (primary proof)
3. Run full backend test suite (includes algorithms, API, ingestion, temporal, reporting)
```bash
cd tool
uv run python -m unittest discover -s test -v
```

### CLI smoke checks (runtime and artifacts)
4. Full report smoke run with mock graph
```bash
cd tool
kubepath --ingestor mock --mock-file ../tests/mock-cluster-graph.json --full-report
```

5. Focused report mode checks
```bash
cd tool
kubepath --ingestor mock --mock-file ../tests/mock-cluster-graph.json --attack-path
kubepath --ingestor mock --mock-file ../tests/mock-cluster-graph.json --blast-radius
kubepath --ingestor mock --mock-file ../tests/mock-cluster-graph.json --cycles
kubepath --ingestor mock --mock-file ../tests/mock-cluster-graph.json --critical-node
```

6. Export checks (graph JSON + PDF)
```bash
cd tool
kubepath --ingestor mock --mock-file ../tests/mock-cluster-graph.json --graph-out out/verify-graph.json --pdf-out out/verify-report.pdf --full-report
```

7. Graph replay check (`--graph-in`)
```bash
cd tool
kubepath --graph-in out/verify-graph.json --full-report
```

### Frontend integrity check
8. Production build
```bash
cd frontend
npm run build
```

## 3. Feature-to-Command Mapping

- CLI startup and parser: Commands 4, 5, 6, 7
- Mock ingestion: Commands 4, 5, 6
- Graph replay ingestion: Command 7
- Dijkstra: Command 3 (tests), Command 4/5 output section
- BFS: Command 3 (tests), Command 4/5 output section
- DFS cycle detect: Command 3 (tests), Command 4/5 output section
- Critical-node: Command 3 (tests), Command 4/5 output section
- Temporal snapshot/diff/rollback: Command 3 (tests), Command 4 output contains temporal block
- Graph JSON export: Command 6
- PDF export: Command 6
- API behavior/contracts: Command 3 (API and contract tests)
- Frontend compile validity: Command 8

## 4. Execution Log (actual run)

- [x] Command 1 completed
  - Result: `uv sync` success.
- [x] Command 2 completed
  - Result: `npm install` success.
- [ ] Command 3 completed
  - Result: failed (104 tests run, 1 failure).
  - Failing test: `test_sample_output_regression.TestSampleOutputRegression.test_mock_full_report_matches_sample_output`
  - Failure reason: expected sample output still contains fixed timestamp suffix (`2026-04-03 02:25:35`), while current formatter output uses actual dynamic timestamp.
- [x] Command 4 completed
  - Result: full mock CLI run success; all main report sections present.
- [x] Command 5 completed
  - Result: all focused mode commands ran successfully and emitted expected mode-specific blocks.
- [x] Command 6 completed
  - Result: export success; files generated and non-empty.
  - Artifacts: `tool/out/verify-graph.json`, `tool/out/verify-report.pdf`
- [x] Command 7 completed
  - Result: graph replay (`--graph-in`) success.
- [x] Command 8 completed
  - Result: frontend production build success (`vite build`).
  - Note: bundle-size warning reported by Vite (>500 kB chunk), non-blocking.

## 5. Run Summary

- Overall status: partial pass.
- Passed checks: 7/8 command groups.
- Blocking issue found: regression fixture mismatch in sample-output test.
- Functional smoke checks (CLI + export + replay + frontend build): passed.

## 6. Pass Criteria

- Backend test suite exits with code 0.
- CLI smoke commands execute with exit code 0.
- Export files are created and non-empty.
- Frontend build exits with code 0.
- No blocking runtime errors in tested flows.

## 7. Frontend Features Added (2026-04-05)

- Persisted analysis preferences in browser storage:
  - namespace
  - include-cluster-rbac
  - enable-nvd-scoring
  - max-hops/max-depth
  - graph overlay toggles
- Graph page productivity actions:
  - auto-refresh interval selector (Off/15s/30s/60s)
  - download current analysis payload as JSON
  - copy a PPT-ready risk brief summary to clipboard
- Risks page analyst workflow upgrades:
  - severity filter (ALL/CRITICAL/HIGH/MEDIUM/LOW)
  - attack-path text search (source/target)
  - critical-node search
  - export visible high-risk paths to CSV

Frontend validation after feature addition:
- `cd frontend && npm run build` passed successfully.
