# Kubernetes Attack Path Visualizer

Command-line analyzer for Kubernetes privilege escalation paths.

It ingests cluster state, builds a directed graph of trust and permission relationships, runs security analysis algorithms, prints a kill-chain style CLI report, and can export both JSON and PDF artifacts.

## Quick Access

For a fast copy-paste command reference, use [FASTSTART.md](FASTSTART.md).

## Current Scope (Phases 2-6)

- Data ingestion from live `kubectl` or mock JSON.
- Deterministic normalized graph export (`cluster-graph.json` by default).
- Graph reconstruction from exported JSON.
- Core analysis:
	- Blast radius (BFS)
	- Shortest attack path (Dijkstra)
	- Cycle detection (DFS)
	- Critical node identification
- Reporting:
	- Compact kill-chain CLI output
	- PDF export (`--pdf-out`)
	- Temporal snapshot diff detection across scans
	- Snapshot management APIs (list, detail, rollback)

## Phase 4 Risk and Penalty Logic

The scoring pipeline includes the following implemented controls:

- God Mode Wildcard: `resources: ["*"]` or `verbs: ["*"]`
	- Adds `+5.0` to affected RBAC binding edges.
- Overly-Permissive Token: `automountServiceAccountToken` is `true` or missing
	- Adds `+2.0` to Pod node risk.
- Privileged Container: any container has `securityContext.privileged: true`
	- Adds `+4.0` to Pod node risk.
- Secret Snooping: secrets `get`/`list` without `resourceNames`
	- Adds `+3.0` to `Role -> Secret` edge weight.

These are reflected naturally in shortest-path `risk_score` totals.

## Bonus 2: Live CVE Scoring (NVD)

Optional live CVE enrichment is available for Pod risk scoring. When enabled,
the ingestor attempts to map each container image tag to NVD CPE/CVE records and
adds the max CVSS score found to the Pod risk.

Notes:

- This feature is opt-in and disabled by default.
- Explicit Pod CVSS annotations still take precedence over live lookup.
- NVD rate limits apply (an API key is recommended).
- Set `NVD_API_KEY` in your environment or pass `--nvd-api-key`.
- Legacy normalized node payloads that use `cves` are accepted as a compatibility alias for `nvd_cve_ids`.
- Exported graph artifacts include both `nvd_cve_ids` (canonical) and `cves` (compatibility) on each node.

NVD source attribution notice (required by NVD terms):

"This product uses data from the NVD API but is not endorsed or certified by the NVD."

## Progress Update (2026-04-04)

### Completed so far

- Added NVD scoring service package:
	- `src/services/cve/nvd_scorer.py`
	- `src/services/cve/models.py`
	- `src/services/cve/__init__.py`
- Added optional kubectl-ingestion integration for live Pod CVE risk enrichment.
- Added CLI toggles for live scoring:
	- `--enable-nvd-scoring`
	- `--nvd-api-key`
	- `--nvd-timeout`
- Added API toggle via query parameter:
	- `enable_nvd_scoring=true`
- Preserved annotation precedence:
	- Existing Pod CVSS annotations override live NVD lookup.
- Added graceful fallback behavior:
	- Timeouts or NVD failures do not break ingestion.

### Validation completed

- Added and ran targeted tests for:
	- NVD scorer behavior and caching.
	- Ingestion risk enrichment and fallback handling.
	- API wiring and default behavior.
	- CLI orchestration regression checks.
- Current targeted test status: passing.

### Remaining improvements (next)

- Improve CPE matching precision for less common image naming/version patterns.
- Add request pacing/backoff for stricter NVD rate-limit handling.
- Optionally expose CVE metadata directly in API node payloads for frontend display.

## Prerequisites

- Python 3.10+
- `uv`
- `kubectl` (for live ingestion)
- Optional local Kubernetes runtime (`kind` recommended)

## Setup

```bash
uv sync
```

## Install As System CLI

From this `tool/` directory, install the command into your user tool environment:

```bash
uv tool install .
```

For local development with live code edits:

```bash
uv tool install --editable .
```

Run the CLI from anywhere:

```bash
hack2future --help
h2f --help
```

Upgrade after changes:

```bash
uv tool upgrade hack2future-cli
```

## Phase 6 API (Backend Server)

The FastAPI bridge used by the frontend is exposed from `src/api/app.py`.

### Run API locally

```bash
uv run uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

### Verify API health

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status":"ok"}
```

### Query graph-analysis endpoint

```bash
curl "http://localhost:8000/api/v1/graph-analysis?namespace=vulnerable-ns&include_cluster_rbac=true&max_hops=3&max_depth=8"

# Enable live NVD CVE scoring
curl "http://localhost:8000/api/v1/graph-analysis?namespace=vulnerable-ns&include_cluster_rbac=true&enable_nvd_scoring=true"
```

The response now also includes a top-level `temporal` object and `report.temporal`
with consecutive-scan diff results and new attack-path alerts.

### Snapshot management endpoints

List snapshots:

```bash
curl "http://localhost:8000/api/v1/snapshots?namespace=vulnerable-ns&limit=50"
```

Get snapshot detail by scope and timestamp:

```bash
curl "http://localhost:8000/api/v1/snapshots/api-upload__payload__vulnerable-ns__cluster-rbac__nvd-off/20260405T120000000000Z"
```

Rollback to a previous snapshot (promotes it to latest baseline in same scope):

```bash
curl -X POST "http://localhost:8000/api/v1/snapshots/api-upload__payload__vulnerable-ns__cluster-rbac__nvd-off/20260405T120000000000Z/rollback" \
	-H "Content-Type: application/json" \
	-d '{"reason":"restore baseline"}'
```

Rollback semantics:

- Rollback does not mutate live cluster resources.
- Rollback writes a new latest snapshot using the selected historical payload.
- Subsequent temporal diff comparisons use that promoted snapshot as baseline.

Common namespace checks:

- `namespace=vulnerable-ns`
- `namespace=secure-ns`

Optional local cluster bootstrap:

```bash
kind create cluster --name hack2future --config src/k8s-yaml/cluster-config.yaml
kubectl config use-context kind-hack2future
kubectl apply -f src/k8s-yaml/vulnerable-cluster.yaml
kubectl apply -f src/k8s-yaml/secure-cluster.yaml
```

## Usage

### Live kubectl ingestion (namespace scoped)

```bash
uv run python src/main.py --ingestor kubectl --namespace vulnerable-ns --graph-out out/vulnerable-graph.json --pdf-out out/vulnerable-report.pdf
uv run python src/main.py --ingestor kubectl --namespace secure-ns --graph-out out/secure-graph.json --pdf-out out/secure-report.pdf

# Enable live NVD CVE scoring for Pod images
uv run python src/main.py --ingestor kubectl --namespace vulnerable-ns --enable-nvd-scoring true --nvd-timeout 10
```

### Algorithm Mode CLI (Rubric-Friendly)

All core algorithms are directly invokable via named flags:

```bash
# Full report (default if no mode flag is set)
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --full-report

# Full report with only top 6 attack paths shown in Section 1
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --full-report --attack-path-output six

# Full report with all detected attack paths shown in Section 1
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --full-report --attack-path-output all

# Dijkstra shortest attack path (set source/target explicitly)
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --source User:default:dev-1 --target Database:data:production-db

# Dijkstra shortest attack path (fixture-style aliases are also accepted)
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --source user-dev1 --target db-production

# BFS blast radius only
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --blast-radius --source Pod:default:web-frontend --max-hops 3

# DFS cycle detection only
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --cycles

# Critical-node analysis only
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --critical-node --max-depth 8
```

Expected output snippets:

- Attack-path mode: `⚠ Attack Path Detected` and `Hops: <n> | Risk: <score> (<severity>)`
- Disconnected source/target in attack-path mode: `No path found between source and target.` (no exception)
- Blast-radius mode: `Blast Radius: <count> node(s) within <hops> hop(s)`
- Cycle mode: `Cycles: <count>`
- Critical-node mode: `Critical Node: <node>` and path-disruption metrics

Structured full-report readability contract:

- Section 1 through Summary are explicitly labeled and ordered.
- Each path block includes: Source, Target, Hops, Risk Score, and Severity label.
- Severity thresholds: `LOW < 9`, `MEDIUM >= 9`, `HIGH >= 11`, `CRITICAL >= 20`.
- Each path block includes path-specific remediation actions (for example CVE patching, binding removal, or permission revocation).
- Cycle findings include explicit break-cycle remediation guidance.
- Section 4 includes actionable remediation language with estimated impact (recommended node/binding and paths eliminated).

CLI behavior contract:

- `--help` prints usage text and exits with code `0`.
- Successful analysis runs exit with code `0`.
- Invalid explicit nodes (for example `--source Pod:default:not-real`) exit with non-zero code and a clean one-line error.
- Runtime errors are printed as human-readable `Error: ...` messages without traceback noise.

### Temporal Snapshot Diff Alerts (Bonus 3)

Temporal analysis is now automatic on every scan.

- Each run saves a timestamped snapshot for the current scan scope.
- Scope key includes namespace, RBAC mode, ingestor mode, and NVD toggle.
- Current scan is diffed against the immediately previous snapshot in the same scope.
- Alert is raised when a source can reach a sink now but could not in the previous snapshot.
- Structured CLI report renders Section 5 only when new temporal alerts or new paths exist.

Default snapshot location:

`tool/out/snapshots/<scope-id>/snapshot-<timestamp>.json`

Optional custom snapshot directory:

```bash
uv run python src/main.py --ingestor kubectl --namespace vulnerable-ns --snapshot-dir out/custom-snapshots
```

Temporal output fields (CLI/API/report):

- `is_first_snapshot` (baseline run, no previous diff)
- `new_attack_paths_count`
- `alerts[]` with source, target, hops, risk score
- node/edge delta counters under `node_changes` and `edge_changes`

### Namespace RBAC modes

Strict namespace mode (exclude all ClusterRoleBinding-derived nodes):

```bash
uv run python src/main.py --ingestor kubectl --namespace vulnerable-ns --include-cluster-rbac false --graph-out out/vulnerable-strict.json
```

Hybrid mode (default when namespace is set):

- `--include-cluster-rbac true`
- Includes only ClusterRoleBindings that reference ServiceAccount subjects in the target namespace.

### Mock ingestion

```bash
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --graph-out out/mock-graph.json --pdf-out out/mock-report.pdf
```

### Generate expected sample report output

Run from this `tool/` directory:

```bash
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json > ../tests/actual-output.txt
```

Check parity against provided sample output:

```bash
cd .. && diff -u tests/sample-output.txt tests/actual-output.txt
```

Notes for `tests/mock-cluster-graph.json`:

- `metadata.pre_planted_paths = 6` indicates six canonical attack chains were intentionally planted in the fixture.
- The full report lists all shortest source-to-sink attack paths under the active graph weights, so this fixture currently reports `18` attack paths.
- Four planted chains appear exactly, and two are represented by lower-cost variants due to additional shortcut edges in the same graph.

### Replay from exported graph JSON

```bash
uv run python src/main.py --graph-in out/vulnerable-graph.json --pdf-out out/replay-report.pdf
```

## CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--ingestor` | `kubectl` | Data source mode: `kubectl` or `mock`. |
| `--mock-file` | `mock-cluster-graph.json` | Mock JSON path when `--ingestor mock`. In this repo from `tool/`, use `../tests/mock-cluster-graph.json`. |
| `--graph-in` | `None` | Optional exported graph JSON input. Skips live/mock ingestion. |
| `--graph-out` | `cluster-graph.json` | Output path for normalized graph JSON artifact. |
| `--pdf-out` | `None` | Optional output path for PDF kill-chain report artifact. |
| `--fallback-file` | `None` | Optional fallback JSON if kubectl ingestion fails. |
| `--snapshot-dir` | `None` | Optional temporal snapshot root directory. Default: `tool/out/snapshots`. |
| `--include-cluster-rbac` | `true` | Controls cluster RBAC expansion: `false` = strict namespace mode (exclude all ClusterRoleBindings), `true` = include cluster RBAC (hybrid-filtered when `--namespace` is set). |
| `--enable-nvd-scoring` | `false` | Enables live NVD CVE scoring for Pod container image tags. |
| `--nvd-api-key` | `None` | Optional NVD API key (falls back to `NVD_API_KEY` env var). |
| `--nvd-timeout` | `10.0` | Timeout in seconds for each NVD HTTP request. |
| `--source` | `None` | Override source node id. |
| `--target` | `None` | Override target sink node id. |
| `--namespace` | `None` | Namespace scope for kubectl ingestion and source/sink auto-selection. |
| `--max-hops` | `3` | BFS hop limit for blast-radius analysis. |
| `--max-depth` | `8` | DFS depth bound for critical-node path counting on cyclic graphs. |
| `--attack-path-output` | `all` | Attack-path output size in full report: `all` or `six` (top 6 by risk ascending). |
| `--full-report` | `false` | Force full multi-section report rendering. Also default behavior when no mode flag is set. |
| `--attack-path` | `false` | Render focused Dijkstra attack-path section. |
| `--blast-radius` | `false` | Render focused BFS blast-radius section. |
| `--cycles` | `false` | Render focused DFS cycle-detection section. |
| `--critical-node` | `false` | Render focused critical-node analysis section. |

## Rubric Crosswalk

Use this section as a submission checklist that maps rubric items to concrete implementation evidence.

| Rubric checkpoint | Implementation evidence | Verification command |
|---|---|---|
| Ingest from live cluster or mock input | `src/ingestion/kubectl_runner.py`, `src/ingestion/mock_parser.py` | `uv run python -m unittest test/test_kubectl_runner.py test/test_mock_parser.py -v` |
| Build and replay normalized graph artifact | `src/graph/networkx_builder.py`, `src/main.py` (`--graph-out`, `--graph-in`) | `uv run python -m unittest test/test_networkx_builder.py test/test_main_export.py -v` |
| BFS blast-radius analysis | `src/analysis/blast_radius.py`, CLI mode `--blast-radius` | `uv run python -m unittest test/test_blast_radius.py -v` (includes rubric BFS-1, BFS-2, and isolated-source BFS-3 cases) |
| Dijkstra shortest attack path | `src/analysis/shortest_path.py`, CLI mode `--attack-path` | `uv run python -m unittest test/test_shortest_path.py test/test_dijkstra_rubric_cases.py -v` (includes DIJK-1, DIJK-2, DIJK-3/no-path, and weighted-vs-hop-count checks) |
| Attack path output accuracy (sequence, hops, risk sum, CVE labels, sort order) | `src/main.py` (`_enumerate_best_attack_paths`), `src/reporting/cli_formatter.py` | `uv run python -m unittest test/test_attack_path_accuracy.py -v` |
| DFS cycle detection | `src/analysis/cycle_detect.py`, CLI mode `--cycles` | `uv run python -m unittest test/test_cycle_detect.py -v` (includes DFS-1 mock full-graph exact cycle and DFS-2 three-cycle no-duplicate coverage) |
| Critical-node disruption analysis | `src/analysis/critical_node.py`, CLI mode `--critical-node` | `uv run python -m unittest test/test_critical_node.py -v` |
| Focused per-algorithm CLI rendering | `src/main.py` (`_selected_report_modes`, `_select_report_view`) | `uv run python -m unittest test/test_main_cli_modes.py -v` |
| CLI error messaging and exit-code behavior | `src/main.py` (`_run_cli_entrypoint`, `_format_cli_error`) | `uv run python src/main.py --help`; `uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --attack-path --source Pod:default:not-real --target Database:data:production-db` |
| CLI and PDF reporting artifacts | `src/reporting/cli_formatter.py`, `src/reporting/pdf_generator.py` | `uv run python -m unittest test/test_cli_formatter.py test/test_pdf_generator.py -v` |
| API contract for frontend | `src/api/routes/graph_analysis.py`, `src/services/contracts/graph_analysis_contract.py` | `uv run python -m unittest test/test_api/test_graph_analysis_api.py test/test_graph_analysis_contract.py -v` |
| Optional live NVD enrichment for Pods | `src/services/cve/nvd_scorer.py`, `src/ingestion/kubectl_runner.py` | `uv run python -m unittest test/test_nvd_scorer.py test/test_kubectl_runner.py -v` |

Mode command matrix (quick manual sanity):

```bash
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --attack-path --source User:default:dev-1 --target Database:data:production-db
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --blast-radius --source Pod:default:web-frontend
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --cycles
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --critical-node
```

## Schema Reference

The normalized graph artifact uses this top-level shape:

```json
{
	"schema_version": "1.0.0",
	"nodes": [ ... ],
	"edges": [ ... ]
}
```

Node fields:

- `node_id` (`Type:Namespace:Name`) unique node identifier used by traversal logic.
- `entity_type` resource/security type (`Pod`, `ServiceAccount`, `Role`, `ClusterRole`, `Secret`, `ConfigMap`, `User`, `Group`, etc.).
- `name` resource name.
- `namespace` namespace or `cluster` for cluster-scoped entities.
- `risk_score` non-negative node risk signal used in visualization and optional path-cost modes.
- `is_source` marks entry points used for source auto-selection.
- `is_sink` marks crown-jewel targets used for sink auto-selection.
- `nvd_enriched`, `nvd_source`, `nvd_max_cvss`, `nvd_cve_ids`, `nvd_image_refs` optional NVD enrichment metadata for Pod nodes.

Edge fields:

- `source_id`, `target_id` node references.
- `relationship_type` directed relation (`uses`, `bound_to`, `can_read`, `grants`, etc.).
- `weight` traversal cost contribution used by Dijkstra.
- `cve`, `cvss` optional vulnerability annotation shown in reports.
- `source_ref`, `target_ref`, `escalation_type` optional compatibility metadata.

Weight semantics:

- Base edge weights model privilege/trust traversal difficulty.
- Higher weights indicate more severe or sensitive movement steps.
- Additional penalties (wildcard RBAC, secret snooping) are applied during ingestion and become part of edge weights.

Example node row:

```json
{
	"node_id": "Pod:vulnerable-ns:frontend-webapp-vulnerable",
	"entity_type": "Pod",
	"name": "frontend-webapp-vulnerable",
	"namespace": "vulnerable-ns",
	"risk_score": 14.7,
	"is_source": true,
	"is_sink": false,
	"nvd_enriched": true,
	"nvd_source": "nvd",
	"nvd_max_cvss": 7.7,
	"nvd_cve_ids": ["CVE-2019-20372"]
}
```

Example edge row:

```json
{
	"source_id": "Pod:vulnerable-ns:frontend-webapp-vulnerable",
	"target_id": "ServiceAccount:vulnerable-ns:overly-permissive-sa",
	"relationship_type": "uses",
	"weight": 2.0,
	"cve": null,
	"cvss": null
}
```

## Artifacts

- Graph JSON: deterministic normalized export for downstream API/frontend consumers.
- PDF: formatted kill-chain report rendered from the same report model used by CLI output.

## Tests

Run full test suite:

```bash
uv run python -m unittest discover -s test -v
```

Run API-specific tests:

```bash
uv run python -m unittest test/test_api/test_graph_analysis_api.py -v
```

Run focused reporting tests:

```bash
uv run python -m unittest test/test_cli_formatter.py -v
uv run python -m unittest test/test_pdf_generator.py -v
uv run python -m unittest test/test_main_export.py -v
```

Run focused ingestion/graph compatibility tests:

```bash
uv run python -m unittest test/test_mock_parser.py -v
uv run python -m unittest test/test_networkx_builder.py -v
uv run python -m unittest test/test_kubectl_runner.py -v
```

## Key Paths

- Entry point: `src/main.py`
- Ingestion: `src/ingestion/kubectl_runner.py`, `src/ingestion/mock_parser.py`
- Graph storage: `src/graph/networkx_builder.py`
- Analysis: `src/analysis/*`
- Reporting: `src/reporting/cli_formatter.py`, `src/reporting/pdf_generator.py`
- Tests: `test/*`

## End-to-End Local Run (Backend + Frontend)

1. Terminal 1 (this folder):

```bash
uv sync
uv run uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

2. Terminal 2 (`../frontend`):

```bash
npm install
npm run dev
```

3. Open frontend app:

- `http://localhost:5173`

The Vite dev server proxies `/api` requests to `http://localhost:8000`.