# Kubernetes Attack Path Visualizer

Command-line analyzer for Kubernetes privilege escalation paths.

It ingests cluster state, builds a directed graph of trust and permission relationships, runs security analysis algorithms, prints a kill-chain style CLI report, and can export both JSON and PDF artifacts.

## Current Scope (Phases 2-5)

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

## Prerequisites

- Python 3.10+
- `uv`
- `kubectl` (for live ingestion)
- Optional local Kubernetes runtime (`kind` recommended)

## Setup

```bash
uv sync
```

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
```

### Mock ingestion

```bash
uv run python src/main.py --ingestor mock --mock-file mock-cluster-graph.json --graph-out out/mock-graph.json --pdf-out out/mock-report.pdf
```

### Replay from exported graph JSON

```bash
uv run python src/main.py --graph-in out/vulnerable-graph.json --pdf-out out/replay-report.pdf
```

## CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--ingestor` | `kubectl` | Data source mode: `kubectl` or `mock`. |
| `--mock-file` | `mock-cluster-graph.json` | Mock JSON path when `--ingestor mock`. |
| `--graph-in` | `None` | Optional exported graph JSON input. Skips live/mock ingestion. |
| `--graph-out` | `cluster-graph.json` | Output path for normalized graph JSON artifact. |
| `--pdf-out` | `None` | Optional output path for PDF kill-chain report artifact. |
| `--fallback-file` | `None` | Optional fallback JSON if kubectl ingestion fails. |
| `--source` | `None` | Override source node id. |
| `--target` | `None` | Override target sink node id. |
| `--namespace` | `None` | Namespace scope for kubectl ingestion and source/sink auto-selection. |
| `--max-hops` | `3` | BFS hop limit for blast-radius analysis. |
| `--max-depth` | `8` | DFS depth bound for critical-node path counting on cyclic graphs. |

## Artifacts

- Graph JSON: deterministic normalized export for downstream API/frontend consumers.
- PDF: formatted kill-chain report rendered from the same report model used by CLI output.

## Tests

Run full test suite:

```bash
uv run python -m unittest discover -s test -v
```

Run focused reporting tests:

```bash
uv run python -m unittest test/test_cli_formatter.py -v
uv run python -m unittest test/test_pdf_generator.py -v
uv run python -m unittest test/test_main_export.py -v
```

## Key Paths

- Entry point: `src/main.py`
- Ingestion: `src/ingestion/kubectl_runner.py`, `src/ingestion/mock_parser.py`
- Graph storage: `src/graph/networkx_builder.py`
- Analysis: `src/analysis/*`
- Reporting: `src/reporting/cli_formatter.py`, `src/reporting/pdf_generator.py`
- Tests: `test/*`