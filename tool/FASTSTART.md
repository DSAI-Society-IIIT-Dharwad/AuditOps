# Hack2Future Tool Faststart

This is a copy-paste guide for the backend analyzer so you can run setup, features, API, and tests quickly.

## 1) What Features Exist

- Graph ingestion:
  - Live Kubernetes ingestion via `kubectl`
  - Mock ingestion via JSON fixture
  - Replay analysis from exported graph JSON
- Core analysis:
  - Shortest attack path (Dijkstra)
  - Blast radius (BFS)
  - Circular permission detection (DFS)
  - Critical node identification
- Reporting outputs:
  - CLI kill-chain style report
  - Graph JSON export artifact
  - PDF report export
- Temporal analysis:
  - Auto-saved snapshots per scan scope
  - Consecutive-scan diff and new attack-path alerts
- API:
  - FastAPI endpoint for graph and risk data
- Bonus 2 (opt-in):
  - Live NVD CVE scoring for Pod image tags

## 2) One-Time Setup

From `tool/`:

```bash
uv sync
```

## 3) Daily Fast Workflow

### Terminal A: backend API

```bash
cd /home/sg/dev/Hack2Future/tool
uv run uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

### Terminal B: run analysis commands

```bash
cd /home/sg/dev/Hack2Future/tool
```

## 4) Core CLI Commands

### A) Live cluster (namespace scoped)

```bash
uv run python src/main.py --ingestor kubectl --namespace vulnerable-ns --graph-out out/vulnerable-graph.json --pdf-out out/vulnerable-report.pdf
uv run python src/main.py --ingestor kubectl --namespace secure-ns --graph-out out/secure-graph.json --pdf-out out/secure-report.pdf
```

### B) Namespace RBAC modes

Strict mode (exclude cluster role bindings):

```bash
uv run python src/main.py --ingestor kubectl --namespace vulnerable-ns --include-cluster-rbac false --graph-out out/vulnerable-strict.json
```

Hybrid mode (default behavior):

```bash
uv run python src/main.py --ingestor kubectl --namespace vulnerable-ns --include-cluster-rbac true --graph-out out/vulnerable-hybrid.json
```

### C) Mock mode

```bash
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --graph-out out/mock-graph.json --pdf-out out/mock-report.pdf
```

### D) Replay from exported graph

```bash
uv run python src/main.py --graph-in out/vulnerable-graph.json --pdf-out out/replay-report.pdf
```

### E) Temporal diff with explicit snapshot directory

```bash
uv run python src/main.py --ingestor kubectl --namespace vulnerable-ns --snapshot-dir out/custom-snapshots
```

Notes:

- First run in a scope creates a baseline snapshot.
- Next run in the same scope compares against the previous snapshot.
- Alert is emitted when a new source-to-sink path becomes reachable.

## 5) Bonus 2: Live CVE Scoring (NVD)

Optional feature. Disabled by default.

### Recommended: set API key once

```bash
export NVD_API_KEY="your_nvd_api_key"
```

### Run with live NVD scoring

```bash
uv run python src/main.py --ingestor kubectl --namespace vulnerable-ns --enable-nvd-scoring true --nvd-timeout 10 --graph-out out/vulnerable-nvd.json
```

### Notes

- If Pod annotations already include CVSS, annotation score takes precedence.
- If NVD is unavailable or times out, ingestion continues.
- NVD rate limits still apply; API key is strongly recommended.

## 6) API Commands

### Health

```bash
curl http://localhost:8000/health
```

### Standard graph analysis

```bash
curl "http://localhost:8000/api/v1/graph-analysis?namespace=vulnerable-ns&include_cluster_rbac=true&max_hops=3&max_depth=8"
```

### Graph analysis with live NVD scoring

```bash
curl "http://localhost:8000/api/v1/graph-analysis?namespace=vulnerable-ns&include_cluster_rbac=true&enable_nvd_scoring=true"
```

## 7) Local Cluster Bootstrap (Optional)

```bash
kind create cluster --name hack2future --config src/k8s-yaml/cluster-config.yaml
kubectl config use-context kind-hack2future
kubectl apply -f src/k8s-yaml/vulnerable-cluster.yaml
kubectl apply -f src/k8s-yaml/secure-cluster.yaml
```

## 8) Testing Commands

### Full suite

```bash
uv run python -m unittest discover -s test -v
```

### High-value focused runs

```bash
uv run python -m unittest test/test_api/test_graph_analysis_api.py -v
uv run python -m unittest test/test_kubectl_runner.py -v
uv run python -m unittest test/test_nvd_scorer.py -v
uv run python -m unittest test/test_main_export.py -v
```

## 9) Most Useful Paths

- Entry point: `src/main.py`
- API app: `src/api/app.py`
- API route: `src/api/routes/graph_analysis.py`
- Ingestion: `src/ingestion/kubectl_runner.py`
- NVD scorer: `src/services/cve/nvd_scorer.py`
- Tests: `test/`

## 10) Quick Troubleshooting

- `kubectl` errors:
  - Verify context: `kubectl config current-context`
  - Verify namespace exists: `kubectl get ns`
- API not reachable:
  - Ensure uvicorn is running on `:8000`
- NVD scoring appears inactive:
  - Ensure `--enable-nvd-scoring true` is set
  - Ensure image tags are versioned (non-`latest` helps matching)
  - Ensure `NVD_API_KEY` is set for better rate limits
