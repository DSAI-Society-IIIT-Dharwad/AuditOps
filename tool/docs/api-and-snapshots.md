# API and Snapshots

## Run API Server

Linux/macOS:

```bash
cd tool
source .venv/bin/activate
uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

Windows PowerShell:

```powershell
cd tool
.\.venv\Scripts\Activate.ps1
uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

Health:

```bash
curl http://localhost:8000/health
```

## Primary Endpoints

- `GET /api/v1/graph-analysis`
- `POST /api/v1/graph-analysis/ingest`
- `GET /api/v1/snapshots`
- `GET /api/v1/snapshots/{scope_id}/{snapshot_timestamp}`
- `POST /api/v1/snapshots/{scope_id}/{snapshot_timestamp}/rollback`

## Example Requests

Graph analysis:

```bash
curl "http://localhost:8000/api/v1/graph-analysis?namespace=vulnerable-ns&include_cluster_rbac=true&max_hops=3&max_depth=8"
```

Enable live NVD scoring:

```bash
curl "http://localhost:8000/api/v1/graph-analysis?namespace=vulnerable-ns&include_cluster_rbac=true&enable_nvd_scoring=true"
```

List snapshots:

```bash
curl "http://localhost:8000/api/v1/snapshots?namespace=vulnerable-ns&limit=50"
```

Get snapshot detail:

```bash
curl "http://localhost:8000/api/v1/snapshots/api-upload__payload__vulnerable-ns__cluster-rbac__nvd-off/20260405T120000000000Z"
```

Rollback snapshot:

```bash
curl -X POST "http://localhost:8000/api/v1/snapshots/api-upload__payload__vulnerable-ns__cluster-rbac__nvd-off/20260405T120000000000Z/rollback" \
  -H "Content-Type: application/json" \
  -d '{"reason":"restore baseline"}'
```

## Temporal Fields in Responses

Common temporal data includes:

- `is_first_snapshot`
- `new_attack_paths_count`
- `alerts[]`
- node and edge delta counters
- `snapshot_timestamp`
- `previous_snapshot_timestamp`

## Rollback Semantics

- Rollback does not mutate live Kubernetes resources.
- Rollback promotes a historical snapshot into a new latest baseline in the same scope.
- Future temporal diff calculations compare against that promoted baseline.
