# Hack2Future

Kubernetes security analysis platform for finding attack paths, blast radius, cyclic privilege chains, and high-impact remediation points.

The repository contains:

- Backend analysis engine and API: [tool/README.md](tool/README.md)
- Frontend dashboard (graph, ingest, risk, snapshots): [frontend/README.md](frontend/README.md)

## Repository Layout

- [tool](tool): Python analysis engine, FastAPI server, temporal snapshot system
- [frontend](frontend): React + Vite UI
- [tests](tests): sample and mock outputs used for report parity checks

## What The Platform Does

- Ingests cluster state from live kubectl, uploaded YAML/JSON, or mock files
- Builds a directed trust/permission graph
- Runs core analyses:
	- Shortest attack paths (Dijkstra)
	- Blast radius (BFS)
	- Circular permission detection (DFS)
	- Critical-node disruption ranking
- Tracks temporal drift between scans via snapshots
- Supports snapshot browsing and rollback-to-baseline from the UI

## Quick Start

### 1) Backend API

```bash
cd tool
uv sync
uv run uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

Health check:

```bash
curl http://localhost:8000/health
```

### 2) Frontend

```bash
cd frontend
npm install
npm run dev
```

Open:

- http://localhost:5173/graph
- http://localhost:5173/ingest
- http://localhost:5173/risks
- http://localhost:5173/snapshots

## Snapshot Rollback Semantics

Snapshot rollback does not change cluster resources.

Rollback promotes a chosen historical snapshot into a new latest snapshot in the same scope so future temporal comparisons use that promoted baseline.

## Report Parity

To verify CLI output parity against the sample output:

```bash
cd tool
uv run python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json > ../tests/actual-output.txt
cd ..
diff -u tests/sample-output.txt tests/actual-output.txt
```

## Documentation Entry Points

- Backend details and API reference: [tool/README.md](tool/README.md)
- Frontend pages and usage: [frontend/README.md](frontend/README.md)
