# Hack2Future Frontend

React + Vite dashboard for Kubernetes attack-path analysis and temporal snapshot operations.

Current pages:

- Graph page: /graph
- Ingest page: /ingest
- Risk center page: /risks
- Snapshot vault page: /snapshots

Backend endpoints used by the UI:

- GET /api/v1/graph-analysis
- POST /api/v1/graph-analysis/ingest
- GET /api/v1/snapshots
- GET /api/v1/snapshots/{scope_id}/{snapshot_timestamp}
- POST /api/v1/snapshots/{scope_id}/{snapshot_timestamp}/rollback

## Prerequisites

- Node.js 18+
- npm
- Backend API running from ../tool on port 8000

## Install

From this folder:

```bash
npm install
```

## Run (Development)

```bash
npm run dev
```

Default app URL:

- http://localhost:5173

## API Connectivity

Vite is configured to proxy all /api requests to:

http://localhost:8000

That means no frontend code changes are needed for local development as long as the backend server is running.

If snapshots are empty in the UI, run at least one analysis from /graph or /ingest first so snapshot files are created.

## Recommended Local Workflow

1. Terminal 1 (backend in ../tool):

```bash
uv sync
uv run uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

2. Terminal 2 (frontend in this folder):

```bash
npm install
npm run dev
```

3. Open:

- http://localhost:5173

## Build

```bash
npm run build
```

Build artifacts are generated in:

- dist/

## Preview Production Build

```bash
npm run preview
```

## Useful Pages

- http://localhost:5173/graph
- http://localhost:5173/ingest
- http://localhost:5173/risks
- http://localhost:5173/snapshots

## Snapshot Vault Behavior

- View historical snapshots grouped by scan scope.
- Open a snapshot to inspect stored payload metadata and top risk nodes.
- Rollback promotes a selected old snapshot into a new latest snapshot in the same scope.
- Rollback changes temporal baseline only. It does not change live cluster resources.

## Troubleshooting

- If Graph/Risks loading fails, verify backend health:
  ```bash
  curl http://localhost:8000/health
  ```
- If dependencies changed, rerun npm install.
- If API still fails, inspect backend logs in the tool terminal.
- If /snapshots shows no data, run a scan first to generate snapshot files.
