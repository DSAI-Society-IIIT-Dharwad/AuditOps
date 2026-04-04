# Hack2Future Frontend (Phase 6)

Two-page React + Vite UI for Kubernetes attack-path analysis:

- Graph page: /graph
- Risk center page: /risks

The frontend consumes backend data from the FastAPI endpoint:

- /api/v1/graph-analysis

## Prerequisites

- Node.js 18+
- npm
- Backend API running from ../tool on port 8000

## Install

From this folder:

npm install

## Run (Development)

npm run dev

Default app URL:

http://localhost:5173

## API Connectivity

Vite is configured to proxy all /api requests to:

http://localhost:8000

That means no frontend code changes are needed for local development as long as the backend server is running.

## Recommended Local Workflow

1. Terminal 1 (backend in ../tool):

uv sync
uv run uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload

2. Terminal 2 (frontend in this folder):

npm install
npm run dev

3. Open:

http://localhost:5173

## Build

npm run build

Build artifacts are generated in:

- dist/

## Preview Production Build

npm run preview

## Useful Pages

- http://localhost:5173/graph
- http://localhost:5173/risks

## Troubleshooting

- If Graph/Risks loading fails, verify backend health:
  curl http://localhost:8000/health
- If dependencies changed, rerun npm install.
- If API still fails, inspect backend logs in the tool terminal.
