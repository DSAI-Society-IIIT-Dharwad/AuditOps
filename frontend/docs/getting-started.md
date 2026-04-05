# Getting Started

## Prerequisites

- Node.js 18+
- npm
- Backend API running from `../tool` on port `8000`

## Install and Run

```bash
cd frontend
npm install
npm run dev
```

Default app URL:

- `http://localhost:5173`

## Build and Preview

Build production bundle:

```bash
npm run build
```

Preview production build:

```bash
npm run preview
```

## Recommended Local Workflow

Terminal 1 (backend, Linux/macOS):

```bash
cd tool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

Terminal 1 (backend, Windows PowerShell):

```powershell
cd tool
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

Terminal 2 (frontend):

```bash
cd frontend
npm install
npm run dev
```
