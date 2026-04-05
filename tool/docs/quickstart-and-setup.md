# Quickstart and Setup

## Prerequisites

- Python 3.10+
- `pip`
- Optional for live ingestion: `kubectl`
- Optional for local cluster: `kind`

## Five-Minute CLI Quickstart (Linux/macOS)

From repository root:

```bash
cd tool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
hack2future --ingestor mock --mock-file ../tests/mock-cluster-graph.json --full-report
```

## Five-Minute CLI Quickstart (Windows PowerShell)

From repository root:

```powershell
cd tool
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
hack2future --ingestor mock --mock-file ../tests/mock-cluster-graph.json --full-report
```

## Five-Minute CLI Quickstart (Windows Command Prompt)

From repository root:

```bat
cd tool
py -3 -m venv .venv
.\.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -e .
hack2future --ingestor mock --mock-file ../tests/mock-cluster-graph.json --full-report
```

Expected section markers:

```text
[ SECTION 1 — ATTACK PATH DETECTION (Dijkstra) ]
[ SECTION 2 — BLAST RADIUS ANALYSIS (BFS, depth=3) ]
[ SECTION 3 — CIRCULAR PERMISSION DETECTION (DFS) ]
[ SECTION 4 — CRITICAL NODE ANALYSIS ]
SUMMARY
```

## Setup Options

### Option A (recommended, editable install)

Linux/macOS:

```bash
cd tool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Windows PowerShell:

```powershell
cd tool
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

### Option B (dependencies-only install)

Linux/macOS:

```bash
cd tool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
cd tool
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Verify CLI Entry Points

If you installed with Option A (`python -m pip install -e .`) or a regular package install (`python -m pip install .`):

```bash
hack2future --help
h2f --help
```

## Run Backend API

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

Health check:

```bash
curl http://localhost:8000/health
```

## End-to-End Local Run (Backend + Frontend)

Terminal 1 (backend, Linux/macOS):

```bash
cd tool
source .venv/bin/activate
uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

Terminal 1 (backend, Windows PowerShell):

```powershell
cd tool
.\.venv\Scripts\Activate.ps1
uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

Terminal 2:

```bash
cd frontend
npm install
npm run dev
```

Open:

- `http://localhost:5173`

## Optional Local Cluster Bootstrap

```bash
kind create cluster --name hack2future --config src/k8s-yaml/cluster-config.yaml
kubectl config use-context kind-hack2future
kubectl apply -f src/k8s-yaml/vulnerable-cluster.yaml
kubectl apply -f src/k8s-yaml/secure-cluster.yaml
```
