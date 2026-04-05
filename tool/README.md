# Kubernetes Attack Path Visualizer (Backend)

This README is the navigation hub for backend documentation.

## Quick Links

- Fast command reference: [FASTSTART.md](FASTSTART.md)
- Docs index: [docs/README.md](docs/README.md)
- Setup and local run: [docs/quickstart-and-setup.md](docs/quickstart-and-setup.md)
- CLI modes and examples: [docs/cli-modes-and-examples.md](docs/cli-modes-and-examples.md)
- API and snapshot workflows: [docs/api-and-snapshots.md](docs/api-and-snapshots.md)
- Architecture and algorithms: [docs/architecture-and-algorithms.md](docs/architecture-and-algorithms.md)
- Graph schema: [docs/schema-reference.md](docs/schema-reference.md)
- Testing and rubric crosswalk: [docs/testing-and-rubric.md](docs/testing-and-rubric.md)

## Most Common Commands

Create environment and install dependencies (Linux/macOS):

```bash
cd tool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Create environment and install dependencies (Windows PowerShell):

```powershell
cd tool
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Run full report on mock fixture:

```bash
python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --full-report
```

Run API server:

```bash
uvicorn api.app:app --app-dir src --host 0.0.0.0 --port 8000 --reload
```

Run tests:

```bash
python -m unittest discover -s test -v
```
