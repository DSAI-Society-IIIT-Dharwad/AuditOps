# CLI Modes and Examples

All commands below assume you are in `tool/` with the project virtual environment activated.

## Common Full-Report Runs

Mock fixture full report:

```bash
cd tool
python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --full-report
```

Limit Section 1 to top 6 attack paths:

```bash
python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --full-report --attack-path-output six
```

Show all detected attack paths:

```bash
python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --full-report --attack-path-output all
```

## Focused Algorithm Modes

Dijkstra (explicit source/target):

```bash
python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --attack-path --source User:default:dev-1 --target Database:data:production-db
```

BFS blast radius:

```bash
python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --blast-radius --source Pod:default:web-frontend --max-hops 3
```

DFS cycle detection:

```bash
python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --cycles
```

Critical-node analysis:

```bash
python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --critical-node --max-depth 8
```

## Live Ingestion

```bash
python src/main.py --ingestor kubectl --namespace vulnerable-ns --graph-out out/vulnerable-graph.json --pdf-out out/vulnerable-report.pdf
```

Enable live NVD scoring:

```bash
python src/main.py --ingestor kubectl --namespace vulnerable-ns --enable-nvd-scoring true --nvd-timeout 10
```

## Graph Export and Replay

Export normalized graph and PDF:

```bash
python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json --graph-out out/mock-graph.json --pdf-out out/mock-report.pdf
```

Replay from a graph artifact:

```bash
python src/main.py --graph-in out/mock-graph.json --full-report
```

## Temporal Snapshot Controls

Use custom snapshot directory:

```bash
python src/main.py --ingestor kubectl --namespace vulnerable-ns --snapshot-dir out/custom-snapshots
```

## Namespace RBAC Modes

Strict namespace mode (exclude cluster RBAC expansion):

```bash
python src/main.py --ingestor kubectl --namespace vulnerable-ns --include-cluster-rbac false
```

Hybrid mode (default with namespace + include cluster RBAC):

```bash
python src/main.py --ingestor kubectl --namespace vulnerable-ns --include-cluster-rbac true
```

## CLI Flags (Reference)

| Flag | Default | Description |
|---|---|---|
| `--ingestor` | `kubectl` | Ingestor mode: `kubectl` or `mock`. |
| `--mock-file` | `mock-cluster-graph.json` | Mock file path when using `mock`. |
| `--graph-in` | `None` | Load graph JSON directly, skip ingestion. |
| `--graph-out` | `cluster-graph.json` | Export path for normalized graph JSON. |
| `--pdf-out` | `None` | Optional PDF output path. |
| `--snapshot-dir` | `None` | Optional snapshot root directory. |
| `--include-cluster-rbac` | `true` | Include or exclude cluster RBAC expansion. |
| `--enable-nvd-scoring` | `false` | Enable live NVD image/CVE enrichment. |
| `--nvd-api-key` | `None` | NVD API key (or `NVD_API_KEY`). |
| `--nvd-timeout` | `10.0` | NVD request timeout in seconds. |
| `--source` | `None` | Override source node id. |
| `--target` | `None` | Override target sink node id. |
| `--namespace` | `None` | Namespace scope. |
| `--max-hops` | `3` | BFS hop limit. |
| `--max-depth` | `8` | DFS depth for critical-node counting. |
| `--attack-path-output` | `all` | Section 1 list size in full report. |
| `--full-report` | `false` | Render full multi-section report. |
| `--attack-path` | `false` | Focused Dijkstra section. |
| `--blast-radius` | `false` | Focused BFS section. |
| `--cycles` | `false` | Focused DFS section. |
| `--critical-node` | `false` | Focused critical-node section. |
