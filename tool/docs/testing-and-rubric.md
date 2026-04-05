# Testing and Rubric Crosswalk

All commands below assume you are in `tool/` with the project virtual environment activated.

## Run Full Test Suite

```bash
cd tool
python -m unittest discover -s test -v
```

## Focused Test Runs

API tests:

```bash
python -m unittest test/test_api/test_graph_analysis_api.py -v
```

Reporting tests:

```bash
python -m unittest test/test_cli_formatter.py test/test_pdf_generator.py test/test_main_export.py -v
```

Ingestion and graph tests:

```bash
python -m unittest test/test_mock_parser.py test/test_networkx_builder.py test/test_kubectl_runner.py -v
```

Algorithm tests:

```bash
python -m unittest test/test_shortest_path.py test/test_blast_radius.py test/test_cycle_detect.py test/test_critical_node.py -v
```

## Rubric Crosswalk

| Rubric checkpoint | Evidence |
|---|---|
| Ingest from live cluster or mock input | `src/ingestion/kubectl_runner.py`, `src/ingestion/mock_parser.py` |
| Build and replay normalized graph | `src/graph/networkx_builder.py`, `src/main.py` (`--graph-out`, `--graph-in`) |
| Dijkstra shortest attack path | `src/analysis/shortest_path.py` |
| BFS blast radius | `src/analysis/blast_radius.py` |
| DFS cycle detection | `src/analysis/cycle_detect.py` |
| Critical-node disruption analysis | `src/analysis/critical_node.py` |
| Focused algorithm CLI modes | `src/main.py` mode-selection logic |
| CLI and PDF reporting | `src/reporting/cli_formatter.py`, `src/reporting/pdf_generator.py` |
| API contract for frontend | `src/api/routes/graph_analysis.py`, `src/services/contracts/graph_analysis_contract.py` |
| Temporal diff and rollback baseline | `src/services/temporal/*` |
| Optional live NVD enrichment | `src/services/cve/nvd_scorer.py` |

## Sample Output Parity Check

```bash
cd tool
python src/main.py --ingestor mock --mock-file ../tests/mock-cluster-graph.json > ../tests/actual-output.txt
cd ..
diff -u tests/sample-output.txt tests/actual-output.txt
```

## Behavior Contracts to Validate

- `--help` exits successfully.
- Successful analysis exits with code `0`.
- Invalid explicit node inputs fail with clean error messages.
- Full report contains all core sections in order.
