## Plan: Phase Roadmap Execution (Updated)

This plan reflects current repository progress and the exact remaining work for a submission-ready deliverable.

## Current Status

1. Phase 1 Environment and Foundation Setup: completed
- Project structure exists: [src/core](src/core), [src/ingestion](src/ingestion), [src/graph](src/graph), [src/analysis](src/analysis), [src/reporting](src/reporting).
- Data models are implemented in [src/core/models.py](src/core/models.py).
- Test manifests exist: [src/k8s-yaml/vulnerable-cluster.yaml](src/k8s-yaml/vulnerable-cluster.yaml), [src/k8s-yaml/secure-cluster.yaml](src/k8s-yaml/secure-cluster.yaml).
- Python baseline is aligned to 3.10+ in [pyproject.toml](pyproject.toml).
- Setup commands are documented in [README.md](README.md).

2. Phase 2 Data Ingestion: mostly completed
- Live ingestion and namespace-scoped kubectl reading are implemented in [src/ingestion/kubectl_runner.py](src/ingestion/kubectl_runner.py).
- Mock ingestion is implemented in [src/ingestion/mock_parser.py](src/ingestion/mock_parser.py).
- RBAC subject and role relationship parsing is implemented.
- Role rule parsing to secrets is implemented.
- Remaining: deterministic export to cluster-graph.json and tests for export.

3. Phase 3 Graph Construction: mostly completed
- NetworkX graph storage/builder exists in [src/graph/networkx_builder.py](src/graph/networkx_builder.py).
- Remaining: explicit artifact read flow from exported cluster-graph.json and tests around reconstruction.

4. Phase 4 Core Security Algorithms: completed baseline
- BFS in [src/analysis/blast_radius.py](src/analysis/blast_radius.py).
- Dijkstra in [src/analysis/shortest_path.py](src/analysis/shortest_path.py).
- DFS cycle detection in [src/analysis/cycle_detect.py](src/analysis/cycle_detect.py).
- Critical node logic in [src/analysis/critical_node.py](src/analysis/critical_node.py).
- Remaining: risk-scoring fidelity enhancement (pod CVSS and path composition tuning) and integration tests across vulnerable vs secure namespaces.

5. Phase 5 Reporting and Deliverables: partially completed
- CLI report is implemented in [src/reporting/cli_formatter.py](src/reporting/cli_formatter.py).
- Main orchestration is wired in [src/main.py](src/main.py).
- Remaining: PDF generator module and CLI option to export PDF.

6. Phase 6 Bonus (optional): not started
- No FastAPI bridge or Cytoscape UI implementation yet.

## Execution Plan (Remaining)

1. Complete Phase 2 export
- Add normalized graph export to JSON in [src/main.py](src/main.py) with flag support (default path cluster-graph.json).
- Reuse Node and Edge schema from [src/core/models.py](src/core/models.py).
- Add unit tests in [test/test_kubectl_runner.py](test/test_kubectl_runner.py) and/or new export-focused tests.

2. Complete Phase 3 artifact import and validation
- Add explicit graph reconstruction from exported JSON using [src/graph/networkx_builder.py](src/graph/networkx_builder.py).
- Add tests verifying exported graph round-trips into equivalent node and edge sets.

3. Strengthen Phase 4 with integration checks
- Add integration tests that compare vulnerable and secure behavior:
- vulnerable namespace: non-zero source-to-secret path expected
- secure namespace: no critical secret path expected

4. Complete Phase 5 PDF deliverable
- Implement [src/reporting/pdf_generator.py](src/reporting/pdf_generator.py).
- Extend [src/main.py](src/main.py) with PDF output option.
- Add smoke test for PDF generation and section parity with CLI output.

5. Stabilize release checklist
- Run all tests in [test](test).
- Verify namespace-scoped runs for both environments.
- Verify artifact outputs: cluster-graph.json and PDF.

## Verification Commands

1. Apply fixtures
- kubectl apply -f [src/k8s-yaml/vulnerable-cluster.yaml](src/k8s-yaml/vulnerable-cluster.yaml)
- kubectl apply -f [src/k8s-yaml/secure-cluster.yaml](src/k8s-yaml/secure-cluster.yaml)

2. Run analysis
- python src/main.py --ingestor kubectl --namespace vulnerable-ns
- python src/main.py --ingestor kubectl --namespace secure-ns

3. Run tests
- python -m unittest discover -s [test](test) -v

## Decisions

1. Included now
- Finish phases 2 through 5 for a submission-grade CLI + artifact workflow.

2. Deferred by default
- Phase 6 FastAPI and frontend visualization unless timeline permits.

3. Scope rule
- Namespace-scoped analysis remains default for deterministic test environments.
