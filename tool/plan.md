## Plan: Phase Roadmap Execution (Updated)

This plan reflects current repository progress and the exact remaining work for a submission-ready deliverable.

## Current Status

1. Phase 1 Environment and Foundation Setup: completed
- Project structure exists: [src/core](src/core), [src/ingestion](src/ingestion), [src/graph](src/graph), [src/analysis](src/analysis), [src/reporting](src/reporting).
- Data models are implemented in [src/core/models.py](src/core/models.py).
- Test manifests exist: [src/k8s-yaml/vulnerable-cluster.yaml](src/k8s-yaml/vulnerable-cluster.yaml), [src/k8s-yaml/secure-cluster.yaml](src/k8s-yaml/secure-cluster.yaml).
- Python baseline is aligned to 3.10+ in [pyproject.toml](pyproject.toml).
- Setup commands are documented in [README.md](README.md).

2. Phase 2 Data Ingestion: completed
- Live ingestion and namespace-scoped kubectl reading are implemented in [src/ingestion/kubectl_runner.py](src/ingestion/kubectl_runner.py).
- Mock ingestion is implemented in [src/ingestion/mock_parser.py](src/ingestion/mock_parser.py).
- RBAC subject and role relationship parsing is implemented.
- Role rule parsing to secrets is implemented.
- Ingestion unit coverage exists in [test/test_kubectl_runner.py](test/test_kubectl_runner.py) and [test/test_mock_parser.py](test/test_mock_parser.py).
- Deterministic graph export to cluster-graph.json is implemented in [src/main.py](src/main.py).
- Pod CVSS or CVE annotation parsing into risk_score enrichment is implemented in [src/ingestion/kubectl_runner.py](src/ingestion/kubectl_runner.py).
- Export behavior and enrichment tests are implemented in [test/test_main_export.py](test/test_main_export.py) and [test/test_kubectl_runner.py](test/test_kubectl_runner.py).

3. Phase 3 Graph Construction: completed
- NetworkX graph storage/builder exists in [src/graph/networkx_builder.py](src/graph/networkx_builder.py).
- Graph construction from normalized in-memory data is implemented via `from_cluster_graph_data(...)`.
- Graph-layer unit coverage exists in [test/test_networkx_builder.py](test/test_networkx_builder.py).
- Artifact read flow from exported cluster-graph.json is implemented via `from_exported_json(...)` and `from_json_file(...)`.
- Round-trip validation coverage (exported JSON -> graph rebuild -> equivalent nodes/edges) is implemented in [test/test_networkx_builder.py](test/test_networkx_builder.py).
- Reconstruction tests verify edge weights and relationship types are preserved in [test/test_networkx_builder.py](test/test_networkx_builder.py).
- Cycle-presence handling for artifact-based reconstruction is explicitly documented and covered by tests in [src/graph/networkx_builder.py](src/graph/networkx_builder.py) and [test/test_networkx_builder.py](test/test_networkx_builder.py).

4. Phase 4 Core Security Algorithms: completed
- BFS in [src/analysis/blast_radius.py](src/analysis/blast_radius.py).
- Dijkstra in [src/analysis/shortest_path.py](src/analysis/shortest_path.py).
- DFS cycle detection in [src/analysis/cycle_detect.py](src/analysis/cycle_detect.py).
- Critical node logic in [src/analysis/critical_node.py](src/analysis/critical_node.py).
- Attack-pattern implementation audit: implemented.
- God Mode Wildcard (`resources: ["*"]` or `verbs: ["*"]`): implemented as +5.0 penalty on affected RBAC binding edges in [src/ingestion/kubectl_runner.py](src/ingestion/kubectl_runner.py).
- Overly-Permissive Token (`automountServiceAccountToken` true or missing): implemented as +2.0 Pod risk in [src/ingestion/kubectl_runner.py](src/ingestion/kubectl_runner.py).
- Privileged Container (`securityContext.privileged: true`): implemented as +4.0 Pod risk in [src/ingestion/kubectl_runner.py](src/ingestion/kubectl_runner.py).
- Secret Snooping (secrets get or list without `resourceNames`): implemented as +3.0 Role -> Secret edge penalty in [src/ingestion/kubectl_runner.py](src/ingestion/kubectl_runner.py).
- Path-score impact checks for these penalties are covered in [test/test_shortest_path.py](test/test_shortest_path.py) and targeted ingestion checks in [test/test_kubectl_runner.py](test/test_kubectl_runner.py).
- Integration-style vulnerable vs secure path expectation checks are covered in [test/test_shortest_path.py](test/test_shortest_path.py).

5. Phase 5 Reporting and Deliverables: completed
- CLI report is implemented in [src/reporting/cli_formatter.py](src/reporting/cli_formatter.py).
- Main orchestration is wired in [src/main.py](src/main.py).
- CLI formatter tests are implemented in [test/test_cli_formatter.py](test/test_cli_formatter.py).
- PDF export module is implemented in [src/reporting/pdf_generator.py](src/reporting/pdf_generator.py).
- CLI output path flag for PDF export is implemented via `--pdf-out` in [src/main.py](src/main.py).
- Graph JSON output path remains configurable via `--graph-out` in [src/main.py](src/main.py).
- CLI output style is updated to compact Kill Chain formatting with warning and check symbols, arrow path formatting, and friendly node labels in [src/reporting/cli_formatter.py](src/reporting/cli_formatter.py).
- PDF generation and section parity smoke coverage are implemented in [test/test_pdf_generator.py](test/test_pdf_generator.py) and [test/test_main_export.py](test/test_main_export.py).

6. Phase 6 Bonus (optional): not started
- No FastAPI bridge or Cytoscape UI implementation yet.

## Execution Plan (Remaining)

1. Maintain Phase 2 stability
- Keep regression coverage for ingestion and export in [test/test_kubectl_runner.py](test/test_kubectl_runner.py), [test/test_mock_parser.py](test/test_mock_parser.py), and [test/test_main_export.py](test/test_main_export.py).
- Keep exported schema backward-compatible for downstream frontend/API consumers.

2. Keep Phase 4 stable
- Preserve regression coverage for attack-pattern penalties and node-risk enrichments in [test/test_kubectl_runner.py](test/test_kubectl_runner.py) and [test/test_shortest_path.py](test/test_shortest_path.py).
- Keep vulnerable-vs-secure integration-style path checks passing in [test/test_shortest_path.py](test/test_shortest_path.py).

3. Stabilize release checklist
- Run all tests in [test](test) using uv.
- Verify namespace-scoped runs for both environments.
- Verify artifact outputs: cluster-graph.json and PDF.

## Verification Commands

1. Apply fixtures
- kubectl apply -f [src/k8s-yaml/vulnerable-cluster.yaml](src/k8s-yaml/vulnerable-cluster.yaml)
- kubectl apply -f [src/k8s-yaml/secure-cluster.yaml](src/k8s-yaml/secure-cluster.yaml)

2. Run analysis
- uv run python src/main.py --ingestor kubectl --namespace vulnerable-ns
- uv run python src/main.py --ingestor kubectl --namespace secure-ns

3. Run tests
- uv run python -m unittest discover -s [test](test) -v

## Decisions

1. Included now
- Finish phases 2 through 5 for a submission-grade CLI + artifact workflow.

2. Deferred by default
- Phase 6 FastAPI and frontend visualization unless timeline permits.

3. Scope rule
- Namespace-scoped analysis remains default for deterministic test environments.

4. Tooling rule
- Use uv for Python execution, dependency sync, and test commands.

## Appendix: Phase 6 Two-Page Frontend Plan (Added 2026-04-04)

This appendix defines the exact Phase 6 execution scope based on the provided design assets.

### Scope Lock

1. Frontend will have exactly 2 pages
- Graph page
- Risks page

2. Design mapping
- Graph page source: [../design/2nd one.html](../design/2nd%20one.html)
- Risks page source: [../design/frontend_riskandalert.html](../design/frontend_riskandalert.html)

3. Current frontend state
- [../frontend](../frontend) is empty and will be initialized in this phase.

### Phase 6 Deliverables

1. FastAPI bridge (backend)
- Add `GET /api/v1/graph-analysis?namespace=<ns>`.
- Return one unified payload for both pages: context, summary, nodes, edges, and analysis blocks.
- Keep schema backward-compatible and include clear error responses.

2. Graph page implementation
- Build the graph experience from [../design/2nd one.html](../design/2nd%20one.html).
- Render directed graph (Cytoscape).
- Add overlay toggles for attack path, blast radius, cycles, and critical node.
- Add graph-oriented filters and node detail interactions.

3. Risks page implementation
- Build the risk dashboard from [../design/frontend_riskandalert.html](../design/frontend_riskandalert.html).
- Render summary cards, critical-node panel, severity/risk sections, and recommendations.
- Bind all values to the same API payload used by Graph page.

4. Shared navigation and state
- Route structure: `/graph` and `/risks`.
- Persist selected namespace and filters while moving between pages.

5. Documentation updates
- Add Phase 6 run instructions and API usage to [README.md](README.md).

### Implementation Sequence

1. Build API contract service and endpoint first.
2. Scaffold frontend app with two routes.
3. Implement Graph page (design fidelity + live data).
4. Implement Risks page (design fidelity + live data).
5. Add shared filters/state and page-to-page continuity.
6. Validate secure/vulnerable namespace behavior and finalize docs.

### Verification Checklist

1. API returns valid payload for both `vulnerable-ns` and `secure-ns`.
2. Graph page renders nodes/edges and overlay toggles from live API output.
3. Risks page renders risk cards, critical node details, and recommendations from the same output.
4. Secure namespace shows no attack path while still rendering graph and risk summary.
5. Vulnerable namespace shows critical path and elevated risk indicators.
6. Existing backend tests remain green.
