# Architecture and Algorithms

## Scope

- Ingest live Kubernetes data, uploaded payloads, or mock fixtures.
- Build a directed graph of trust, permissions, and resource relationships.
- Run 4 core graph analyses.
- Render CLI and PDF reports.
- Persist temporal snapshots and detect drift.

## Analysis Algorithms

1. Dijkstra shortest attack path
- Purpose: lowest-risk source-to-sink route.
- Cost model: sum of edge weights.

2. BFS blast radius
- Purpose: reachable resources by hop depth.

3. DFS cycle detection
- Purpose: identify circular permission/trust chains.

4. Critical-node analysis
- Purpose: rank node removals by path disruption impact.

## Risk and Penalty Logic

- Wildcard RBAC (`resources: ["*"]` or `verbs: ["*"]`): `+5.0` edge penalty.
- Overly permissive service-account token behavior: `+2.0` Pod risk.
- Privileged container: `+4.0` Pod risk.
- Secret snooping (`get/list` with broad scope): `+3.0` Role->Secret edge penalty.

## Temporal Diff Model

- Each scan writes a snapshot for a scope id.
- Current scan is compared to previous scan in same scope.
- New source->sink reachability raises alerts.
- Rollback promotes historical snapshot as latest baseline.
- Rollback does not mutate live cluster resources.

## Project Structure

```text
tool/
  src/
    main.py                 # CLI entrypoint/orchestration
    ingestion/              # kubectl/mock parsing and normalization
    graph/                  # networkx storage and JSON replay/export
    analysis/               # BFS, Dijkstra, DFS, critical node
    reporting/              # CLI formatter and PDF generator
    api/                    # FastAPI routes/schemas
    services/               # contracts, NVD, temporal
  test/                     # unit and API tests
  out/                      # generated artifacts and snapshots
```
