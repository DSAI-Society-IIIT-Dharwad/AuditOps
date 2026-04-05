# Phase 6 Frontend Handoff

## 1) Problem Statement Context

Modern Kubernetes environments are made of many connected entities (Pods, ServiceAccounts, Roles, Secrets, ConfigMaps, Users). Security issues are rarely isolated to one resource; attackers usually move across multiple hops.

The backend in this project already models the cluster as a directed graph and computes key security results:

- blast radius (BFS)
- shortest attack path to crown jewels (Dijkstra)
- circular permission detection (DFS)
- critical node identification

The frontend goal is to visually represent this graph and these results so security teams can quickly understand attack paths and remediation priorities.

## 2) What We Are Doing In Phase 6

We are building a frontend that:

1. fetches graph-analysis JSON from backend
2. renders a directed graph visualization
3. overlays analysis outputs (attack path, blast radius, critical node, cycles)
4. provides interactive filtering and node details
5. gives an actionable view for remediation

## 3) Backend -> Frontend JSON Contract (v1)

The frontend should consume this response shape.

```json
{
  "schema_version": "1.0.0",
  "generated_at": "2026-04-04T14:23:11Z",
  "context": {
    "cluster": "kind-kubepath",
    "namespace": "vulnerable-ns",
    "directed": true
  },
  "summary": {
    "node_count": 4,
    "edge_count": 3,
    "source_count": 1,
    "sink_count": 1
  },
  "nodes": [
    {
      "id": "Pod:vulnerable-ns:frontend-webapp-vulnerable",
      "entity_type": "Pod",
      "name": "frontend-webapp-vulnerable",
      "namespace": "vulnerable-ns",
      "risk_score": 9.8,
      "is_source": true,
      "is_sink": false,
      "tags": ["public-entrypoint"]
    },
    {
      "id": "ServiceAccount:vulnerable-ns:overly-permissive-sa",
      "entity_type": "ServiceAccount",
      "name": "overly-permissive-sa",
      "namespace": "vulnerable-ns",
      "risk_score": 6.0,
      "is_source": false,
      "is_sink": false,
      "tags": []
    },
    {
      "id": "Role:vulnerable-ns:dangerous-secret-reader",
      "entity_type": "Role",
      "name": "dangerous-secret-reader",
      "namespace": "vulnerable-ns",
      "risk_score": 6.5,
      "is_source": false,
      "is_sink": false,
      "tags": ["rbac-high-risk"]
    },
    {
      "id": "Secret:vulnerable-ns:prod-db-credentials",
      "entity_type": "Secret",
      "name": "prod-db-credentials",
      "namespace": "vulnerable-ns",
      "risk_score": 9.0,
      "is_source": false,
      "is_sink": true,
      "tags": ["crown-jewel"]
    }
  ],
  "edges": [
    {
      "id": "e-1",
      "source": "Pod:vulnerable-ns:frontend-webapp-vulnerable",
      "target": "ServiceAccount:vulnerable-ns:overly-permissive-sa",
      "relationship_type": "uses",
      "weight": 2.0
    },
    {
      "id": "e-2",
      "source": "ServiceAccount:vulnerable-ns:overly-permissive-sa",
      "target": "Role:vulnerable-ns:dangerous-secret-reader",
      "relationship_type": "bound_to",
      "weight": 2.2
    },
    {
      "id": "e-3",
      "source": "Role:vulnerable-ns:dangerous-secret-reader",
      "target": "Secret:vulnerable-ns:prod-db-credentials",
      "relationship_type": "can_read",
      "weight": 1.8
    }
  ],
  "analysis": {
    "attack_path": {
      "source": "Pod:vulnerable-ns:frontend-webapp-vulnerable",
      "target": "Secret:vulnerable-ns:prod-db-credentials",
      "path_node_ids": [
        "Pod:vulnerable-ns:frontend-webapp-vulnerable",
        "ServiceAccount:vulnerable-ns:overly-permissive-sa",
        "Role:vulnerable-ns:dangerous-secret-reader",
        "Secret:vulnerable-ns:prod-db-credentials"
      ],
      "path_edge_ids": ["e-1", "e-2", "e-3"],
      "hops": 3,
      "risk_score": 27.5,
      "severity": "CRITICAL"
    },
    "blast_radius": {
      "source": "Pod:vulnerable-ns:frontend-webapp-vulnerable",
      "max_hops": 3,
      "reachable_node_ids": [
        "ServiceAccount:vulnerable-ns:overly-permissive-sa",
        "Role:vulnerable-ns:dangerous-secret-reader",
        "Secret:vulnerable-ns:prod-db-credentials"
      ],
      "hops_by_node": {
        "ServiceAccount:vulnerable-ns:overly-permissive-sa": 1,
        "Role:vulnerable-ns:dangerous-secret-reader": 2,
        "Secret:vulnerable-ns:prod-db-credentials": 3
      }
    },
    "cycles": {
      "count": 0,
      "items": []
    },
    "critical_node": {
      "node_id": "Role:vulnerable-ns:dangerous-secret-reader",
      "total_paths_before": 1,
      "total_paths_after": 0,
      "paths_removed": 1
    },
    "recommendations": [
      "Reduce privileges on the shortest attack path to increase traversal cost.",
      "Harden or remove Role:vulnerable-ns:dangerous-secret-reader to break 1 path(s)."
    ]
  }
}
```

## 4) Frontend Work To Be Built

### A) Data and API integration

1. Build API client for endpoint:
   - `GET /api/v1/graph-analysis?namespace=<ns>`
2. Validate `schema_version`.
3. Handle loading, error, empty states.

### B) Graph visualization

1. Render directed graph from `nodes` and `edges`.
2. Suggested library:
   - Cytoscape.js (preferred)
3. Node styling rules:
   - source nodes (`is_source=true`) highlighted as entry points
   - sink nodes (`is_sink=true`) highlighted as crown jewels
   - color scale by `risk_score`
4. Edge styling rules:
   - labels from `relationship_type`
   - thickness/intensity by `weight`

### C) Analysis overlays

1. Attack path overlay
   - highlight `analysis.attack_path.path_node_ids` and `path_edge_ids`
2. Blast radius overlay
   - highlight `analysis.blast_radius.reachable_node_ids`
3. Critical node overlay
   - emphasize `analysis.critical_node.node_id`
4. Cycle overlay
   - if any cycles, mark cycle nodes/edges from `analysis.cycles.items`

### D) UI panels and controls

1. Summary cards
   - node count, edge count, source count, sink count
2. Node details panel
   - show entity type, namespace, risk score, tags, inbound/outbound links
3. Filters
   - by namespace, entity type, risk score range
4. Toggle controls
   - show/hide attack path, blast radius, cycles, critical node

### E) UX and quality

1. Layout persistence (zoom/pan memory per session)
2. Responsive layout for desktop and laptop
3. Basic accessibility: keyboard focus and contrast
4. Test coverage:
   - parser tests for payload mapping
   - UI tests for overlay toggles and rendering states

## 5) Minimum Frontend Definition of Done

1. Graph renders successfully from backend payload.
2. Attack path and blast radius overlays are visible and toggleable.
3. Critical node is visually identifiable.
4. Summary and recommendation sections display analysis values.
5. Works for both vulnerable and secure namespace payloads.

## 6) Notes For Team Coordination

1. Backend guarantees unique IDs in `nodes[].id` and `edges[].id`.
2. Frontend should never derive IDs from names; always use provided IDs.
3. If `analysis.attack_path` is missing or empty, graph should still render.
4. Keep schema backward-compatible by checking `schema_version`.
