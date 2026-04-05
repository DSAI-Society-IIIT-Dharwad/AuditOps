# Pages and Features

## Routes

- `/graph` - graph exploration and analysis controls
- `/ingest` - upload/paste YAML or JSON and run analysis
- `/risks` - risk-centric summaries and rankings
- `/snapshots` - snapshot list, detail, and rollback

## Core UI Features

- Graph visualization with overlays for:
  - attack paths
  - blast radius
  - critical node context
- Sectioned analysis report panel.
- Temporal alert context from snapshot diffing.
- Snapshot rollback flow (baseline promotion).

## Recently Added UX Features

- Persisted analysis preferences (namespace, RBAC/NVD toggles, hops/depth, overlay toggles).
- Graph-page quick actions:
  - auto-refresh interval selector
  - download analysis JSON
  - copy PPT-ready risk brief
- Risks-page controls:
  - severity filter
  - path and critical-node search
  - CSV export for visible risk paths
- Attack-path sorting in report widget:
  - default
  - risk high->low and low->high
  - hops high->low and low->high
