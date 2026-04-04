# Phase 6 Implementation Plan (Output Parity Track)

Last updated: 2026-04-04

## Completed

1. Mock schema compatibility in ingestion
- Accept node aliases: id, node_id, nodeId.
- Accept node type aliases: entity_type, entityType, type.
- Accept edge aliases: source/source_id/source_node_id/sourceNodeId, target variants, relationship variants.
- Skip comment-only edge rows.
- Resolve alias edge references to canonical node IDs.

2. Edge metadata transport
- Extended edge model with optional source_ref, target_ref, cve, cvss, escalation_type.
- Preserved metadata in JSON export and import paths.

3. Regression coverage and validation
- Added parser tests for alias-schema payloads and metadata mapping.
- Updated graph export/import tests for alias IDs and metadata round-trip.
- Updated main export test for edge metadata output.
- Full backend suite is green: 56/56 tests.

4. Multi-path and reporting pipeline implementation
- Added full simple-path enumeration for baseline critical-node analysis.
- Added shortest-path-per-source/sink enumeration for sectioned attack-path output.
- Added multi-source blast-radius aggregation with hop buckets.
- Added structured sectioned CLI formatter with metadata, attack-path index, blast radius, cycles, critical-node ranking, and summary sections.
- Added mock metadata extraction for cluster header.

## In Progress

5. Sample parity polish
- Completed: CLI output now matches `tests/sample-output.txt` with zero diff when generated from `tests/mock-cluster-graph.json`.
- Completed: parity styling and ordering alignment (glyphs, spacing, symbols, section text, source/hop ordering, recommendation formatting).

## Next

6. Critical-node and contract alignment
- Compute baseline and top-N node removals for report section.
- Align API/report contracts and add golden-output checks against sample markers.

7. Parity lock tests
- Add golden-file style assertions (or marker-based snapshot checks) for sample-output compatibility.
