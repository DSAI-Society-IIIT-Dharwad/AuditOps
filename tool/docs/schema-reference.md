# Schema Reference

This schema describes the normalized graph artifact exported by the backend.

## Top-Level Shape

```json
{
  "schema_version": "1.0.0",
  "nodes": [],
  "edges": []
}
```

## Node Fields

Required:

- `node_id` (`Type:Namespace:Name`)
- `entity_type`
- `name`
- `namespace`
- `risk_score`
- `is_source`
- `is_sink`

Optional:

- `cves` (compatibility alias for `nvd_cve_ids`)
- `nvd_enriched`
- `nvd_source`
- `nvd_max_cvss`
- `nvd_cve_ids`
- `nvd_image_refs`

## Edge Fields

Required:

- `source_id`
- `target_id`
- `relationship_type`
- `weight`

Optional:

- `cve`
- `cvss`
- `source_ref`
- `target_ref`
- `escalation_type`

## Import Compatibility Aliases

Source id aliases:

- `source_id`
- `source_node_id`
- `sourceNodeId`
- `source`

Target id aliases:

- `target_id`
- `target_node_id`
- `targetNodeId`
- `target`

Relationship aliases:

- `relationship_type`
- `relationshipType`
- `relationship`

## Weight Semantics

- `weight` is non-negative traversal cost.
- Dijkstra minimizes total path cost.
- Reported attack-path risk score is the sum of edge weights.

## Source and Sink Semantics

- `is_source = true`: candidate attack entrypoints.
- `is_sink = true`: crown-jewel targets.

## Example Node

```json
{
  "node_id": "Pod:default:web-frontend",
  "entity_type": "Pod",
  "name": "web-frontend",
  "namespace": "default",
  "risk_score": 14.7,
  "is_source": true,
  "is_sink": false,
  "nvd_enriched": true,
  "nvd_source": "nvd",
  "nvd_max_cvss": 7.7,
  "nvd_cve_ids": ["CVE-2019-20372"],
  "cves": ["CVE-2019-20372"],
  "nvd_image_refs": ["nginx:1.19.1"]
}
```

## Example Edge

```json
{
  "source_id": "ServiceAccount:default:sa-webapp",
  "target_id": "Role:default:secret-reader",
  "relationship_type": "bound_to",
  "weight": 4.0,
  "source_ref": "sa-webapp",
  "target_ref": "role-secret-reader"
}
```
