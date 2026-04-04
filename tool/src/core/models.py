"""Core data models for the Kubernetes Attack Path Visualizer.

These models are intentionally framework-agnostic so they can be shared by
ingestion, graph, analysis, and reporting layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True, frozen=True)
class Node:
	"""Represents a single Kubernetes or security-relevant entity."""

	entity_type: str
	name: str
	namespace: str = "default"
	risk_score: float = 0.0
	is_source: bool = False
	is_sink: bool = False
	node_id: str = field(init=False)

	def __post_init__(self) -> None:
		if not self.entity_type.strip():
			raise ValueError("entity_type cannot be empty")
		if not self.name.strip():
			raise ValueError("name cannot be empty")
		if self.risk_score < 0:
			raise ValueError("risk_score must be >= 0")

		normalized_namespace = self.namespace.strip() or "default"
		object.__setattr__(self, "namespace", normalized_namespace)
		object.__setattr__(self, "node_id", f"{self.entity_type}:{self.namespace}:{self.name}")


@dataclass(slots=True, frozen=True)
class Edge:
	"""Represents a directional trust/permission relationship between nodes."""

	source_id: str
	target_id: str
	relationship_type: str
	weight: float = 1.0
	source_ref: str | None = None
	target_ref: str | None = None
	cve: str | None = None
	cvss: float | None = None
	escalation_type: str | None = None

	def __post_init__(self) -> None:
		if not self.source_id.strip():
			raise ValueError("source_id cannot be empty")
		if not self.target_id.strip():
			raise ValueError("target_id cannot be empty")
		if not self.relationship_type.strip():
			raise ValueError("relationship_type cannot be empty")
		if self.weight < 0:
			raise ValueError("weight must be >= 0")
		if self.cvss is not None:
			try:
				normalized_cvss = float(self.cvss)
			except (TypeError, ValueError) as exc:
				raise ValueError("cvss must be numeric") from exc
			if normalized_cvss < 0:
				raise ValueError("cvss must be >= 0")
			object.__setattr__(self, "cvss", normalized_cvss)

		if self.source_ref is not None:
			normalized_source_ref = self.source_ref.strip()
			object.__setattr__(self, "source_ref", normalized_source_ref or None)
		if self.target_ref is not None:
			normalized_target_ref = self.target_ref.strip()
			object.__setattr__(self, "target_ref", normalized_target_ref or None)
		if self.cve is not None:
			normalized_cve = self.cve.strip()
			object.__setattr__(self, "cve", normalized_cve or None)
		if self.escalation_type is not None:
			normalized_escalation = self.escalation_type.strip()
			object.__setattr__(self, "escalation_type", normalized_escalation or None)

	@property
	def source_node_id(self) -> str:
		"""Compatibility alias used by some modules/documentation."""
		return self.source_id

	@property
	def target_node_id(self) -> str:
		"""Compatibility alias used by some modules/documentation."""
		return self.target_id


@dataclass(slots=True)
class ClusterGraphData:
	"""Simple transport object carrying fully normalized graph entities."""

	nodes: list[Node] = field(default_factory=list)
	edges: list[Edge] = field(default_factory=list)

