"""Live Kubernetes ingestion via kubectl subprocess calls."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from core.interfaces import DataIngestor
from core.models import ClusterGraphData, Edge, Node


_RESOURCE_ORDER = (
	"pods",
	"serviceaccounts",
	"roles",
	"rolebindings",
	"clusterrolebindings",
	"secrets",
	"configmaps",
)

_BASE_RISK_BY_KIND: dict[str, float] = {
	"Pod": 5.0,
	"ServiceAccount": 6.0,
	"Role": 6.5,
	"ClusterRole": 8.0,
	"Secret": 9.0,
	"ConfigMap": 4.0,
	"User": 5.0,
	"Group": 4.0,
}


class KubectlIngestError(RuntimeError):
	"""Raised when live cluster data cannot be retrieved or parsed."""


def build_cluster_graph_data(kube_payload: Mapping[str, Any]) -> ClusterGraphData:
	"""Normalize Kubernetes resource payloads into Node and Edge objects."""
	nodes_by_id: dict[str, Node] = {}
	edges: list[Edge] = []

	def add_node(node: Node) -> None:
		nodes_by_id.setdefault(node.node_id, node)

	def add_edge(edge: Edge) -> None:
		edges.append(edge)

	for item in _safe_items(kube_payload.get("pods")):
		pod_name, namespace = _metadata_name_ns(item)
		pod = _make_node(
			"Pod",
			pod_name,
			namespace,
			risk_score=_pod_risk_score(item),
			is_source=_is_public_entrypoint(item),
		)
		add_node(pod)

		sa_name = item.get("spec", {}).get("serviceAccountName") or "default"
		sa = _make_node("ServiceAccount", str(sa_name), namespace)
		add_node(sa)
		add_edge(Edge(source_id=pod.node_id, target_id=sa.node_id, relationship_type="uses", weight=2.0))

		for secret_name in _pod_secret_refs(item):
			secret = _make_node("Secret", secret_name, namespace)
			add_node(secret)
			add_edge(
				Edge(
					source_id=pod.node_id,
					target_id=secret.node_id,
					relationship_type="can_read",
					weight=3.0,
				)
			)

		for config_name in _pod_configmap_refs(item):
			config = _make_node("ConfigMap", config_name, namespace)
			add_node(config)
			add_edge(
				Edge(
					source_id=pod.node_id,
					target_id=config.node_id,
					relationship_type="can_read",
					weight=1.5,
				)
			)

	for item in _safe_items(kube_payload.get("serviceaccounts")):
		name, namespace = _metadata_name_ns(item)
		add_node(_make_node("ServiceAccount", name, namespace))

	for item in _safe_items(kube_payload.get("secrets")):
		name, namespace = _metadata_name_ns(item)
		add_node(_make_node("Secret", name, namespace, is_sink=_is_crown_jewel(item)))

	for item in _safe_items(kube_payload.get("configmaps")):
		name, namespace = _metadata_name_ns(item)
		add_node(_make_node("ConfigMap", name, namespace, is_sink=_is_crown_jewel(item)))

	for item in _safe_items(kube_payload.get("roles")):
		role_name, namespace = _metadata_name_ns(item)
		role_node = _make_node("Role", role_name, namespace)
		add_node(role_node)

		for rule in _safe_rules(item):
			if _rule_targets_resource(rule, "secrets"):
				resource_names = rule.get("resourceNames", [])
				if isinstance(resource_names, list) and resource_names:
					for secret_name in resource_names:
						secret_node = _make_node("Secret", str(secret_name), namespace)
						add_node(secret_node)
						add_edge(
							Edge(
								source_id=role_node.node_id,
								target_id=secret_node.node_id,
								relationship_type="can_read",
								weight=1.8,
							)
						)
				else:
					for existing_node in list(nodes_by_id.values()):
						if existing_node.entity_type == "Secret" and existing_node.namespace == namespace:
							add_edge(
								Edge(
									source_id=role_node.node_id,
									target_id=existing_node.node_id,
									relationship_type="can_read",
									weight=1.8,
								)
							)

	for item in _safe_items(kube_payload.get("rolebindings")):
		binding_name, namespace = _metadata_name_ns(item)
		role_ref = item.get("roleRef", {})
		role_kind = str(role_ref.get("kind") or "Role")
		role_name = str(role_ref.get("name") or "unknown")
		role = _make_node(role_kind, role_name, namespace if role_kind == "Role" else "cluster")
		add_node(role)

		for subject in item.get("subjects", []) or []:
			subject_node = _subject_to_node(subject, fallback_namespace=namespace)
			add_node(subject_node)
			add_edge(
				Edge(
					source_id=subject_node.node_id,
					target_id=role.node_id,
					relationship_type="bound_to",
					weight=2.2,
				)
			)

		binding_node = _make_node("RoleBinding", binding_name, namespace, risk_score=3.0)
		add_node(binding_node)
		add_edge(
			Edge(
				source_id=binding_node.node_id,
				target_id=role.node_id,
				relationship_type="grants",
				weight=1.0,
			)
		)

	for item in _safe_items(kube_payload.get("clusterrolebindings")):
		binding_name, _ = _metadata_name_ns(item)
		role_ref = item.get("roleRef", {})
		role_name = str(role_ref.get("name") or "unknown")
		role = _make_node("ClusterRole", role_name, "cluster")
		add_node(role)

		for subject in item.get("subjects", []) or []:
			subject_node = _subject_to_node(subject, fallback_namespace="default")
			add_node(subject_node)
			add_edge(
				Edge(
					source_id=subject_node.node_id,
					target_id=role.node_id,
					relationship_type="bound_to",
					weight=2.6,
				)
			)

		binding_node = _make_node("ClusterRoleBinding", binding_name, "cluster", risk_score=4.0)
		add_node(binding_node)
		add_edge(
			Edge(
				source_id=binding_node.node_id,
				target_id=role.node_id,
				relationship_type="grants",
				weight=1.0,
			)
		)

	return ClusterGraphData(nodes=list(nodes_by_id.values()), edges=_dedupe_edges(edges))


class KubectlDataIngestor(DataIngestor):
	"""Fetches Kubernetes resources using kubectl and normalizes into graph data."""

	def __init__(
		self,
		fallback_file: str | Path | None = None,
		*,
		namespace: str | None = None,
	) -> None:
		self._fallback_file = Path(fallback_file) if fallback_file else None
		self._namespace = namespace

	def source_name(self) -> str:
		return "kubectl"

	def ingest(self) -> ClusterGraphData:
		payload: dict[str, Any] = {}
		try:
			for resource in _RESOURCE_ORDER:
				payload[resource] = self._run_kubectl_get(resource)
			return build_cluster_graph_data(payload)
		except KubectlIngestError:
			if self._fallback_file is None:
				raise
			if not self._fallback_file.exists():
				raise KubectlIngestError(
					f"kubectl failed and fallback file was not found: {self._fallback_file}"
				) from None
			with self._fallback_file.open("r", encoding="utf-8") as fp:
				fallback_payload = json.load(fp)
			if not isinstance(fallback_payload, Mapping):
				raise KubectlIngestError("fallback JSON must be an object at top-level")
			return build_cluster_graph_data(fallback_payload)

	def _run_kubectl_get(self, resource: str) -> dict[str, Any]:
		if self._namespace:
			cmd = ["kubectl", "get", resource, "-n", self._namespace, "-o", "json"]
		else:
			cmd = ["kubectl", "get", resource, "-A", "-o", "json"]
		try:
			result = subprocess.run(cmd, check=True, text=True, capture_output=True)
		except FileNotFoundError as exc:
			raise KubectlIngestError("kubectl is not installed or not in PATH") from exc
		except subprocess.CalledProcessError as exc:
			stderr = exc.stderr.strip() if exc.stderr else ""
			raise KubectlIngestError(f"kubectl get {resource} failed: {stderr}") from exc

		try:
			parsed: Any = json.loads(result.stdout)
		except json.JSONDecodeError as exc:
			raise KubectlIngestError(f"kubectl returned invalid JSON for {resource}") from exc

		if not isinstance(parsed, dict):
			raise KubectlIngestError(f"kubectl payload for {resource} is not a JSON object")
		return parsed


def _make_node(
	entity_type: str,
	name: str,
	namespace: str,
	*,
	risk_score: float | None = None,
	is_source: bool = False,
	is_sink: bool = False,
) -> Node:
	base_risk = _BASE_RISK_BY_KIND.get(entity_type, 3.0)
	return Node(
		entity_type=entity_type,
		name=name,
		namespace=namespace,
		risk_score=base_risk if risk_score is None else risk_score,
		is_source=is_source,
		is_sink=is_sink,
	)


def _subject_to_node(subject: Mapping[str, Any], fallback_namespace: str) -> Node:
	kind = str(subject.get("kind") or "User")
	name = str(subject.get("name") or "unknown")
	if kind == "ServiceAccount":
		namespace = str(subject.get("namespace") or fallback_namespace)
	else:
		namespace = "cluster"
	return _make_node(kind, name, namespace)


def _metadata_name_ns(item: Mapping[str, Any]) -> tuple[str, str]:
	metadata = item.get("metadata", {}) if isinstance(item, Mapping) else {}
	name = str(metadata.get("name") or "unknown")
	namespace = str(metadata.get("namespace") or "default")
	return name, namespace


def _safe_items(payload: Any) -> list[dict[str, Any]]:
	if not isinstance(payload, Mapping):
		return []
	items = payload.get("items", [])
	if not isinstance(items, list):
		return []
	return [x for x in items if isinstance(x, dict)]


def _is_public_entrypoint(pod: Mapping[str, Any]) -> bool:
	labels = pod.get("metadata", {}).get("labels", {})
	if isinstance(labels, Mapping):
		if str(labels.get("public", "")).lower() in {"true", "1", "yes"}:
			return True
		if str(labels.get("internet-facing", "")).lower() in {"true", "1", "yes"}:
			return True
	annotations = pod.get("metadata", {}).get("annotations", {})
	if isinstance(annotations, Mapping):
		if str(annotations.get("security.hack2future.io/source", "")).lower() in {"true", "1", "yes"}:
			return True
	return False


def _is_crown_jewel(resource: Mapping[str, Any]) -> bool:
	metadata = resource.get("metadata", {})
	labels = metadata.get("labels", {})
	annotations = metadata.get("annotations", {})

	if isinstance(labels, Mapping):
		if str(labels.get("crown-jewel", "")).lower() in {"true", "1", "yes"}:
			return True
		if str(labels.get("sensitivity", "")).lower() in {"critical", "high"}:
			return True

	if isinstance(annotations, Mapping):
		if str(annotations.get("security.hack2future.io/sink", "")).lower() in {"true", "1", "yes"}:
			return True

	return False


def _pod_risk_score(pod: Mapping[str, Any]) -> float:
	base = _BASE_RISK_BY_KIND.get("Pod", 5.0)
	return base + _pod_annotation_risk_bonus(pod)


def _pod_annotation_risk_bonus(pod: Mapping[str, Any]) -> float:
	metadata = pod.get("metadata", {})
	annotations = metadata.get("annotations", {})
	if not isinstance(annotations, Mapping):
		return 0.0

	for key in ("security.analysis/cvss", "security.hack2future.io/cvss", "cvss"):
		if key not in annotations:
			continue
		parsed = _as_non_negative_float(annotations.get(key))
		if parsed is not None:
			return parsed

	for key in ("security.analysis/cve", "security.hack2future.io/cve", "cve"):
		value = annotations.get(key)
		if value is not None and str(value).strip():
			# CVE id exists but no numeric CVSS score was provided.
			return 2.0

	return 0.0


def _as_non_negative_float(value: Any) -> float | None:
	try:
		parsed = float(value)
	except (TypeError, ValueError):
		return None
	return parsed if parsed >= 0 else None


def _pod_secret_refs(pod: Mapping[str, Any]) -> set[str]:
	names: set[str] = set()
	spec = pod.get("spec", {})
	for volume in spec.get("volumes", []) or []:
		if isinstance(volume, Mapping):
			secret = volume.get("secret", {})
			if isinstance(secret, Mapping):
				name = secret.get("secretName")
				if name:
					names.add(str(name))
	for container in _all_containers(spec):
		for env_from in container.get("envFrom", []) or []:
			if isinstance(env_from, Mapping):
				secret_ref = env_from.get("secretRef", {})
				if isinstance(secret_ref, Mapping) and secret_ref.get("name"):
					names.add(str(secret_ref["name"]))
		for env in container.get("env", []) or []:
			if isinstance(env, Mapping):
				value_from = env.get("valueFrom", {})
				if isinstance(value_from, Mapping):
					secret_key_ref = value_from.get("secretKeyRef", {})
					if isinstance(secret_key_ref, Mapping) and secret_key_ref.get("name"):
						names.add(str(secret_key_ref["name"]))
	return names


def _pod_configmap_refs(pod: Mapping[str, Any]) -> set[str]:
	names: set[str] = set()
	spec = pod.get("spec", {})
	for volume in spec.get("volumes", []) or []:
		if isinstance(volume, Mapping):
			cm = volume.get("configMap", {})
			if isinstance(cm, Mapping) and cm.get("name"):
				names.add(str(cm["name"]))
	for container in _all_containers(spec):
		for env_from in container.get("envFrom", []) or []:
			if isinstance(env_from, Mapping):
				cm_ref = env_from.get("configMapRef", {})
				if isinstance(cm_ref, Mapping) and cm_ref.get("name"):
					names.add(str(cm_ref["name"]))
		for env in container.get("env", []) or []:
			if isinstance(env, Mapping):
				value_from = env.get("valueFrom", {})
				if isinstance(value_from, Mapping):
					cm_key_ref = value_from.get("configMapKeyRef", {})
					if isinstance(cm_key_ref, Mapping) and cm_key_ref.get("name"):
						names.add(str(cm_key_ref["name"]))
	return names


def _all_containers(spec: Mapping[str, Any]) -> list[dict[str, Any]]:
	containers = []
	for key in ("containers", "initContainers"):
		group = spec.get(key, [])
		if isinstance(group, list):
			containers.extend([x for x in group if isinstance(x, dict)])
	return containers


def _dedupe_edges(edges: list[Edge]) -> list[Edge]:
	unique: dict[tuple[str, str, str], Edge] = {}
	for edge in edges:
		unique[(edge.source_id, edge.target_id, edge.relationship_type)] = edge
	return list(unique.values())


def _safe_rules(item: Mapping[str, Any]) -> list[dict[str, Any]]:
	rules = item.get("rules", [])
	if not isinstance(rules, list):
		return []
	return [rule for rule in rules if isinstance(rule, dict)]


def _rule_targets_resource(rule: Mapping[str, Any], resource_name: str) -> bool:
	resources = rule.get("resources", [])
	if not isinstance(resources, list):
		return False
	resource_set = {str(resource).lower() for resource in resources}
	return resource_name.lower() in resource_set or "*" in resource_set

