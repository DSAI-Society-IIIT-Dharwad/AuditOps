"""Live Kubernetes ingestion via kubectl subprocess calls."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.interfaces import DataIngestor
from core.models import ClusterGraphData, Edge, Node

if TYPE_CHECKING:
	from services.cve.nvd_scorer import NVDCveScorer


_RESOURCE_ORDER = (
	"pods",
	"serviceaccounts",
	"roles",
	"rolebindings",
	"clusterrolebindings",
	"secrets",
	"configmaps",
)

_CLUSTER_SCOPED_RESOURCES = {
	"clusterrolebindings",
}

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

_GOD_MODE_WILDCARD_EDGE_PENALTY = 5.0
_OVERLY_PERMISSIVE_TOKEN_NODE_PENALTY = 2.0
_PRIVILEGED_CONTAINER_NODE_PENALTY = 4.0
_SECRET_SNOOPING_EDGE_PENALTY = 3.0


@dataclass(slots=True, frozen=True)
class _PodRiskContext:
	"""Computed Pod risk score and optional NVD enrichment details."""

	score: float
	nvd_enriched: bool = False
	nvd_source: str | None = None
	nvd_max_cvss: float | None = None
	nvd_cve_ids: tuple[str, ...] = ()
	nvd_image_refs: tuple[str, ...] = ()


class KubectlIngestError(RuntimeError):
	"""Raised when live cluster data cannot be retrieved or parsed."""


def build_cluster_graph_data(
	kube_payload: Mapping[str, Any],
	*,
	namespace_scope: str | None = None,
	include_cluster_rbac: bool = True,
	cve_scorer: NVDCveScorer | None = None,
) -> ClusterGraphData:
	"""Normalize Kubernetes resource payloads into Node and Edge objects."""
	nodes_by_id: dict[str, Node] = {}
	edges: list[Edge] = []
	role_wildcard_penalty_by_id: dict[str, float] = {}

	def add_node(node: Node) -> None:
		nodes_by_id.setdefault(node.node_id, node)

	def add_edge(edge: Edge) -> None:
		edges.append(edge)

	for item in _safe_items(kube_payload.get("pods")):
		pod_name, namespace = _metadata_name_ns(item)
		risk_context = _build_pod_risk_context(item, cve_scorer=cve_scorer)
		pod = _make_node(
			"Pod",
			pod_name,
			namespace,
			risk_score=risk_context.score,
			is_source=_is_public_entrypoint(item),
			nvd_enriched=risk_context.nvd_enriched,
			nvd_source=risk_context.nvd_source,
			nvd_max_cvss=risk_context.nvd_max_cvss,
			nvd_cve_ids=risk_context.nvd_cve_ids,
			nvd_image_refs=risk_context.nvd_image_refs,
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

		rules = _safe_rules(item)
		if any(_rule_has_wildcard_resources_or_verbs(rule) for rule in rules):
			role_wildcard_penalty_by_id[role_node.node_id] = _GOD_MODE_WILDCARD_EDGE_PENALTY

		for rule in rules:
			if _rule_targets_resource(rule, "secrets"):
				edge_weight = 1.8
				if _rule_is_secret_snooping(rule):
					edge_weight += _SECRET_SNOOPING_EDGE_PENALTY

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
								weight=edge_weight,
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
									weight=edge_weight,
								)
							)

	for item in _safe_items(kube_payload.get("rolebindings")):
		binding_name, namespace = _metadata_name_ns(item)
		role_ref = item.get("roleRef", {})
		role_kind = str(role_ref.get("kind") or "Role")
		role_name = str(role_ref.get("name") or "unknown")
		role = _make_node(role_kind, role_name, namespace if role_kind == "Role" else "cluster")
		add_node(role)
		rbac_penalty = role_wildcard_penalty_by_id.get(role.node_id, 0.0)

		for subject in item.get("subjects", []) or []:
			subject_node = _subject_to_node(subject, fallback_namespace=namespace)
			add_node(subject_node)
			add_edge(
				Edge(
					source_id=subject_node.node_id,
					target_id=role.node_id,
					relationship_type="bound_to",
					weight=2.2 + rbac_penalty,
				)
			)

		binding_node = _make_node("RoleBinding", binding_name, namespace, risk_score=3.0)
		add_node(binding_node)
		add_edge(
			Edge(
				source_id=binding_node.node_id,
				target_id=role.node_id,
				relationship_type="grants",
				weight=1.0 + rbac_penalty,
			)
		)

	if include_cluster_rbac:
		for item in _iter_clusterrolebinding_items(kube_payload, namespace_scope):
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
		include_cluster_rbac: bool = True,
		cve_scorer: NVDCveScorer | None = None,
	) -> None:
		self._fallback_file = Path(fallback_file) if fallback_file else None
		self._namespace = namespace
		self._include_cluster_rbac = include_cluster_rbac
		self._cve_scorer = cve_scorer

	def source_name(self) -> str:
		return "kubectl"

	def ingest(self) -> ClusterGraphData:
		payload: dict[str, Any] = {}
		try:
			for resource in _RESOURCE_ORDER:
				if resource == "clusterrolebindings" and not self._include_cluster_rbac:
					payload[resource] = {"items": []}
					continue
				payload[resource] = self._run_kubectl_get(resource)
			return build_cluster_graph_data(
				payload,
				namespace_scope=self._namespace,
				include_cluster_rbac=self._include_cluster_rbac,
				cve_scorer=self._cve_scorer,
			)
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
			return build_cluster_graph_data(
				fallback_payload,
				namespace_scope=self._namespace,
				include_cluster_rbac=self._include_cluster_rbac,
				cve_scorer=self._cve_scorer,
			)

	def _run_kubectl_get(self, resource: str) -> dict[str, Any]:
		if resource in _CLUSTER_SCOPED_RESOURCES:
			cmd = ["kubectl", "get", resource, "-o", "json"]
		elif self._namespace:
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
	nvd_enriched: bool = False,
	nvd_source: str | None = None,
	nvd_max_cvss: float | None = None,
	nvd_cve_ids: tuple[str, ...] = (),
	nvd_image_refs: tuple[str, ...] = (),
) -> Node:
	base_risk = _BASE_RISK_BY_KIND.get(entity_type, 3.0)
	return Node(
		entity_type=entity_type,
		name=name,
		namespace=namespace,
		risk_score=base_risk if risk_score is None else risk_score,
		is_source=is_source,
		is_sink=is_sink,
		nvd_enriched=nvd_enriched,
		nvd_source=nvd_source,
		nvd_max_cvss=nvd_max_cvss,
		nvd_cve_ids=nvd_cve_ids,
		nvd_image_refs=nvd_image_refs,
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


def _iter_clusterrolebinding_items(kube_payload: Mapping[str, Any], namespace_scope: str | None) -> list[dict[str, Any]]:
	items = _safe_items(kube_payload.get("clusterrolebindings"))
	if namespace_scope is None:
		return items
	return [item for item in items if _clusterrolebinding_matches_namespace(item, namespace_scope)]


def _clusterrolebinding_matches_namespace(item: Mapping[str, Any], namespace_scope: str) -> bool:
	subjects = item.get("subjects", [])
	if not isinstance(subjects, list):
		return False

	for subject in subjects:
		if not isinstance(subject, Mapping):
			continue
		if str(subject.get("kind") or "") != "ServiceAccount":
			continue
		subject_namespace = str(subject.get("namespace") or "")
		if subject_namespace == namespace_scope:
			return True

	return False


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


def _pod_risk_score(pod: Mapping[str, Any], cve_scorer: NVDCveScorer | None = None) -> float:
	return _build_pod_risk_context(pod, cve_scorer=cve_scorer).score


def _build_pod_risk_context(pod: Mapping[str, Any], cve_scorer: NVDCveScorer | None = None) -> _PodRiskContext:
	base = _BASE_RISK_BY_KIND.get("Pod", 5.0)
	annotation_bonus, annotation_cve_ids, annotation_cvss = _pod_annotation_enrichment(pod)
	container_images = _pod_container_images(pod)
	cve_bonus = 0.0
	nvd_source: str | None = None
	nvd_max_cvss: float | None = None
	nvd_cve_ids: tuple[str, ...] = ()
	nvd_image_refs: tuple[str, ...] = ()
	nvd_enriched = False

	if annotation_bonus > 0.0:
		nvd_source = "annotation"
		nvd_cve_ids = annotation_cve_ids
		nvd_max_cvss = annotation_cvss
		nvd_image_refs = container_images
		nvd_enriched = True
	elif cve_scorer is not None:
		lookup_max_cvss, lookup_cve_ids, lookup_image_refs = _pod_cve_lookup_enrichment(pod, cve_scorer)
		cve_bonus = lookup_max_cvss
		if lookup_max_cvss > 0.0 or lookup_cve_ids:
			nvd_source = "nvd"
			nvd_max_cvss = lookup_max_cvss if lookup_max_cvss > 0.0 else None
			nvd_cve_ids = lookup_cve_ids
			nvd_image_refs = lookup_image_refs
			nvd_enriched = True

	score = (
		base
		+ annotation_bonus
		+ cve_bonus
		+ _pod_automount_token_risk_bonus(pod)
		+ _pod_privileged_container_risk_bonus(pod)
	)

	return _PodRiskContext(
		score=score,
		nvd_enriched=nvd_enriched,
		nvd_source=nvd_source,
		nvd_max_cvss=nvd_max_cvss,
		nvd_cve_ids=nvd_cve_ids,
		nvd_image_refs=nvd_image_refs,
	)


def _pod_cve_lookup_risk_bonus(pod: Mapping[str, Any], cve_scorer: NVDCveScorer) -> float:
	max_cvss, _, _ = _pod_cve_lookup_enrichment(pod, cve_scorer)
	return max_cvss


def _pod_cve_lookup_enrichment(
	pod: Mapping[str, Any], cve_scorer: NVDCveScorer
) -> tuple[float, tuple[str, ...], tuple[str, ...]]:
	spec = pod.get("spec", {})
	if not isinstance(spec, Mapping):
		return 0.0, (), ()

	max_cvss = 0.0
	cve_ids: set[str] = set()
	vulnerable_images: list[str] = []

	for image_ref in _pod_container_images(pod):
		try:
			result = cve_scorer.score_image(image_ref)
		except Exception:
			continue

		try:
			result_max_cvss = float(getattr(result, "max_cvss", 0.0) or 0.0)
		except (TypeError, ValueError):
			result_max_cvss = 0.0

		if result_max_cvss > max_cvss:
			max_cvss = result_max_cvss

		image_has_findings = result_max_cvss > 0.0
		result_cve_ids = getattr(result, "cve_ids", ())
		if isinstance(result_cve_ids, (tuple, list, set)):
			for cve_id in result_cve_ids:
				normalized_cve = str(cve_id).strip()
				if normalized_cve:
					cve_ids.add(normalized_cve)
					image_has_findings = True

		if image_has_findings:
			vulnerable_images.append(image_ref)

	return max_cvss, tuple(sorted(cve_ids)), tuple(dict.fromkeys(vulnerable_images))


def _pod_container_images(pod: Mapping[str, Any]) -> tuple[str, ...]:
	spec = pod.get("spec", {})
	if not isinstance(spec, Mapping):
		return ()

	image_refs: list[str] = []
	for container in _all_containers(spec):
		image_ref = container.get("image")
		if image_ref is None:
			continue
		normalized_image = str(image_ref).strip()
		if normalized_image:
			image_refs.append(normalized_image)

	return tuple(dict.fromkeys(image_refs))


def _pod_annotation_enrichment(pod: Mapping[str, Any]) -> tuple[float, tuple[str, ...], float | None]:
	metadata = pod.get("metadata", {})
	annotations = metadata.get("annotations", {})
	if not isinstance(annotations, Mapping):
		return 0.0, (), None

	for key in ("security.analysis/cvss", "security.hack2future.io/cvss", "cvss"):
		if key not in annotations:
			continue
		parsed = _as_non_negative_float(annotations.get(key))
		if parsed is not None:
			return parsed, _annotation_cve_ids(annotations), parsed

	cve_ids = _annotation_cve_ids(annotations)
	if cve_ids:
		# CVE id exists but no numeric CVSS score was provided.
		return 2.0, cve_ids, None

	return 0.0, (), None


def _annotation_cve_ids(annotations: Mapping[str, Any]) -> tuple[str, ...]:
	for key in ("security.analysis/cve", "security.hack2future.io/cve", "cve"):
		value = annotations.get(key)
		if value is None:
			continue
		raw = str(value).strip()
		if not raw:
			continue
		tokens = [token.strip() for token in raw.replace(";", ",").split(",")]
		normalized = tuple(sorted({token for token in tokens if token}))
		if normalized:
			return normalized
		return (raw,)
	return ()


def _pod_annotation_risk_bonus(pod: Mapping[str, Any]) -> float:
	bonus, _, _ = _pod_annotation_enrichment(pod)
	return bonus


def _pod_automount_token_risk_bonus(pod: Mapping[str, Any]) -> float:
	spec = pod.get("spec", {})
	if not isinstance(spec, Mapping):
		return _OVERLY_PERMISSIVE_TOKEN_NODE_PENALTY

	automount = spec.get("automountServiceAccountToken")
	if automount is None:
		return _OVERLY_PERMISSIVE_TOKEN_NODE_PENALTY
	if _is_truthy(automount):
		return _OVERLY_PERMISSIVE_TOKEN_NODE_PENALTY
	return 0.0


def _pod_privileged_container_risk_bonus(pod: Mapping[str, Any]) -> float:
	spec = pod.get("spec", {})
	if not isinstance(spec, Mapping):
		return 0.0

	for container in _all_containers(spec):
		security_context = container.get("securityContext", {})
		if isinstance(security_context, Mapping) and _is_truthy(security_context.get("privileged")):
			return _PRIVILEGED_CONTAINER_NODE_PENALTY

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


def _is_truthy(value: Any) -> bool:
	if isinstance(value, bool):
		return value
	if isinstance(value, str):
		return value.strip().lower() in {"true", "1", "yes", "on"}
	if isinstance(value, (int, float)):
		return value != 0
	return False


def _dedupe_edges(edges: list[Edge]) -> list[Edge]:
	unique: dict[tuple[str, str, str], Edge] = {}
	for edge in edges:
		key = (edge.source_id, edge.target_id, edge.relationship_type)
		existing = unique.get(key)
		if existing is None or edge.weight > existing.weight:
			unique[key] = edge
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


def _rule_has_wildcard_resources_or_verbs(rule: Mapping[str, Any]) -> bool:
	resources = rule.get("resources", [])
	verbs = rule.get("verbs", [])
	resource_set = {str(resource).lower() for resource in resources} if isinstance(resources, list) else set()
	verb_set = {str(verb).lower() for verb in verbs} if isinstance(verbs, list) else set()
	return "*" in resource_set or "*" in verb_set


def _rule_is_secret_snooping(rule: Mapping[str, Any]) -> bool:
	if not _rule_targets_resource(rule, "secrets"):
		return False
	verbs = rule.get("verbs", [])
	if not isinstance(verbs, list):
		return False
	verb_set = {str(verb).lower() for verb in verbs}
	if not ({"get", "list", "*"} & verb_set):
		return False
	resource_names = rule.get("resourceNames")
	return not (isinstance(resource_names, list) and len(resource_names) > 0)

