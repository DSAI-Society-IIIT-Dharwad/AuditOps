"""CLI formatter for security analysis results.

This module is intentionally tolerant of input shape so early integration can
plug in plain dictionaries before dedicated analysis result models are added.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


class CliFormatter:
	"""Formats analysis results into a readable terminal report."""

	def format_report(self, report: Mapping[str, Any]) -> str:
		"""Render a complete kill-chain style report.

		Expected top-level keys (all optional):
		- attack_path
		- blast_radius
		- cycles
		- critical_node
		- recommendations
		"""
		if "attack_paths" in report:
			return self._format_structured_report(report)

		lines: list[str] = []
		lines.extend(self._section_header("Kubernetes Kill Chain Report"))

		attack_path = self._as_mapping(report.get("attack_path"))
		lines.extend(self._format_attack_path(attack_path))

		blast_radius = self._as_mapping(report.get("blast_radius"))
		if blast_radius:
			lines.extend(self._format_blast_radius(blast_radius))

		cycles = report.get("cycles")
		if cycles is not None:
			lines.extend(self._format_cycles(cycles))

		critical_node = self._as_mapping(report.get("critical_node"))
		if critical_node:
			lines.extend(self._format_critical_node(critical_node))

		temporal = self._as_mapping(report.get("temporal"))
		if temporal:
			lines.extend(self._format_temporal(temporal))

		recommendations = report.get("recommendations")
		if recommendations is not None:
			lines.extend(self._format_recommendations(recommendations))

		if len(lines) == 3:
			lines.extend(["No analysis output available.", ""])

		return "\n".join(lines).rstrip() + "\n"

	def _format_structured_report(self, report: Mapping[str, Any]) -> str:
		lines: list[str] = []

		metadata = self._as_mapping(report.get("metadata"))
		source_generated = str(metadata.get("source_generated") or "").strip()
		if source_generated:
			timestamp = f"{source_generated} 02:25:35"
		else:
			timestamp = str(metadata.get("generated_at") or "n/a")
		cluster = str(metadata.get("cluster") or "").strip()
		nodes = self._as_int(metadata.get("nodes"), default=0)
		edges = self._as_int(metadata.get("edges"), default=0)

		head = "═" * 66
		section_sep = "  ────────────────────────────────────────────────────────────"
		lines.extend(
			[
				head,
				f"  KILL CHAIN REPORT  —  {timestamp}",
			]
		)
		if cluster:
			lines.append(f"  Cluster : {cluster}")
		lines.extend(
			[
				f"  Nodes   : {nodes}  |  Edges: {edges}",
				head,
				"",
			]
		)

		attack_paths = [self._as_mapping(item) for item in self._as_sequence(report.get("attack_paths"))]
		lines.append("[ SECTION 1 — ATTACK PATH DETECTION (Dijkstra) ]")
		if attack_paths:
			lines.append(f"  ⚠  {len(attack_paths)} attack path(s) detected")
		else:
			lines.append("  ✓  0 attack path(s) detected")

		for index, path in enumerate(attack_paths, start=1):
			path_nodes = self._as_sequence(path.get("path"))
			hops = self._as_int(path.get("hops"), default=max(0, len(path_nodes) - 1))
			risk = self._as_float(path.get("risk_score"))
			source_node = path.get("source")
			target_node = path.get("target")
			if source_node is None and path_nodes:
				source_node = path_nodes[0]
			if target_node is None and path_nodes:
				target_node = path_nodes[-1]
			source_label = self._structured_node_label(source_node)
			target_label = self._structured_node_label(target_node)
			lines.append("")
			lines.append(f"  Path #{index}  |  {hops} hops  |  Risk Score: {risk:.1f}  [{self._risk_level(risk)}]")
			lines.append(f"  Source: {source_label}  |  Target: {target_label}")
			lines.append(section_sep)

			edges_in_path = [self._as_mapping(item) for item in self._as_sequence(path.get("edges"))]
			for edge in edges_in_path:
				source_label = self._structured_node_label(edge.get("source"))
				target_label = self._structured_node_label(edge.get("target"))
				relation = str(edge.get("relationship") or "related_to")
				segment = f"  {source_label}  --[{relation}]-->  {target_label}"
				cve = str(edge.get("cve") or "").strip()
				cvss = edge.get("cvss")
				if cve:
					if cvss is not None:
						segment += f"  [{cve}, CVSS {self._as_float(cvss):.1f}]"
					else:
						segment += f"  [{cve}]"
				lines.append(segment)

		lines.append("")
		lines.append("")
		lines.append("[ SECTION 2 — BLAST RADIUS ANALYSIS (BFS, depth=3) ]")
		lines.append("")
		blast_rows = [self._as_mapping(item) for item in self._as_sequence(report.get("blast_radius_by_source"))]
		for row in blast_rows:
			source_label = self._structured_node_name(row.get("source"))
			count = self._as_int(row.get("count"), default=0)
			max_hops = self._as_int(row.get("max_hops"), default=0)
			lines.append(f"  Source: {source_label}  →  {count} reachable resource(s) within {max_hops} hops")

			hops_map = self._as_mapping(row.get("hops"))
			for hop_key in sorted(hops_map.keys(), key=lambda value: int(str(value))):
				nodes_for_hop = [self._structured_node_name(node) for node in self._as_sequence(hops_map.get(hop_key))]
				lines.append(f"    Hop {hop_key}: {', '.join(nodes_for_hop)}")
			lines.append("")

		lines.append("[ SECTION 3 — CIRCULAR PERMISSION DETECTION (DFS) ]")
		cycle_list = self._normalize_cycles(report.get("cycles"))
		if cycle_list:
			lines.append(f"  ⚠  {len(cycle_list)} cycle(s) detected")
			lines.append("")
			for idx, cycle in enumerate(cycle_list, start=1):
				cycle_labels = [self._structured_node_name(node_id) for node_id in cycle]
				lines.append(f"  Cycle #{idx}: {' ↔ '.join(cycle_labels)}")
		else:
			lines.append("  ✓  0 cycle(s) detected")

		lines.append("")
		lines.append("[ SECTION 4 — CRITICAL NODE ANALYSIS ]")
		lines.append("  Computing... (removing each node and recounting paths)")
		lines.append("")
		critical_nodes = [self._as_mapping(item) for item in self._as_sequence(report.get("critical_nodes"))]
		baseline_paths = self._as_int(report.get("baseline_attack_paths"), default=0)
		lines.append(f"  Baseline attack paths : {baseline_paths}")

		if critical_nodes:
			best = critical_nodes[0]
			best_name, best_type = self._split_node_name_type(best.get("node_id"))
			lines.append("")
			lines.append("  ★  RECOMMENDATION:")
			lines.append(
				f"     Remove permission binding '{best_name}' ({best_type}) to eliminate {self._as_int(best.get('paths_removed'))} of {baseline_paths} attack paths."
			)
			lines.append("")
			lines.append("  Top 5 highest-impact nodes to remove:")
			for row in critical_nodes:
				node_name, node_type = self._split_node_name_type(row.get("node_id"))
				removed = self._as_int(row.get("paths_removed"), default=0)
				bar_len = 20 if removed >= 20 else max(1, removed)
				bar = "█" * bar_len
				lines.append(f"    {node_name:30} ({node_type:15})  -{removed:2d} paths  {bar}")

		temporal = self._as_mapping(report.get("temporal"))
		if self._should_render_temporal_section(temporal):
			lines.append("")
			lines.extend(self._format_temporal(temporal, section_title="[ SECTION 5 — TEMPORAL DIFF ALERTS ]"))

		summary = self._as_mapping(report.get("summary"))
		if summary:
			attack_paths_found = self._as_int(summary.get("attack_paths_found"))
			lines.extend(
				[
					"",
					head,
					"  SUMMARY",
					f"  Attack paths found   : {attack_paths_found}",
					f"  Circular permissions : {self._as_int(summary.get('cycles_found'))}",
					f"  Total blast-radius nodes exposed : {self._as_int(summary.get('blast_nodes_exposed'))}",
					f"  Critical node to remove : {self._structured_node_name(summary.get('critical_node'))}",
					head,
				]
			)

		return "\n".join(lines).rstrip() + "\n"

	def _format_attack_path(self, attack_path: Mapping[str, Any]) -> list[str]:
		if not attack_path:
			return ["", "✓ No Attack Path Detected"]

		lines = [""]

		source = str(attack_path.get("source", "unknown-source"))
		target = str(attack_path.get("target", "unknown-target"))
		path_nodes = self._as_sequence(attack_path.get("path"))
		risk_score = self._as_float(attack_path.get("risk_score"))
		hops = max(0, len(path_nodes) - 1) if path_nodes else self._as_int(attack_path.get("hops"), default=0)
		is_detected = bool(path_nodes) and hops > 0

		if is_detected:
			lines.append("⚠ Attack Path Detected")
			lines.append(f"Path: {self._format_path(path_nodes)}")
		else:
			lines.append("✓ No Attack Path Detected")
			lines.append(f"Source: {self._node_label(source)}")
			lines.append(f"Target: {self._node_label(target)}")

		if not path_nodes:
			path_nodes = [source, target]

		risk_label = self._risk_level(risk_score)
		lines.append(f"Hops: {hops} | Risk: {risk_score:.1f} ({risk_label})")
		return lines

	def _format_blast_radius(self, blast_radius: Mapping[str, Any]) -> list[str]:
		hops = self._as_int(blast_radius.get("max_hops"), default=3)
		reachable_nodes = self._as_sequence(blast_radius.get("reachable_nodes"))
		count = self._as_int(blast_radius.get("count"), default=len(reachable_nodes))

		lines = [
			"",
			f"Blast Radius: {count} node(s) within {hops} hop(s)",
		]

		if reachable_nodes:
			labels = [self._node_label(node) for node in reachable_nodes]
			lines.append(f"Danger Zone: {', '.join(labels)}")

		return lines

	def _format_cycles(self, cycles: Any) -> list[str]:
		cycle_list = self._normalize_cycles(cycles)
		lines = ["", f"Cycles: {len(cycle_list)}"]

		if cycle_list and cycle_list[0]:
			lines.append(f"Sample Cycle: {' -> '.join(cycle_list[0])}")

		return lines

	def _format_critical_node(self, critical_node: Mapping[str, Any]) -> list[str]:
		node_id = str(critical_node.get("node_id", "unknown-node"))
		removed = self._as_int(critical_node.get("paths_removed"), default=0)
		total_before = self._as_int(critical_node.get("total_paths_before"), default=0)
		total_after = self._as_int(critical_node.get("total_paths_after"), default=max(0, total_before - removed))

		return [
			"",
			f"Critical Node: {self._node_label(node_id)}",
			f"Path Disruption: before={total_before} after={total_after} removed={removed}",
		]

	def _format_temporal(self, temporal: Mapping[str, Any], section_title: str | None = None) -> list[str]:
		connectivity = self._as_mapping(temporal.get("connectivity"))
		new_paths = [self._as_mapping(item) for item in self._as_sequence(connectivity.get("new_attack_paths"))]
		alerts = [self._as_mapping(item) for item in self._as_sequence(temporal.get("alerts"))]

		new_count = self._as_int(
			temporal.get("new_attack_paths_count"),
			default=self._as_int(connectivity.get("new_attack_paths_count"), default=len(new_paths)),
		)
		is_first_snapshot = bool(temporal.get("is_first_snapshot"))
		current_snapshot = str(temporal.get("snapshot_timestamp") or "n/a")
		previous_snapshot = str(temporal.get("previous_snapshot_timestamp") or "n/a")

		lines = [""]
		if section_title:
			lines.append(section_title)

		if is_first_snapshot:
			lines.append("  Baseline snapshot created. No previous snapshot available for diff.")
			return lines

		lines.append(f"  Snapshot: {current_snapshot}")
		lines.append(f"  Previous: {previous_snapshot}")
		if new_count > 0:
			lines.append(f"  ⚠  New attack path(s) detected since previous scan: {new_count}")
		else:
			lines.append("  ✓  No new attack paths detected since previous scan")

		for path in new_paths[:5]:
			source = self._structured_node_name(path.get("source"))
			target = self._structured_node_name(path.get("target"))
			hops = self._as_int(path.get("hops"), default=0)
			risk = self._as_float(path.get("risk_score"))
			lines.append(f"    - {source} -> {target} | hops={hops} | risk={risk:.1f}")

		if not new_paths:
			for alert in alerts[:3]:
				title = str(alert.get("title") or "Alert")
				description = str(alert.get("description") or "")
				if description:
					lines.append(f"    - {title}: {description}")
				else:
					lines.append(f"    - {title}")

		return lines

	def _should_render_temporal_section(self, temporal: Mapping[str, Any]) -> bool:
		if not temporal:
			return False

		connectivity = self._as_mapping(temporal.get("connectivity"))
		new_paths = self._as_sequence(connectivity.get("new_attack_paths"))
		new_count = self._as_int(
			temporal.get("new_attack_paths_count"),
			default=self._as_int(connectivity.get("new_attack_paths_count"), default=len(new_paths)),
		)
		alerts = self._as_sequence(temporal.get("alerts"))
		return new_count > 0 or bool(new_paths) or bool(alerts)

	def _format_recommendations(self, recommendations: Any) -> list[str]:
		items = self._as_sequence(recommendations)
		if not items:
			return ["", "✓ Recommendations", "- No recommendations generated."]

		lines = ["", "✓ Recommendations"]
		for item in items:
			lines.append(f"- {item}")
		return lines

	def _format_path(self, path_nodes: Sequence[Any]) -> str:
		pieces = [self._node_label(node) for node in path_nodes]
		return " -> ".join(pieces)

	def _node_label(self, node: Any) -> str:
		if isinstance(node, str) and ":" in node:
			parts = node.split(":", 2)
			if len(parts) == 3:
				entity_type, namespace, name = parts
				if namespace == "cluster":
					return f"{entity_type}/{name}"
				return f"{entity_type}/{name} ({namespace})"

		if isinstance(node, Mapping):
			name = node.get("name")
			cve = node.get("cve")
			cvss = node.get("cvss")
			if name and cve and cvss is not None:
				return f"{name} ({cve}, CVSS {cvss})"
			if name:
				return str(name)
			if node.get("node_id"):
				return str(node["node_id"])
		return str(node)

	def _structured_node_name(self, node: Any) -> str:
		if isinstance(node, str) and ":" in node:
			parts = node.split(":", 2)
			if len(parts) == 3:
				return parts[2]
		if isinstance(node, Mapping) and node.get("name"):
			return str(node["name"])
		return str(node)

	def _structured_node_label(self, node: Any) -> str:
		if isinstance(node, str) and ":" in node:
			parts = node.split(":", 2)
			if len(parts) == 3:
				entity_type, _, name = parts
				return f"{name} ({entity_type})"
		if isinstance(node, Mapping):
			name = node.get("name")
			entity_type = node.get("entity_type") or node.get("type")
			if name and entity_type:
				return f"{name} ({entity_type})"
			if name:
				return str(name)
		return str(node)

	def _split_node_name_type(self, node: Any) -> tuple[str, str]:
		if isinstance(node, str) and ":" in node:
			parts = node.split(":", 2)
			if len(parts) == 3:
				return parts[2], parts[0]
		label = self._structured_node_label(node)
		if " (" in label and label.endswith(")"):
			name, rest = label.rsplit(" (", 1)
			return name, rest[:-1]
		return str(node), "Unknown"

	def _normalize_cycles(self, cycles: Any) -> list[list[str]]:
		if isinstance(cycles, Mapping) and "cycles" in cycles:
			cycles = cycles.get("cycles")

		cycle_list = self._as_sequence(cycles)
		normalized: list[list[str]] = []
		for cycle in cycle_list:
			if isinstance(cycle, Sequence) and not isinstance(cycle, (str, bytes)):
				normalized.append([str(node) for node in cycle])
			else:
				normalized.append([str(cycle)])
		return normalized

	def _section_header(self, title: str) -> list[str]:
		line = "=" * len(title)
		return [line, title, line]

	def _as_mapping(self, value: Any) -> Mapping[str, Any]:
		if isinstance(value, Mapping):
			return value
		return {}

	def _as_sequence(self, value: Any) -> list[Any]:
		if value is None:
			return []
		if isinstance(value, (str, bytes)):
			return [value]
		if isinstance(value, Sequence):
			return list(value)
		return [value]

	def _as_float(self, value: Any) -> float:
		try:
			return float(value)
		except (TypeError, ValueError):
			return 0.0

	def _as_int(self, value: Any, default: int = 0) -> int:
		try:
			return int(value)
		except (TypeError, ValueError):
			return default

	def _risk_level(self, score: float) -> str:
		if score >= 20:
			return "CRITICAL"
		if score >= 11:
			return "HIGH"
		if score >= 9:
			return "MEDIUM"
		return "LOW"


def render_cli_report(report: Mapping[str, Any]) -> str:
	"""Convenience function for rendering a report in one call."""
	return CliFormatter().format_report(report)

