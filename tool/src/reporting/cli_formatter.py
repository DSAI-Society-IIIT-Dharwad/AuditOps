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

		recommendations = report.get("recommendations")
		if recommendations is not None:
			lines.extend(self._format_recommendations(recommendations))

		if len(lines) == 3:
			lines.extend(["No analysis output available.", ""])

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
		if score >= 12:
			return "HIGH"
		if score >= 6:
			return "MEDIUM"
		return "LOW"


def render_cli_report(report: Mapping[str, Any]) -> str:
	"""Convenience function for rendering a report in one call."""
	return CliFormatter().format_report(report)

