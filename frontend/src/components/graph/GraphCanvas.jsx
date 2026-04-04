import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

export default function GraphCanvas({ payload, showAttackPath, showBlastRadius, showCriticalNode }) {
  const hostRef = useRef(null);

  useEffect(() => {
    if (!hostRef.current || !payload) {
      return undefined;
    }

    const reportAttackPaths = payload.report?.attack_paths || [];
    const attackNodeIds = new Set(
      reportAttackPaths.flatMap((path) => (Array.isArray(path.path) ? path.path : [])),
    );
    if (attackNodeIds.size === 0) {
      for (const nodeId of payload.analysis?.attack_path?.path_node_ids || []) {
        attackNodeIds.add(nodeId);
      }
    }

    const blastNodeIds = new Set(payload.analysis?.blast_radius?.reachable_node_ids || []);
    for (const row of payload.report?.blast_radius_by_source || []) {
      const hops = row?.hops || {};
      for (const nodeIds of Object.values(hops)) {
        for (const nodeId of nodeIds || []) {
          blastNodeIds.add(nodeId);
        }
      }
    }

    const criticalNodeId = payload.report?.critical_nodes?.[0]?.node_id || payload.analysis?.critical_node?.node_id;

    const elements = [
      ...(payload.nodes || []).map((node) => ({
        data: {
          id: node.id,
          label: `${node.entity_type}/${node.name}`,
          risk: Number(node.risk_score || 0),
          isSource: Boolean(node.is_source),
          isSink: Boolean(node.is_sink),
          inAttackPath: showAttackPath && attackNodeIds.has(node.id),
          inBlastRadius: showBlastRadius && blastNodeIds.has(node.id),
          isCritical: showCriticalNode && criticalNodeId && criticalNodeId === node.id,
        },
      })),
      ...(payload.edges || []).map((edge) => ({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: edge.relationship_type,
          weight: Number(edge.weight || 1),
        },
      })),
    ];

    const cy = cytoscape({
      container: hostRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "mapData(risk, 0, 20, #4edea3, #ff4d5b)",
            "border-width": 1,
            "border-color": "#1f2d4a",
            label: "data(label)",
            color: "#d7e2ff",
            "font-size": 10,
            "text-wrap": "wrap",
            "text-max-width": 100,
            "text-valign": "bottom",
            "text-halign": "center",
          },
        },
        {
          selector: "node[isSource]",
          style: {
            shape: "diamond",
            "border-color": "#00f3ff",
            "border-width": 2,
          },
        },
        {
          selector: "node[isSink]",
          style: {
            shape: "round-rectangle",
            "border-color": "#ff4d5b",
            "border-width": 2,
          },
        },
        {
          selector: "node[inAttackPath]",
          style: {
            "border-color": "#00f3ff",
            "border-width": 3,
            "shadow-blur": 10,
            "shadow-color": "#00f3ff",
          },
        },
        {
          selector: "node[inBlastRadius]",
          style: {
            "overlay-color": "#4edea3",
            "overlay-opacity": 0.2,
            "overlay-padding": 6,
          },
        },
        {
          selector: "node[isCritical]",
          style: {
            "shadow-blur": 16,
            "shadow-color": "#ff4d5b",
            "shadow-opacity": 0.9,
          },
        },
        {
          selector: "edge",
          style: {
            width: "mapData(weight, 0, 10, 1, 6)",
            "line-color": "#6079b5",
            "target-arrow-color": "#6079b5",
            "target-arrow-shape": "triangle",
            label: "data(label)",
            "font-size": 8,
            color: "#8aa0cf",
            "curve-style": "bezier",
          },
        },
      ],
      layout: {
        name: "cose",
        animate: false,
        fit: true,
        nodeRepulsion: 220000,
      },
    });

    return () => cy.destroy();
  }, [payload, showAttackPath, showBlastRadius, showCriticalNode]);

  return <div ref={hostRef} style={{ width: "100%", height: "520px" }} />;
}
