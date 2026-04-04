import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";

cytoscape.use(dagre);

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

    const edgeByPair = new Map(
      (payload.edges || []).map((edge) => [`${edge.source}->${edge.target}`, edge.id]),
    );
    const attackEdgeIds = new Set();

    for (const path of reportAttackPaths) {
      const steps = Array.isArray(path.path) ? path.path : [];
      for (let index = 0; index < steps.length - 1; index += 1) {
        const pairKey = `${steps[index]}->${steps[index + 1]}`;
        const edgeId = edgeByPair.get(pairKey);
        if (edgeId) {
          attackEdgeIds.add(edgeId);
        }
      }
    }

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

    const degreeByNode = new Map();
    for (const edge of payload.edges || []) {
      degreeByNode.set(edge.source, (degreeByNode.get(edge.source) || 0) + 1);
      degreeByNode.set(edge.target, (degreeByNode.get(edge.target) || 0) + 1);
    }

    const maxDegree = Math.max(1, ...degreeByNode.values(), 1);

    const elements = [
      ...(payload.nodes || []).map((node) => ({
        data: {
          id: node.id,
          label: `${node.name}\n${node.entity_type}`,
          risk: Number(node.risk_score || 0),
          influence: Number(degreeByNode.get(node.id) || 0) + 1,
          influenceNorm: (Number(degreeByNode.get(node.id) || 0) + 1) / (maxDegree + 1),
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
          inAttackPath: showAttackPath && attackEdgeIds.has(edge.id),
        },
      })),
    ];

    let isDisposed = false;
    let cy;

    const start = async () => {
      if (document.fonts?.ready) {
        await document.fonts.ready;
      }

      if (isDisposed) {
        return;
      }

      cy = cytoscape({
        container: hostRef.current,
        elements,
        minZoom: 0.25,
        maxZoom: 2.2,
        wheelSensitivity: 0.15,
        style: [
          {
            selector: "node",
            style: {
              shape: "round-rectangle",
              width: "mapData(influenceNorm, 0, 1, 36, 72)",
              height: "mapData(influenceNorm, 0, 1, 36, 72)",
              "background-color": "mapData(risk, 0, 20, #5ed39c, #ff5e63)",
              "border-width": 2,
              "border-color": "#0f2747",
              "background-opacity": 0.95,
              label: "data(label)",
              color: "#f1f6ff",
              "font-family": "Sora, sans-serif",
              "font-size": 9,
              "font-weight": 600,
              "text-wrap": "wrap",
              "text-max-width": 95,
              "text-valign": "center",
              "text-halign": "center",
              "text-background-color": "#072149",
              "text-background-opacity": 0.72,
              "text-background-padding": 2,
              "text-background-shape": "round-rectangle",
              "text-outline-opacity": 0,
              "overlay-padding": 5,
              "overlay-opacity": 0,
            },
          },
          {
            selector: "node[isSource]",
            style: {
              shape: "diamond",
              "border-color": "#19d6ff",
            },
          },
          {
            selector: "node[isSink]",
            style: {
              shape: "hexagon",
              "border-color": "#ff8a57",
            },
          },
          {
            selector: "node[inAttackPath]",
            style: {
              "border-color": "#31f0ff",
              "border-width": 3,
              "shadow-color": "#31f0ff",
              "shadow-opacity": 0.45,
              "shadow-blur": 24,
            },
          },
          {
            selector: "node[inBlastRadius]",
            style: {
              "overlay-color": "#6de8c3",
              "overlay-opacity": 0.18,
            },
          },
          {
            selector: "node[isCritical]",
            style: {
              "border-color": "#ff4f67",
              "border-width": 3.5,
              "shadow-color": "#ff4f67",
              "shadow-opacity": 0.55,
              "shadow-blur": 28,
            },
          },
          {
            selector: "node.hovered",
            style: {
              "overlay-color": "#d8f4ff",
              "overlay-opacity": 0.15,
              "overlay-padding": 10,
              "z-index": 999,
            },
          },
          {
            selector: "node.faded",
            style: {
              opacity: 0.25,
            },
          },
          {
            selector: "edge",
            style: {
              width: "mapData(weight, 0, 10, 1.5, 5)",
              "curve-style": "round-taxi",
              "taxi-direction": "rightward",
              "taxi-turn": "52%",
              "taxi-turn-min-distance": 16,
              "taxi-radius": 7,
              "line-color": "#6282c8",
              "line-opacity": 0.9,
              "line-outline-width": 0.8,
              "line-outline-color": "#081b39",
              "target-arrow-color": "#89a8eb",
              "target-arrow-shape": "chevron",
              "target-arrow-fill": "filled",
              "arrow-scale": 1,
              "source-endpoint": "outside-to-node",
              "target-endpoint": "outside-to-node",
              label: "data(label)",
              color: "#d6e4ff",
              "font-family": "IBM Plex Sans, sans-serif",
              "font-size": 8,
              "font-weight": 500,
              "text-background-color": "#041632",
              "text-background-opacity": 0.8,
              "text-background-padding": 1,
              "text-border-color": "#0e2a57",
              "text-border-opacity": 0.65,
              "text-border-width": 1,
              "text-rotation": "autorotate",
              "text-max-width": 85,
              "text-wrap": "ellipsis",
            },
          },
          {
            selector: "edge[inAttackPath]",
            style: {
              "line-color": "#35e8ff",
              "target-arrow-color": "#35e8ff",
              width: 4.5,
            },
          },
          {
            selector: "edge.faded",
            style: {
              opacity: 0.15,
            },
          },
        ],
        layout: {
          name: "dagre",
          rankDir: "LR",
          rankSep: 96,
          nodeSep: 44,
          edgeSep: 28,
          ranker: "network-simplex",
          acyclicer: "greedy",
          nodeDimensionsIncludeLabels: true,
          animate: true,
          animationDuration: 420,
          fit: true,
          padding: 42,
        },
      });

      cy.on("mouseover", "node", (event) => {
        const focusSet = event.target.closedNeighborhood();
        cy.elements().addClass("faded");
        focusSet.removeClass("faded");
        event.target.addClass("hovered");
      });

      cy.on("mouseout", "node", () => {
        cy.elements().removeClass("faded");
        cy.nodes().removeClass("hovered");
      });
    };

    start();

    return () => {
      isDisposed = true;
      if (cy) {
        cy.destroy();
      }
    };
  }, [payload, showAttackPath, showBlastRadius, showCriticalNode]);

  return <div ref={hostRef} className="graph-canvas" />;
}
