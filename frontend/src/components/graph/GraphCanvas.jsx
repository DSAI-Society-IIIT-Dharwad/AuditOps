import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";

cytoscape.use(dagre);

function formatCvss(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return "N/A";
  }
  return numeric.toFixed(1);
}

function formatNvdSource(source) {
  if (source === "annotation") {
    return "Annotation";
  }
  if (source === "nvd") {
    return "Live NVD";
  }
  return "Not enriched";
}

function toPopoverModel(nodeId, node, renderedPosition, canvasWidth, canvasHeight) {
  const cveIds = Array.isArray(node?.nvd_cve_ids) ? node.nvd_cve_ids : [];
  const imageRefs = Array.isArray(node?.nvd_image_refs) ? node.nvd_image_refs : [];
  const rawCvss = Number(node?.nvd_max_cvss);
  const nvdMaxCvss = Number.isFinite(rawCvss) ? rawCvss : null;

  return {
    nodeId,
    name: String(node?.name || nodeId),
    entityType: String(node?.entity_type || "Unknown"),
    namespace: String(node?.namespace || "unknown"),
    risk: Number(node?.risk_score || 0),
    compromised: Boolean(node?.nvd_enriched),
    nvdEnriched: Boolean(node?.nvd_enriched),
    nvdSource: String(node?.nvd_source || ""),
    nvdMaxCvss,
    nvdCveIds: cveIds,
    nvdImageRefs: imageRefs,
    left: Math.min(Math.max(12, renderedPosition.x + 14), Math.max(12, canvasWidth - 260)),
    top: Math.min(Math.max(12, renderedPosition.y + 12), Math.max(12, canvasHeight - 200)),
  };
}

export default function GraphCanvas({
  payload,
  showAttackPath,
  showBlastRadius,
  showCriticalNode,
  selectedNodeId,
  hoveredPath,
  onSelectNode,
}) {
  const hostRef = useRef(null);
  const cyRef = useRef(null);
  const [popover, setPopover] = useState(null);

  useEffect(() => {
    if (!hostRef.current || !payload) {
      return undefined;
    }

    setPopover(null);

    const nodeLookup = new Map((payload.nodes || []).map((node) => [node.id, node]));

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
    const temporalAlertPathNodes = new Set(
      (payload?.temporal?.connectivity?.new_attack_paths || []).flatMap((path) =>
        Array.isArray(path?.path) ? path.path : [],
      ),
    );

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
          name: node.name,
          entityType: node.entity_type,
          namespace: node.namespace,
          isSource: Boolean(node.is_source),
          isSink: Boolean(node.is_sink),
          isSelected: Boolean(selectedNodeId) && selectedNodeId === node.id,
          nvdEnriched: Boolean(node.nvd_enriched),
          isCompromised: Boolean(node.nvd_enriched),
          nvdScore: Number(node.nvd_max_cvss || 0),
          inAttackPath: showAttackPath && attackNodeIds.has(node.id),
          inBlastRadius: showBlastRadius && blastNodeIds.has(node.id),
          isCritical: showCriticalNode && criticalNodeId && criticalNodeId === node.id,
          inTemporalAlert: temporalAlertPathNodes.has(node.id),
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
              shape: "ellipse",
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
              "border-color": "#19d6ff",
            },
          },
          {
            selector: "node[isSink]",
            style: {
              "border-color": "#ff8a57",
            },
          },
          {
            selector: "node[isCompromised]",
            style: {
              "background-color": "#ff4f67",
              "border-color": "#ff8fa0",
              "border-width": 3,
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
            selector: "node[nvdEnriched]",
            style: {
              "border-color": "#ffb17a",
              "border-width": 3,
              "pie-size": "92%",
              "pie-1-background-color": "#ff8a57",
              "pie-1-background-size": "mapData(nvdScore, 0, 10, 12, 50)",
              "pie-1-background-opacity": 0.92,
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
            selector: "node[inTemporalAlert]",
            style: {
              "border-color": "#ffe28e",
              "border-width": 3.5,
              "overlay-color": "#ffe28e",
              "overlay-opacity": 0.15,
            },
          },
          {
            selector: "node[isSelected]",
            style: {
              "border-color": "#ffe28e",
              "border-width": 4,
              "shadow-color": "#ffe28e",
              "shadow-opacity": 0.45,
              "shadow-blur": 22,
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
            selector: "node.path-muted",
            style: {
              opacity: 0.16,
              "text-opacity": 0.35,
            },
          },
          {
            selector: "node.path-hover",
            style: {
              "border-color": "#ffe28e",
              "border-width": 4,
              "shadow-color": "#ffe28e",
              "shadow-opacity": 0.52,
              "shadow-blur": 24,
              opacity: 1,
              "text-opacity": 1,
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
          {
            selector: "edge.path-muted",
            style: {
              opacity: 0.08,
            },
          },
          {
            selector: "edge.path-hover",
            style: {
              "line-color": "#ffe28e",
              "target-arrow-color": "#ffe28e",
              width: 5,
              opacity: 1,
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
      cyRef.current = cy;

      cy.on("mouseover", "node", (event) => {
        const focusSet = event.target.closedNeighborhood();
        cy.elements().addClass("faded");
        focusSet.removeClass("faded");
        event.target.addClass("hovered");

        const nodeId = String(event.target.data("id") || "");
        if (!nodeId) {
          return;
        }
        const node = nodeLookup.get(nodeId);
        const rendered = event.target.renderedPosition();
        const canvasWidth = hostRef.current?.clientWidth || 0;
        const canvasHeight = hostRef.current?.clientHeight || 0;
        setPopover(toPopoverModel(nodeId, node, rendered, canvasWidth, canvasHeight));
      });

      cy.on("mouseout", "node", () => {
        cy.elements().removeClass("faded");
        cy.nodes().removeClass("hovered");
        setPopover(null);
      });

      cy.on("tap", "node", (event) => {
        const nodeId = String(event.target.data("id") || "");
        if (!nodeId) {
          return;
        }

        const node = nodeLookup.get(nodeId);
        const rendered = event.target.renderedPosition();
        const canvasWidth = hostRef.current?.clientWidth || 0;
        const canvasHeight = hostRef.current?.clientHeight || 0;
        setPopover(toPopoverModel(nodeId, node, rendered, canvasWidth, canvasHeight));

        onSelectNode?.(nodeId);
      });

      cy.on("tap", (event) => {
        if (event.target === cy) {
          setPopover(null);
        }
      });
    };

    start();

    return () => {
      isDisposed = true;
      if (cy) {
        cy.destroy();
      }
      cyRef.current = null;
    };
  }, [payload, showAttackPath, showBlastRadius, showCriticalNode, selectedNodeId, onSelectNode]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }

    const hoveredNodeIds = new Set();
    const hoveredEdgePairs = new Set();

    if (Array.isArray(hoveredPath?.path)) {
      for (const nodeId of hoveredPath.path) {
        hoveredNodeIds.add(String(nodeId));
      }
      for (let index = 0; index < hoveredPath.path.length - 1; index += 1) {
        hoveredEdgePairs.add(`${hoveredPath.path[index]}->${hoveredPath.path[index + 1]}`);
      }
    }

    if (Array.isArray(hoveredPath?.edges)) {
      for (const edge of hoveredPath.edges) {
        const source = String(edge?.source || "");
        const target = String(edge?.target || "");
        if (!source || !target) {
          continue;
        }
        hoveredNodeIds.add(source);
        hoveredNodeIds.add(target);
        hoveredEdgePairs.add(`${source}->${target}`);
      }
    }

    cy.elements().removeClass("path-hover path-muted");

    if (hoveredNodeIds.size === 0 && hoveredEdgePairs.size === 0) {
      return;
    }

    cy.elements().addClass("path-muted");

    cy.nodes().forEach((node) => {
      if (hoveredNodeIds.has(String(node.id()))) {
        node.removeClass("path-muted");
        node.addClass("path-hover");
      }
    });

    cy.edges().forEach((edge) => {
      const source = String(edge.data("source") || "");
      const target = String(edge.data("target") || "");
      if (hoveredEdgePairs.has(`${source}->${target}`)) {
        edge.removeClass("path-muted");
        edge.addClass("path-hover");
      }
    });
  }, [hoveredPath, payload]);

  return (
    <div className="graph-canvas-wrap">
      <div ref={hostRef} className="graph-canvas" />
      {popover && (
        <div className="graph-node-popover" style={{ left: `${popover.left}px`, top: `${popover.top}px` }}>
          <div className="graph-node-popover-title">{popover.name}</div>
          <div className="graph-node-popover-subline">
            {popover.entityType} | {popover.namespace}
          </div>
          <div className="graph-node-popover-meta">Risk: {popover.risk.toFixed(1)}</div>
          <div className="graph-node-popover-meta">
            Status: {popover.compromised ? "Compromised" : "No compromise signal"}
          </div>
          {!popover.nvdEnriched && <div className="graph-node-popover-empty">No NVD metadata on this node.</div>}
          {popover.nvdEnriched && (
            <>
              <div className="graph-node-popover-meta">Source: {formatNvdSource(popover.nvdSource)}</div>
              <div className="graph-node-popover-meta">Max CVSS: {formatCvss(popover.nvdMaxCvss)}</div>
              {popover.nvdImageRefs.length > 0 && (
                <div className="graph-node-popover-meta">Images: {popover.nvdImageRefs.join(", ")}</div>
              )}
              {popover.nvdCveIds.length > 0 && (
                <div className="graph-node-popover-chip-row">
                  {popover.nvdCveIds.slice(0, 4).map((cveId) => (
                    <span className="graph-node-popover-chip" key={cveId}>
                      {cveId}
                    </span>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
