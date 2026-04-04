# Kubernetes Attack Path Visualizer
**Graph-Based Security Analysis for Cloud-Native Infrastructure** 

**Author:** Sarthak

## 🎯 Executive Summary
Modern cloud-native applications run on Kubernetes clusters composed of dozens of interconnected entities: Users, Pods, ServiceAccounts, Roles, Secrets, and Databases. While traditional security audits rely on static spreadsheet reviews, they are fundamentally incapable of revealing multi-hop attack paths. 

This project is a command-line security analysis tool that replaces manual audits. It ingests the live state of a Kubernetes cluster, models all entities and their relationships as a Directed Acyclic Graph (DAG), and applies classical graph traversal algorithms to surface hidden, exploitable attack chains before an adversary does.

---

## 🏗️ System Architecture & Engineering Principles

This application is designed with strict adherence to SOLID principles, ensuring a clean, decoupled architecture that is entirely maintainable by a single developer. 

**Core Architectural Decisions:**
* **Zero-Caching Policy:** To guarantee that the security analysis reflects the absolute live state of the environment, state is computed entirely fresh on every execution. There is no cache layer.
* **Environment:** Developed, tested, and optimized for Fedora Linux environments.
* **Separation of Concerns:** The codebase is divided into four strictly isolated layers:

### 1. The Ingestion Layer (`/ingestion`)
Responsible for executing `kubectl` subprocess commands to fetch live cluster state (`pods`, `serviceaccounts`, `rolebindings`, `clusterrolebindings`, `secrets`, `configmaps`) and parsing the JSON output. It also features a fallback parser to read from a local `mock-cluster-graph.json`.

### 2. The Graph Layer (`/graph`)
Converts the parsed Python dictionaries into a persistent in-memory DAG utilizing the `NetworkX` library. This layer strictly enforces the data models defined below.

### 3. The Analysis Layer (`/analysis`)
Houses the core security algorithms (BFS, DFS, Dijkstra's) isolated using the Strategy Pattern.

### 4. The Reporting Layer (`/reporting`)
Formats the mathematical outputs into actionable intelligence, generating both a CLI interface and a PDF Kill Chain Report.

---

## 🧩 Standardized Data Models

To maintain a predictable state, all raw Kubernetes JSON data is strictly parsed into standardized data classes before entering the graph structure.

### `Node` (Cluster Entity)
Represents a singular Kubernetes resource (e.g., User, Pod, ServiceAccount, Role, ClusterRole, Secret, Database, ConfigMap).
* `node_id` (str): Unique identifier (e.g., `Pod:default:webapp`).
* `entity_type` (str): The kind of resource.
* `name` (str): Resource name.
* `namespace` (str): Resource namespace.
* `risk_score` (float): The base vulnerability score (e.g., CVSS severity).
* `is_source` (bool): True if it is a Public Entry Point.
* `is_sink` (bool): True if it is a Crown Jewel (e.g., Production Database).

### `Edge` (Trust Relationship)
Represents the directional permissions or trust relationships between two Nodes.
* `source_id` (str): The node originating the permission.
* `target_id` (str): The node receiving the action.
* `relationship_type` (str): The structural link (e.g., `uses`, `bound_to`, `can_read`).
* `weight` (float): The Exploitability Score. 

---

## ⚙️ Core Security Algorithms

The tool implements the following graph operations to assess cluster vulnerability:

### 1. Blast Radius Detection
* **Algorithm:** Breadth-First Search (BFS) 
* **Purpose:** If a specific node is compromised today, how far can the attacker reach? 
* **Method:** Executes BFS up to a configurable $N$ hops (default: 3) from the source.
* **Output:** The "Danger Zone" (all reachable nodes).

### 2. Shortest Path to Crown Jewels
* **Algorithm:** Dijkstra's Algorithm 
* **Purpose:** Determines the easiest route from a public entry point to a target "crown jewel" node.
* **Method:** Calculates the lowest-cost path utilizing the edge `weight`. The path risk is calculated using the formula:
  $$Cost_{edge} = Weight_{base} + Score_{vulnerability} + Penalty_{misconfiguration}$$
* **Output:** The optimal attack path and total risk score.

### 3. Circular Permission Detection
* **Algorithm:** Depth-First Search (DFS)
* **Purpose:** Detects misconfigured mutual admin grants that amplify attack paths.
* **Method:** Executes DFS cycle detection across role bindings.
* **Output:** A list of all circular dependencies.

### 4. Critical Node Identification
* **Purpose:** Identifies the single graph node whose removal would break the most attack paths.
* **Method:** Iteratively removes each node, recounts valid source-to-crown-jewel paths, and flags the node causing the greatest reduction.

---

## 📊 Sample Deliverable Output

The final execution of the tool produces a human-readable Kill Chain Report outlining the critical vulnerabilities and remediation steps:

```text
WARNING: Attack Path Detected
User 'dev-1' can reach 'production-db' via:
dev-1 -> Pod-X (CVE-2024-1234, CVSS 8.1)
  -> ServiceAccount-webapp
  -> Role-secret-reader
  -> Secret-db-credentials
  -> production-db
Total Hops: 4 | Path Risk Score: 24.7 (CRITICAL)

✓ Blast Radius of Pod-X: 7 resources within 3 hops
✓ Cycles Detected: 1 (Service-A <-> Service-B mutual admin grant)

Recommendation: Remove permission binding 'Role-X' to eliminate 8 of 11 attack paths.