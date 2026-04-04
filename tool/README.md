# Kubernetes Attack Path Visualizer

A command-line security analysis tool for cloud-native infrastructure. This tool ingests the live state of a Kubernetes cluster via `kubectl`, models all entities and their relationships as a Directed Acyclic Graph (DAG), and applies classical graph traversal algorithms to detect exploitable multi-hop attack paths.

## 🎯 Executive Summary
Modern cloud-native applications run on Kubernetes clusters composed of interconnected entities: Users, Pods, ServiceAccounts, Roles, Secrets, and Databases. Attackers routinely exploit chains of seemingly benign permissions to reach sensitive resources, a technique known as privilege escalation via lateral movement. This tool replaces static spreadsheet reviews by mathematically modeling the cluster to surface hidden attack chains before an adversary does.

## 🚀 Phase 1 Quick Start

### Prerequisites
* Python 3.10+
* `kubectl`
* A local Kubernetes runtime (`kind` recommended, `minikube` supported)

### 1. Create local cluster (kind)
```bash
kind create cluster --name hack2future --config src/k8s-yaml/cluster-config.yaml
kubectl config use-context kind-hack2future
```

### 2. Apply deterministic test environments
```bash
kubectl apply -f src/k8s-yaml/vulnerable-cluster.yaml
kubectl apply -f src/k8s-yaml/secure-cluster.yaml
```

### 3. Run analysis per namespace
```bash
python src/main.py --ingestor kubectl --namespace vulnerable-ns
python src/main.py --ingestor kubectl --namespace secure-ns
```

## ⚙️ Core Algorithms
The application implements three primary graph traversal algorithms to analyze cluster security:

1. **Blast Radius Detection (Breadth-First Search)**: Calculates the "Danger Zone" by determining how far an attacker can reach if a specific node is compromised, running BFS up to a configurable *N* hops.
2. **Shortest Path to Crown Jewels (Dijkstra's Algorithm)**: Finds the lowest-cost attack path from a public entry point to a target "crown jewel" (e.g., Production Database) using exploitability scores as edge weights.
3. **Circular Permission Detection (Depth-First Search)**: Detects misconfigured mutual admin grants that amplify attack paths by running DFS cycle detection across role bindings.

Additionally, the tool performs **Critical Node Identification** to find the single graph node whose removal would break the most valid source-to-crown-jewel attack paths.

## 🏗️ System Architecture & SOLID Principles
To ensure the codebase is scalable and maintainable, the system is divided into four decoupled layers following Single Responsibility and Dependency Inversion principles:

* **Layer 1: Data Ingestion:** Parses live cluster state via `kubectl` or reads from a static JSON file.
* **Layer 2: Graph Construction:** Converts parsed entities and RBAC relationships into a standard DAG structure (e.g., using NetworkX). Nodes represent cluster entities, and directed edges represent trust relationships.
* **Layer 3: Security Analysis:** Houses the graph traversal and pathfinding algorithms (BFS, DFS, Dijkstra's).
* **Layer 4: Reporting:** Generates a human-readable and machine-readable Kill Chain Report outlining detected paths and remediation advice.

## 📂 Directory Structure
```text
/k8s-attack-path-visualizer
├── /core                   # Core interfaces and base classes (SOLID definitions)
│   ├── models.py           # Node and Edge classes
│   └── interfaces.py       # Base interfaces (DataIngestor, GraphStorage)
├── /ingestion              # Layer 1: Data parsing
│   ├── kubectl_runner.py   # Live cluster ingestion logic
│   └── mock_parser.py      # Local JSON ingestion fallback
├── /graph                  # Layer 2: Graph definition
│   └── networkx_builder.py # Logic to construct the DAG
├── /analysis               # Layer 3: The Brains
│   ├── blast_radius.py     # BFS implementation
│   ├── shortest_path.py    # Dijkstra's implementation
│   ├── cycle_detect.py     # DFS implementation
│   └── critical_node.py    # Node removal logic
├── /reporting              # Layer 4: Presenter
│   ├── cli_formatter.py    # Terminal output logic
│   └── pdf_generator.py    # PDF export logic
└── main.py                 # Application entry point
```

## 🧩 Core Data Models (Base Classes)
To maintain a clean and predictable state across the application, all raw Kubernetes JSON data is strictly parsed into standardized Python classes before being loaded into the graph. 

### `Node` (Cluster Entity)
Every entity within the Kubernetes cluster inherits from a base `Node` class. This ensures the graph traversal algorithms have a consistent interface to interact with, regardless of whether they are looking at a user or a configuration file.

**Standard Properties:**
* **`entity_type`**: The kind of Kubernetes resource (e.g., `User`, `Pod`, `ServiceAccount`, `Role`, `ClusterRole`, `Secret`, `Database`, `ConfigMap`).
* **`name`**: The unique identifier of the resource.
* **`namespace`**: The cluster namespace where the resource resides.
* **`is_source`**: Boolean flag identifying if this is a Public Entry Point (e.g., Internet-facing Web Server).
* **`is_sink`**: Boolean flag identifying if this is a "Crown Jewel" (e.g., Production Database, Admin Role).

### `Edge` (Trust Relationship)
Edges represent the directional permissions, network access, or trust relationships between two Nodes. 

**Standard Properties:**
* **`source_node_id`**: The origin of the permission (e.g., a Pod).
* **`target_node_id`**: The destination or granted resource (e.g., a ServiceAccount).
* **`relationship_type`**: A string classification of the link (e.g., `uses`, `bound_to`, `can_read`).
* **`weight`**: The Exploitability Score of the connection. This represents the cost for an attacker to traverse this path and is used heavily by Dijkstra's algorithm. It is calculated using CVE severity (CVSS), misconfiguration scores, or known exploit availability.