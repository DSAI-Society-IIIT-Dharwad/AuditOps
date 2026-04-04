import { NavLink } from "react-router-dom";

import { useAnalysis } from "../../app/AnalysisProvider";

export default function AppShell({ children }) {
  const { namespace, loading, refreshAnalysis } = useAnalysis();

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div>
          <h1>NODE_CONSOL</h1>
          <p className="sidebar-subtitle">SYS_OPERATOR_V1</p>
        </div>

        <nav>
          <NavLink to="/graph" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            Hunt
          </NavLink>
          <NavLink to="/risks" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            Analyze
          </NavLink>
        </nav>

        <button className="sidebar-action" onClick={() => refreshAnalysis()} disabled={loading}>
          {loading ? "Scanning..." : "Initiate Scan"}
        </button>
      </aside>

      <div className="workspace-frame">
        <header className="topbar">
          <div className="topbar-title">Threat Graph Console</div>
          <div className="topbar-namespace">Namespace: {namespace}</div>
        </header>
        <main className="main-content">{children}</main>
        <footer className="statusbar">
          <span>CLUSTER_STATUS: OPTIMAL</span>
          <span>LATENCY: 14MS</span>
          <span>MODE: CONTINUOUS</span>
        </footer>
      </div>
    </div>
  );
}
