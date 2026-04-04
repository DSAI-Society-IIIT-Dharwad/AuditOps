import { NavLink } from "react-router-dom";

import { useAnalysis } from "../../app/AnalysisProvider";

export default function AppShell({ children }) {
  const { namespace } = useAnalysis();

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <h1>SENTINEL PROTOCOL</h1>
        <p className="sidebar-subtitle">NS: {namespace}</p>
        <NavLink to="/graph" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          01. Graph View
        </NavLink>
        <NavLink to="/risks" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
          02. Risk Center
        </NavLink>
      </aside>
      <main className="main-content">{children}</main>
    </div>
  );
}
