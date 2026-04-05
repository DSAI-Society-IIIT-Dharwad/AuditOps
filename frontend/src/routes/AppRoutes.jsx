import { Navigate, Route, Routes } from "react-router-dom";

import AppShell from "../components/layout/AppShell";
import GraphPage from "../pages/GraphPage";
import IngestPage from "../pages/IngestPage";
import RisksPage from "../pages/RisksPage";
import SnapshotsPage from "../pages/SnapshotsPage";

export default function AppRoutes() {
  return (
    <AppShell>
      <Routes>
        <Route path="/graph" element={<GraphPage />} />
        <Route path="/ingest" element={<IngestPage />} />
        <Route path="/risks" element={<RisksPage />} />
        <Route path="/snapshots" element={<SnapshotsPage />} />
        <Route path="*" element={<Navigate to="/graph" replace />} />
      </Routes>
    </AppShell>
  );
}
