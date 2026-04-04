import { Navigate, Route, Routes } from "react-router-dom";

import AppShell from "../components/layout/AppShell";
import GraphPage from "../pages/GraphPage";
import RisksPage from "../pages/RisksPage";

export default function AppRoutes() {
  return (
    <AppShell>
      <Routes>
        <Route path="/graph" element={<GraphPage />} />
        <Route path="/risks" element={<RisksPage />} />
        <Route path="*" element={<Navigate to="/graph" replace />} />
      </Routes>
    </AppShell>
  );
}
