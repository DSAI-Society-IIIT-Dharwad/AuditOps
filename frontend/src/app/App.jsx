import { BrowserRouter } from "react-router-dom";

import { AnalysisProvider } from "./AnalysisProvider";
import AppRoutes from "../routes/AppRoutes";

export default function App() {
  return (
    <AnalysisProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </AnalysisProvider>
  );
}
