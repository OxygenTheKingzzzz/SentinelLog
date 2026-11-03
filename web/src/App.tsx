import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Shell } from "@/components/Shell";
import { AlertsPage } from "@/pages/AlertsPage";
import { AnomaliesPage } from "@/pages/AnomaliesPage";
import { InvestigationsPage } from "@/pages/InvestigationsPage";
import { LogsPage } from "@/pages/LogsPage";
import { OverviewPage } from "@/pages/OverviewPage";
import { RulesPage } from "@/pages/RulesPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { SourcesPage } from "@/pages/SourcesPage";

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, retry: 1 } },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Shell />}>
            <Route index element={<OverviewPage />} />
            <Route path="logs" element={<LogsPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="investigations" element={<InvestigationsPage />} />
            <Route path="anomalies" element={<AnomaliesPage />} />
            <Route path="sources" element={<SourcesPage />} />
            <Route path="rules" element={<RulesPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
