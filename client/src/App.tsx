import { Switch, Route, Router } from "wouter";
import { useHashLocation } from "wouter/use-hash-location";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AppLayout } from "@/components/AppLayout";
import NotFound from "@/pages/not-found";
import Dashboard from "@/pages/Dashboard";
import NewScan from "@/pages/NewScan";
import Scans from "@/pages/Scans";
import ScanDetail from "@/pages/ScanDetail";
import Feed from "@/pages/Feed";
import Remediation from "@/pages/Remediation";
import Reports from "@/pages/Reports";
import Settings from "@/pages/Settings";

function AppRouter() {
  return (
    <Switch>
      <Route path="/" component={Dashboard} />
      <Route path="/scan" component={NewScan} />
      <Route path="/scans" component={Scans} />
      <Route path="/scans/:id" component={ScanDetail} />
      <Route path="/feed" component={Feed} />
      <Route path="/remediation" component={Remediation} />
      <Route path="/reports" component={Reports} />
      <Route path="/settings" component={Settings} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <TooltipProvider>
          <Toaster />
          <Router hook={useHashLocation}>
            <AppLayout>
              <AppRouter />
            </AppLayout>
          </Router>
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
