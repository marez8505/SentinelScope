import { Link, useLocation } from "wouter";
import {
  LayoutDashboard,
  Radar,
  ShieldAlert,
  Database,
  Wrench,
  FileText,
  Settings,
  Sun,
  Moon,
} from "lucide-react";
import { Logo } from "./Logo";
import { cn } from "@/lib/utils";
import { useTheme } from "./ThemeProvider";

interface NavItem {
  path: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  testId: string;
}

const NAV: NavItem[] = [
  { path: "/", label: "Dashboard", icon: LayoutDashboard, testId: "nav-dashboard" },
  { path: "/scan", label: "New Scan", icon: Radar, testId: "nav-new-scan" },
  { path: "/scans", label: "Scan Results", icon: ShieldAlert, testId: "nav-scans" },
  { path: "/feed", label: "Vulnerability Feed", icon: Database, testId: "nav-feed" },
  { path: "/remediation", label: "Remediation", icon: Wrench, testId: "nav-remediation" },
  { path: "/reports", label: "Reports", icon: FileText, testId: "nav-reports" },
  { path: "/settings", label: "Settings & Docs", icon: Settings, testId: "nav-settings" },
];

export function AppLayout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const { theme, toggle } = useTheme();

  return (
    <div className="min-h-screen flex bg-background text-foreground">
      <aside className="w-64 shrink-0 bg-sidebar text-sidebar-foreground border-r border-sidebar-border flex flex-col">
        <div className="px-5 py-5 border-b border-sidebar-border">
          <Logo />
        </div>
        <nav className="flex-1 p-3 space-y-0.5" aria-label="Primary">
          {NAV.map(({ path, label, icon: Icon, testId }) => {
            const active = path === "/" ? location === "/" : location.startsWith(path);
            return (
              <Link
                key={path}
                href={path}
                data-testid={testId}
                className={cn(
                  "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-sidebar-accent text-sidebar-accent-foreground border border-sidebar-border"
                    : "hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground",
                )}
              >
                <Icon className="h-4 w-4 shrink-0" />
                <span>{label}</span>
              </Link>
            );
          })}
        </nav>
        <div className="p-3 border-t border-sidebar-border space-y-2">
          <button
            type="button"
            onClick={toggle}
            data-testid="button-theme-toggle"
            className="flex w-full items-center justify-between rounded-md px-3 py-2 text-xs hover:bg-sidebar-accent/60"
            aria-label="Toggle theme"
          >
            <span>Theme</span>
            <span className="flex items-center gap-1.5 text-sidebar-accent-foreground/80">
              {theme === "dark" ? <Moon className="h-3.5 w-3.5" /> : <Sun className="h-3.5 w-3.5" />}
              <span className="capitalize">{theme}</span>
            </span>
          </button>
          <div className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[10px] leading-snug text-amber-300/90">
            <strong className="font-semibold">Authorized use only.</strong> Scan systems you
            own or have written permission to assess.
          </div>
        </div>
      </aside>

      <main className="flex-1 min-w-0 overflow-x-hidden">
        <div className="max-w-[1400px] mx-auto px-8 py-8">{children}</div>
      </main>
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <header className="flex items-start justify-between gap-6 mb-8">
      <div>
        {eyebrow && (
          <div className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground mb-1.5">
            {eyebrow}
          </div>
        )}
        <h1 className="text-xl font-semibold tracking-tight" data-testid="text-page-title">
          {title}
        </h1>
        {description && (
          <p className="text-sm text-muted-foreground mt-1.5 max-w-2xl">{description}</p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}
