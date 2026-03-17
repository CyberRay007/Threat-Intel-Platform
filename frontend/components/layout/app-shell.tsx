"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Bell, LogOut, Search, Shield, UserCircle2 } from "lucide-react";

import { Sidebar } from "@/components/layout/sidebar";
import { clearStoredSession, getEventStats, getAuthToken } from "../../lib/api";

export function AppShell({ children, userEmail }: { children: React.ReactNode; userEmail: string | null }) {
  const [openAlerts, setOpenAlerts] = useState<number>(0);
  const router = useRouter();

  useEffect(() => {
    let mounted = true;

    if (!getAuthToken()) {
      setOpenAlerts(0);
      return () => {
        mounted = false;
      };
    }

    const load = async () => {
      try {
        const stats = await getEventStats();
        if (mounted) setOpenAlerts(stats.open_alerts);
      } catch {
        if (mounted) setOpenAlerts(0);
      }
    };

    load();
    const timer = setInterval(load, 8000);
    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  const handleLogout = () => {
    clearStoredSession();
    router.replace("/login");
  };

  return (
    <div className="siem-grid-bg flex min-h-screen bg-slate-950 text-slate-100">
      <Sidebar />
      <div className="relative z-10 flex min-h-screen flex-1 flex-col">
        <header className="siem-panel m-4 mb-0 flex items-center justify-between rounded-2xl px-4 py-3">
          <div className="flex w-full max-w-md items-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-200/10 px-3 py-2">
            <Search className="h-4 w-4 text-cyan-100/80" />
            <input
              aria-label="Search"
              placeholder="Search alerts, IOC, actors"
              className="w-full bg-transparent text-sm text-cyan-50 placeholder:text-cyan-100/45 focus:outline-none"
            />
          </div>

          <div className="ml-4 flex items-center gap-2">
            <div className="flex items-center gap-2 rounded-full border border-cyan-300/25 bg-slate-900/70 px-3 py-1.5 text-xs font-semibold tracking-wide text-cyan-100">
              <Bell className="h-3.5 w-3.5 text-red-300" />
              Open Alerts: {openAlerts}
            </div>
            <button className="rounded-full border border-cyan-300/25 bg-slate-900/70 p-2 text-cyan-100/85 hover:bg-slate-800/80" aria-label="Security status">
              <Shield className="h-4 w-4" />
            </button>
            <div className="hidden items-center gap-2 rounded-full border border-cyan-300/25 bg-slate-900/70 px-3 py-1.5 md:flex">
              <UserCircle2 className="h-4 w-4 text-cyan-100/85" />
              <span className="max-w-[180px] truncate text-xs text-slate-200">{userEmail ?? "Analyst session"}</span>
            </div>
            <button className="rounded-full border border-cyan-300/25 bg-slate-900/70 p-2 text-cyan-100/85 hover:bg-slate-800/80" aria-label="Logout" onClick={handleLogout}>
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </header>
        <main className="flex-1 overflow-x-hidden p-6">{children}</main>
      </div>
    </div>
  );
}
