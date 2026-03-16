"use client";

import { useEffect, useState } from "react";
import { Bell } from "lucide-react";

import { Sidebar } from "@/components/layout/sidebar";
import { getEventStats } from "@/lib/api";

export function AppShell({ children }: { children: React.ReactNode }) {
  const [openAlerts, setOpenAlerts] = useState<number>(0);

  useEffect(() => {
    let mounted = true;

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

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100">
      <Sidebar />
      <div className="flex min-h-screen flex-1 flex-col">
        <header className="flex items-center justify-end border-b border-slate-800 bg-slate-950/85 px-6 py-3">
          <div className="flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-semibold tracking-wide text-slate-200">
            <Bell className="h-3.5 w-3.5 text-red-300" />
            Real-Time Open Alerts: {openAlerts}
          </div>
        </header>
        <main className="flex-1 overflow-x-hidden p-6">{children}</main>
      </div>
    </div>
  );
}
