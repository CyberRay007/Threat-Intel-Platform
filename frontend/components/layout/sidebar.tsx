"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  Clapperboard,
  Crosshair,
  DatabaseZap,
  Gauge,
  Settings,
  Target,
  Users,
} from "lucide-react";

import { cn } from "@/lib/utils";

const navItems = [
  { href: "/overview", label: "Overview", icon: Gauge },
  { href: "/alerts", label: "Alerts", icon: AlertTriangle },
  { href: "/intel", label: "Intel", icon: Target },
  { href: "/scan-center", label: "Scan Center", icon: Crosshair },
  { href: "/feeds", label: "Feeds", icon: DatabaseZap },
  { href: "/actors", label: "Actors", icon: Users },
  { href: "/campaigns", label: "Campaigns", icon: Clapperboard },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="relative z-10 m-4 mr-0 flex h-[calc(100vh-2rem)] w-72 flex-col rounded-2xl border border-cyan-300/15 bg-slate-950/80 p-5 shadow-2xl">
      <div className="mb-8 flex items-center gap-3 rounded-xl border border-cyan-300/20 bg-cyan-300/5 p-3">
        <div className="rounded-lg bg-red-500/20 p-2 text-red-300">
          <Activity className="h-5 w-5" />
        </div>
        <div>
          <p className="text-sm font-semibold text-cyan-50">THREAT.INTEL</p>
          <p className="text-xs uppercase tracking-wide text-cyan-100/60">SOC Analyst Console</p>
        </div>
      </div>

      <nav className="space-y-2">
        {navItems.map((item) => {
          const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition",
                isActive
                  ? "border border-cyan-300/30 bg-cyan-300/10 text-cyan-50"
                  : "text-slate-300/80 hover:bg-slate-900/70 hover:text-cyan-100",
              )}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
