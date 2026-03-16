"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  Gauge,
  Radio,
  Settings,
  Skull,
  Target,
} from "lucide-react";

import { cn } from "@/lib/utils";

const navItems = [
  { href: "/", label: "Dashboard", icon: Gauge },
  { href: "/alerts", label: "Alerts", icon: AlertTriangle },
  { href: "/events", label: "Events", icon: Radio },
  { href: "/ioc-intelligence", label: "IOC Intelligence", icon: Target },
  { href: "/threat-actors", label: "Threat Actors", icon: Skull },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="sticky top-0 flex h-screen w-72 flex-col border-r border-slate-800 bg-slate-950/90 p-5">
      <div className="mb-8 flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/80 p-3">
        <div className="rounded-lg bg-red-500/20 p-2 text-red-300">
          <Activity className="h-5 w-5" />
        </div>
        <div>
          <p className="text-sm font-semibold text-slate-100">Threat Intel Platform</p>
          <p className="text-xs text-slate-400">SOC Analyst Console</p>
        </div>
      </div>

      <nav className="space-y-2">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition",
                isActive
                  ? "bg-slate-800 text-slate-100"
                  : "text-slate-400 hover:bg-slate-900 hover:text-slate-100",
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
