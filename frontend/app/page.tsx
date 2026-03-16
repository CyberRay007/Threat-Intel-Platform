"use client";

import { useEffect, useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { AlertTriangle, Siren, ShieldAlert, Signal } from "lucide-react";

import { InvestigationDrawer } from "@/components/panels/investigation-drawer";
import { MetricCard } from "@/components/ui/metric-card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { getDashboardSummary, getEventStats } from "@/lib/api";
import { AlertRow, DashboardSummary, EventStats } from "@/lib/types";
import { formatDateTime, formatPercent } from "@/lib/utils";

const severityColor: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#3b82f6",
};

const piePalette = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#3b82f6", "#64748b"];

export default function SecurityOverviewPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [stats, setStats] = useState<EventStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);

  useEffect(() => {
    let mounted = true;

    const load = async () => {
      try {
        const [summaryData, statsData] = await Promise.all([
          getDashboardSummary(),
          getEventStats(),
        ]);
        if (!mounted) return;
        setSummary(summaryData);
        setStats(statsData);
        setError(null);
      } catch {
        if (!mounted) return;
        setError("Unable to load dashboard metrics.");
      } finally {
        if (mounted) setLoading(false);
      }
    };

    load();
    const timer = setInterval(load, 15000);
    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  const recentAlerts: AlertRow[] = useMemo(() => summary?.recent_alerts ?? [], [summary]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-slate-100">Security Overview</h1>
        <p className="text-sm text-slate-400">Live SOC situational awareness from detection and intelligence pipelines.</p>
      </div>

      {error ? <p className="rounded-lg border border-red-500/50 bg-red-500/10 p-3 text-sm text-red-200">{error}</p> : null}

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          title="Total Events Processed Today"
          value={summary?.metrics.total_events_processed_today ?? (loading ? "..." : 0)}
          helper="Volume entering detection pipeline"
          icon={<Signal className="h-4 w-4 text-slate-400" />}
        />
        <MetricCard
          title="Alerts Generated Today"
          value={summary?.metrics.alerts_generated_today ?? (loading ? "..." : 0)}
          helper="New cases requiring analyst review"
          icon={<Siren className="h-4 w-4 text-slate-400" />}
        />
        <MetricCard
          title="Open Alerts"
          value={stats?.open_alerts ?? (loading ? "..." : 0)}
          helper="Active triage workload"
          icon={<ShieldAlert className="h-4 w-4 text-slate-400" />}
        />
        <MetricCard
          title="Alert Rate"
          value={stats ? formatPercent(stats.alert_rate) : loading ? "..." : "0.00%"}
          helper="Alert-to-event conversion"
          icon={<AlertTriangle className="h-4 w-4 text-slate-400" />}
        />
      </section>

      <section className="grid gap-4 xl:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 xl:col-span-2">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-[0.12em] text-slate-300">Events Over Time</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={summary?.events_over_time ?? []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="date" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
                <Line type="monotone" dataKey="events" stroke="#38bdf8" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-[0.12em] text-slate-300">Recent Alerts</h2>
          <div className="max-h-64 overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-400">
                <tr>
                  <th className="py-2">ID</th>
                  <th className="py-2">Observable</th>
                  <th className="py-2">Severity</th>
                  <th className="py-2">Status</th>
                  <th className="py-2">Occ</th>
                  <th className="py-2">First Seen</th>
                  <th className="py-2">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="cursor-pointer border-t border-slate-800 text-slate-200 hover:bg-slate-800/50"
                    onClick={() => setSelectedAlertId(alert.id)}
                  >
                    <td className="py-2">#{alert.id}</td>
                    <td className="py-2">{`${alert.observable_type}:${alert.observable_value}`}</td>
                    <td className="py-2"><SeverityBadge severity={alert.severity} /></td>
                    <td className="py-2">{alert.status}</td>
                    <td className="py-2">{alert.occurrences ?? alert.occurrence_count ?? 0}</td>
                    <td className="py-2">{formatDateTime(alert.first_seen ?? alert.first_seen_at)}</td>
                    <td className="py-2">{formatDateTime(alert.last_seen ?? alert.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-[0.12em] text-slate-300">Alerts by Severity</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={summary?.alerts_by_severity ?? []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="severity" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {(summary?.alerts_by_severity ?? []).map((entry) => (
                    <Cell key={entry.severity} fill={severityColor[entry.severity] ?? "#64748b"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-[0.12em] text-slate-300">IOC Feed Distribution</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={summary?.ioc_feed_distribution ?? []} dataKey="count" nameKey="source" outerRadius={95}>
                  {(summary?.ioc_feed_distribution ?? []).map((entry, index) => (
                    <Cell key={entry.source} fill={piePalette[index % piePalette.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <InvestigationDrawer
        alertId={selectedAlertId}
        open={selectedAlertId !== null}
        onClose={() => setSelectedAlertId(null)}
      />
    </div>
  );
}
