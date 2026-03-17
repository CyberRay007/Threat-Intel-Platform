"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { AlertTriangle, ArrowRight, RefreshCw, ShieldAlert, Siren, Signal } from "lucide-react";

import { InvestigationDrawer } from "@/components/panels/investigation-drawer";
import { MetricCard } from "@/components/ui/metric-card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { getAlerts, getDashboardSummary, getEventStats, getEvents, getIntelDashboard, triageAlert } from "@/lib/api";
import { AlertRow, DashboardSummary, EventRow, EventStats, IntelDashboardResponse } from "@/lib/types";
import { formatDateTime, formatPercent } from "@/lib/utils";

const severityColor: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#3b82f6",
};

const timeRangeToMinutes: Record<string, number> = {
  "15m": 15,
  "1h": 60,
  "24h": 24 * 60,
  "7d": 7 * 24 * 60,
};

function getIsoStartDate(range: string) {
  const minutes = timeRangeToMinutes[range] ?? timeRangeToMinutes["24h"];
  const start = new Date(Date.now() - minutes * 60 * 1000);
  return start.toISOString();
}

export default function SecurityOverviewPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [stats, setStats] = useState<EventStats | null>(null);
  const [intel, setIntel] = useState<IntelDashboardResponse | null>(null);
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);
  const [timeRange, setTimeRange] = useState<"15m" | "1h" | "24h" | "7d">("24h");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [triageStatus, setTriageStatus] = useState<Record<number, string>>({});
  const [triageNote, setTriageNote] = useState<Record<number, string>>({});
  const [triagePendingId, setTriagePendingId] = useState<number | null>(null);
  const [triageError, setTriageError] = useState<string | null>(null);

  const fetchOverviewData = async (range: "15m" | "1h" | "24h" | "7d") => {
    const start_date = getIsoStartDate(range);
    const [summaryResult, statsResult, alertsResult, eventsResult, intelResult] = await Promise.allSettled([
      getDashboardSummary(),
      getEventStats(),
      getAlerts({ start_date, page: 1, limit: 14 }),
      getEvents({ start_date, page: 1, limit: 20 }),
      getIntelDashboard(),
    ]);

    if (summaryResult.status === "fulfilled") setSummary(summaryResult.value);
    if (statsResult.status === "fulfilled") setStats(statsResult.value);
    if (alertsResult.status === "fulfilled") setAlerts(alertsResult.value.alerts);
    if (eventsResult.status === "fulfilled") setEvents(eventsResult.value.events);
    if (intelResult.status === "fulfilled") setIntel(intelResult.value);

    const coreFailure = summaryResult.status === "rejected" && statsResult.status === "rejected";
    if (coreFailure) {
      setError("Unable to load dashboard metrics.");
    } else {
      setError(null);
    }
  };

  useEffect(() => {
    let mounted = true;

    const load = async (isManual = false) => {
      if (isManual && mounted) setRefreshing(true);
      try {
        await fetchOverviewData(timeRange);
        if (!mounted) return;
      } catch {
        if (!mounted) return;
        setError("Unable to load dashboard metrics.");
      } finally {
        if (mounted) setRefreshing(false);
        if (mounted) setLoading(false);
      }
    };

    load();
    const timer = autoRefresh ? setInterval(() => load(), 15000) : null;
    return () => {
      mounted = false;
      if (timer) clearInterval(timer);
    };
  }, [timeRange, autoRefresh]);

  const recentAlerts: AlertRow[] = useMemo(() => alerts, [alerts]);

  const severityCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const row of summary?.alerts_by_severity ?? []) {
      map.set(row.severity, row.count);
    }
    return {
      critical: map.get("critical") ?? 0,
      high: map.get("high") ?? 0,
      medium: map.get("medium") ?? 0,
    };
  }, [summary]);

  const postureTone = severityCounts.critical > 0 ? "critical" : severityCounts.high > 0 ? "high" : "stable";

  const alertRateSpike = (stats?.alert_rate ?? 0) >= 0.2;

  const handleManualRefresh = async () => {
    setRefreshing(true);
    try {
      await fetchOverviewData(timeRange);
    } catch {
      setError("Unable to refresh overview data.");
    } finally {
      setRefreshing(false);
    }
  };

  const handleTriage = async (alert: AlertRow) => {
    const status = triageStatus[alert.id] ?? alert.status;
    const note = triageNote[alert.id] ?? "";
    setTriagePendingId(alert.id);
    setTriageError(null);
    try {
      await triageAlert(alert.id, status, note);
      setAlerts((prev) => prev.map((item) => (item.id === alert.id ? { ...item, status } : item)));
      setTriageNote((prev) => ({ ...prev, [alert.id]: "" }));
    } catch (triageErr) {
      setTriageError(triageErr instanceof Error ? triageErr.message : "Triage update failed");
    } finally {
      setTriagePendingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-cyan-50">Security Overview</h1>
        <p className="text-sm text-slate-300/75">What is happening right now across detection and triage workflows.</p>
        <div className="mt-3 flex flex-wrap gap-3 text-xs text-slate-300/80">
          <Link href="/alerts" className="rounded border border-slate-700 bg-slate-900/60 px-3 py-1.5 hover:border-cyan-400/50">Alerts</Link>
          <Link href="/intel" className="rounded border border-slate-700 bg-slate-900/60 px-3 py-1.5 hover:border-cyan-400/50">Intel</Link>
          <Link href="/scan-center" className="rounded border border-slate-700 bg-slate-900/60 px-3 py-1.5 hover:border-cyan-400/50">Scan Center</Link>
          <Link href="/settings" className="rounded border border-slate-700 bg-slate-900/60 px-3 py-1.5 hover:border-cyan-400/50">Settings</Link>
        </div>
      </div>

      <section
        className={`rounded-2xl border p-4 ${
          postureTone === "critical"
            ? "border-red-500/60 bg-red-500/10"
            : postureTone === "high"
            ? "border-orange-500/60 bg-orange-500/10"
            : "border-emerald-500/50 bg-emerald-500/10"
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs uppercase tracking-[0.14em] text-slate-200/85">Threat Posture</p>
            <p className="mt-1 text-sm text-slate-100">
              {severityCounts.critical > 0
                ? "Immediate analyst attention required"
                : severityCounts.high > 0
                ? "Elevated activity detected"
                : "No critical pressure detected"}
            </p>
          </div>
          <div className="flex items-center gap-4 text-sm">
            <span className="text-red-200">Critical: {severityCounts.critical}</span>
            <span className="text-orange-200">High: {severityCounts.high}</span>
            <span className={alertRateSpike ? "text-amber-200" : "text-emerald-200"}>
              Alert Rate: {stats ? formatPercent(stats.alert_rate) : "0.00%"}
              {alertRateSpike ? " (spike)" : ""}
            </span>
          </div>
        </div>
      </section>

      <section className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-800 bg-slate-950/60 p-4">
        <div className="flex items-center gap-2 text-sm">
          <label htmlFor="timeRange" className="text-slate-300">Time Range</label>
          <select
            id="timeRange"
            value={timeRange}
            onChange={(event) => setTimeRange(event.target.value as "15m" | "1h" | "24h" | "7d")}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-slate-100"
          >
            <option value="15m">Last 15m</option>
            <option value="1h">Last 1h</option>
            <option value="24h">Last 24h</option>
            <option value="7d">Last 7d</option>
          </select>
        </div>
        <div className="flex items-center gap-3 text-sm">
          <button
            type="button"
            onClick={() => setAutoRefresh((prev) => !prev)}
            className={`rounded px-3 py-1.5 ${autoRefresh ? "bg-cyan-600 text-white" : "bg-slate-800 text-slate-200"}`}
          >
            Auto-refresh: {autoRefresh ? "On" : "Off"}
          </button>
          <button
            type="button"
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="inline-flex items-center gap-2 rounded bg-slate-800 px-3 py-1.5 text-slate-100 hover:bg-slate-700 disabled:opacity-60"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
            Refresh now
          </button>
        </div>
      </section>

      {error ? <p className="rounded-lg border border-red-500/50 bg-red-500/10 p-3 text-sm text-red-200">{error}</p> : null}
      {triageError ? <p className="rounded-lg border border-red-500/50 bg-red-500/10 p-3 text-sm text-red-200">{triageError}</p> : null}

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

      <section className="grid gap-4 xl:grid-cols-2">
        <div className="siem-panel rounded-2xl p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-[0.12em] text-cyan-100/80">Events Over Time</h2>
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

        <div className="siem-panel rounded-2xl p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-[0.12em] text-cyan-100/80">Alerts by Severity</h2>
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
      </section>

      <section className="grid gap-4 xl:grid-cols-3">
        <div className="siem-panel rounded-2xl p-4 xl:col-span-2">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h2 className="text-sm font-semibold uppercase tracking-[0.12em] text-cyan-100/80">Alerts Triage Queue</h2>
            <Link href="/alerts" className="inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200">
              Open full queue <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
          <div className="overflow-auto">
            <table className="w-full min-w-[860px] text-left text-xs">
              <thead className="text-cyan-100/65">
                <tr>
                  <th className="py-2 pr-2">Alert</th>
                  <th className="py-2 pr-2">Severity</th>
                  <th className="py-2 pr-2">Status</th>
                  <th className="py-2 pr-2">Occurrences</th>
                  <th className="py-2 pr-2">Last Seen</th>
                  <th className="py-2 pr-2">Set Status</th>
                  <th className="py-2 pr-2">Quick Note</th>
                  <th className="py-2">Action</th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.map((alert) => {
                  const statusValue = triageStatus[alert.id] ?? alert.status;
                  const noteValue = triageNote[alert.id] ?? "";
                  const pending = triagePendingId === alert.id;
                  return (
                    <tr key={alert.id} className="border-t border-cyan-200/10 text-slate-200">
                      <td className="py-2 pr-2">
                        <button
                          type="button"
                          className="max-w-[260px] truncate text-left text-cyan-200 hover:text-cyan-100"
                          onClick={() => setSelectedAlertId(alert.id)}
                        >
                          #{alert.id} {alert.observable_type}:{alert.observable_value}
                        </button>
                      </td>
                      <td className="py-2 pr-2"><SeverityBadge severity={alert.severity} /></td>
                      <td className="py-2 pr-2">
                        <span className="rounded border border-slate-600/70 bg-slate-800/80 px-2 py-0.5 text-[10px] uppercase tracking-wide">
                          {alert.status}
                        </span>
                      </td>
                      <td className="py-2 pr-2">{alert.occurrences ?? alert.occurrence_count ?? 0}</td>
                      <td className="py-2 pr-2">{formatDateTime(alert.last_seen ?? alert.last_seen_at)}</td>
                      <td className="py-2 pr-2">
                        <select
                          aria-label={`Set status for alert ${alert.id}`}
                          value={statusValue}
                          onChange={(event) => setTriageStatus((prev) => ({ ...prev, [alert.id]: event.target.value }))}
                          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-slate-100"
                        >
                          <option value="open">open</option>
                          <option value="in_progress">in_progress</option>
                          <option value="resolved">resolved</option>
                          <option value="false_positive">false_positive</option>
                        </select>
                      </td>
                      <td className="py-2 pr-2">
                        <input
                          value={noteValue}
                          onChange={(event) => setTriageNote((prev) => ({ ...prev, [alert.id]: event.target.value }))}
                          placeholder="Add note"
                          className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-slate-100"
                        />
                      </td>
                      <td className="py-2">
                        <button
                          type="button"
                          onClick={() => handleTriage(alert)}
                          disabled={pending}
                          className="rounded bg-cyan-600 px-2.5 py-1 text-white hover:bg-cyan-500 disabled:opacity-60"
                        >
                          {pending ? "Saving..." : "Apply"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {recentAlerts.length === 0 ? <p className="mt-3 text-sm text-slate-400">No alerts found for this range.</p> : null}
          </div>
        </div>

        <div className="space-y-4">
          <div className="siem-panel rounded-2xl p-4">
            <div className="mb-3 flex items-center justify-between gap-2">
              <h2 className="text-sm font-semibold uppercase tracking-[0.12em] text-cyan-100/80">Live Events</h2>
              <Link href="/events" className="inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200">
                Event stream <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
            <div className="max-h-[370px] space-y-2 overflow-auto">
              {events.map((event) => (
                <div key={event.id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-3 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-slate-100">{formatDateTime(event.timestamp)}</span>
                    <span className={`rounded px-2 py-0.5 uppercase ${event.detection_result === "alerted" ? "bg-red-500/20 text-red-200" : "bg-emerald-500/20 text-emerald-200"}`}>
                      {event.detection_result}
                    </span>
                  </div>
                  <p className="mt-1 text-slate-200">{event.observable ?? "n/a"}</p>
                  <p className="mt-1 text-slate-400">{event.event_type} · {event.source}</p>
                </div>
              ))}
              {events.length === 0 ? <p className="text-sm text-slate-400">No events in selected window.</p> : null}
            </div>
          </div>

          <div className="siem-panel rounded-2xl p-4">
            <div className="mb-3 flex items-center justify-between gap-2">
              <h2 className="text-sm font-semibold uppercase tracking-[0.12em] text-cyan-100/80">Intelligence Signals</h2>
              <Link href="/intel" className="inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200">
                Open intel <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
            <div className="space-y-2 text-sm">
              <p className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-slate-200">
                New IOCs tracked: <span className="font-semibold text-cyan-200">{intel?.total_iocs ?? 0}</span>
              </p>
              <p className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-slate-200">
                Most active actor: <span className="font-semibold text-cyan-200">{intel?.top_actors?.[0]?.name ?? "n/a"}</span>
              </p>
              <p className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-slate-200">
                Fastest feed signal: <span className="font-semibold text-cyan-200">{intel?.by_source?.[0]?.source ?? "n/a"}</span>
              </p>
            </div>
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
