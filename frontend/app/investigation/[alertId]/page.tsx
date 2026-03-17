"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import { getInvestigation } from "@/lib/api";
import { InvestigationResponse } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

export default function InvestigationPage() {
  const params = useParams<{ alertId: string }>();
  const alertId = Number(params.alertId);
  const [data, setData] = useState<InvestigationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!Number.isFinite(alertId)) {
      setError("Invalid alert id");
      return;
    }
    let mounted = true;
    getInvestigation(alertId)
      .then((response) => {
        if (!mounted) return;
        setData(response);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!mounted) return;
        const message = err instanceof Error ? err.message : "Failed to load investigation context.";
        setError(message);
      });

    return () => {
      mounted = false;
    };
  }, [alertId]);

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">Investigation Workspace</h1>
          <p className="text-sm text-slate-400">Deep context for alert #{Number.isFinite(alertId) ? alertId : "-"}</p>
        </div>
        <Link href="/alerts" className="rounded border border-slate-700 bg-slate-900/60 px-3 py-1.5 text-xs text-cyan-200 hover:border-cyan-400/50">Back to Alerts</Link>
      </div>

      {error ? <p className="rounded-lg border border-red-500/50 bg-red-500/10 p-3 text-sm text-red-200">{error}</p> : null}

      <section className="grid gap-4 xl:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 xl:col-span-2">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-[0.12em] text-cyan-100/80">Alert Context</h2>
          {data ? (
            <div className="space-y-2 text-sm">
              <p className="text-slate-200">Observable: {data.alert.observable_type}:{data.alert.observable_value}</p>
              <p className="text-slate-300">Severity: {data.alert.severity}</p>
              <p className="text-slate-300">Status: {data.alert.status}</p>
              <p className="text-slate-300">First Seen: {formatDateTime(data.alert.first_seen_at)}</p>
              <p className="text-slate-300">Last Seen: {formatDateTime(data.alert.last_seen_at)}</p>
            </div>
          ) : (
            <p className="text-sm text-slate-400">Loading alert context...</p>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-[0.12em] text-cyan-100/80">Pivot Targets</h2>
          <div className="space-y-2 text-sm">
            <Link href="/intel" className="block rounded border border-slate-700 bg-slate-900/60 px-3 py-2 text-cyan-200 hover:border-cyan-400/50">IOC Explorer</Link>
            <Link href="/actors" className="block rounded border border-slate-700 bg-slate-900/60 px-3 py-2 text-cyan-200 hover:border-cyan-400/50">Threat Actors</Link>
            <Link href="/campaigns" className="block rounded border border-slate-700 bg-slate-900/60 px-3 py-2 text-cyan-200 hover:border-cyan-400/50">Campaigns</Link>
          </div>
        </div>
      </section>

      <section className="grid gap-4 xl:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-[0.12em] text-cyan-100/80">Recent Event Timeline</h2>
          <div className="max-h-72 space-y-2 overflow-auto text-xs">
            {(data?.recent_events ?? []).map((event) => (
              <div key={String(event.event_id)} className="rounded border border-slate-800 bg-slate-900/70 p-2 text-slate-200">
                <p>{String(event.event_type ?? "event")} · {String(event.source ?? "source")}</p>
                <p className="text-slate-400">{String(event.domain ?? event.url ?? event.ip ?? event.file_hash ?? "n/a")}</p>
              </div>
            ))}
            {(data?.recent_events ?? []).length === 0 ? <p className="text-sm text-slate-400">No timeline data.</p> : null}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-[0.12em] text-cyan-100/80">Related Intelligence</h2>
          <div className="space-y-3 text-xs">
            <div>
              <p className="mb-1 text-slate-400">Observables</p>
              <pre className="overflow-auto rounded border border-slate-800 bg-slate-900/70 p-2 text-slate-200">{JSON.stringify(data?.observables ?? {}, null, 2)}</pre>
            </div>
            <div>
              <p className="mb-1 text-slate-400">Actor Attribution</p>
              <pre className="overflow-auto rounded border border-slate-800 bg-slate-900/70 p-2 text-slate-200">{JSON.stringify(data?.threat_actor_attribution ?? [], null, 2)}</pre>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
