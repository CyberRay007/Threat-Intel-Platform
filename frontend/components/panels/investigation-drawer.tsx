"use client";

import { useEffect, useState } from "react";
import { X } from "lucide-react";
import Link from "next/link";

import { SeverityBadge } from "@/components/ui/severity-badge";
import { Button } from "@/components/ui/button";
import { getInvestigation } from "@/lib/api";
import { InvestigationResponse } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

export function InvestigationDrawer({
  alertId,
  open,
  onClose,
}: {
  alertId: number | null;
  open: boolean;
  onClose: () => void;
}) {
  const [data, setData] = useState<InvestigationResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open || !alertId) return;

    let mounted = true;
    setLoading(true);
    setError(null);

    getInvestigation(alertId)
      .then((payload) => {
        if (mounted) setData(payload);
      })
      .catch(() => {
        if (mounted) setError("Unable to load investigation details.");
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, [alertId, open]);

  if (!open) return null;

  const observable = data ? `${data.alert.observable_type}:${data.alert.observable_value}` : "";

  const copyObservable = async () => {
    if (!observable) return;
    try {
      await navigator.clipboard.writeText(observable);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/55">
      <div className="h-full w-full max-w-2xl overflow-y-auto border-l border-slate-700 bg-slate-950 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-cyan-50">Alert Investigation</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close investigation panel"
            className="rounded-lg border border-slate-700 p-1.5 text-slate-300 hover:bg-slate-800"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {loading ? <p className="text-sm text-slate-400">Loading investigation data...</p> : null}
        {error ? <p className="text-sm text-red-300">{error}</p> : null}

        {data ? (
          <div className="space-y-6">
            <section className="siem-panel rounded-xl p-4">
              <div className="mb-2 flex items-center justify-between">
                <p className="text-sm text-slate-300">Alert #{data.alert.id}</p>
                <SeverityBadge severity={data.alert.severity} />
              </div>
              <p className="text-lg font-semibold text-slate-100">{data.alert.title ?? "Detection Alert"}</p>
              <p className="mt-1 text-sm text-slate-400">{data.alert.description ?? "No description"}</p>
              <div className="mt-2 rounded border border-cyan-200/20 bg-slate-900/80 px-2 py-1 text-xs text-cyan-100/80">
                Observable: {observable}
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <Button size="sm" variant="outline" onClick={copyObservable}>{copied ? "Copied" : "Copy Observable"}</Button>
                <Link href={`/events`}>
                  <Button size="sm" variant="outline">Pivot to Events</Button>
                </Link>
                <Link href={`/ioc-intelligence`}>
                  <Button size="sm" variant="outline">Pivot to IOC Explorer</Button>
                </Link>
                <Link href={`/threat-actors`}>
                  <Button size="sm" variant="outline">Pivot to Actors</Button>
                </Link>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-3 text-xs text-slate-300">
                <div>Status: {data.alert.status}</div>
                <div>Matches: {data.alert.matched_count ?? "-"}</div>
                <div>First Seen: {formatDateTime(data.alert.first_seen_at)}</div>
                <div>Last Seen: {formatDateTime(data.alert.last_seen_at)}</div>
              </div>
            </section>

            <section className="siem-panel rounded-xl p-4">
              <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-300">
                Threat Actor Attribution
              </h3>
              <div className="space-y-2">
                {data.threat_actor_attribution.length === 0 ? (
                  <p className="text-sm text-slate-400">No actor attribution found.</p>
                ) : (
                  data.threat_actor_attribution.map((actor, idx) => (
                    <div key={idx} className="rounded-md border border-cyan-200/15 bg-slate-800/70 p-3 text-sm">
                      <p className="font-semibold text-slate-100">{String(actor.name ?? "Unknown actor")}</p>
                      <p className="text-slate-400">Confidence: {String(actor.confidence ?? "-")}</p>
                      <p className="text-slate-500">Evidence: {String((actor.evidence as string[] | undefined)?.join(", ") ?? "-")}</p>
                    </div>
                  ))
                )}
              </div>
            </section>

            <section className="siem-panel rounded-xl p-4">
              <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-300">Matched IOCs</h3>
              <div className="space-y-2 text-sm">
                {Object.entries(data.ioc_matches).map(([iocType, iocs]) => (
                  <div key={iocType}>
                    <p className="mb-1 text-xs uppercase tracking-wide text-slate-400">{iocType}</p>
                    {iocs.length === 0 ? (
                      <p className="text-slate-500">No matches</p>
                    ) : (
                      <ul className="space-y-1 text-slate-200">
                        {iocs.map((ioc, idx) => (
                          <li key={idx} className="rounded border border-cyan-200/15 bg-slate-800/60 px-2 py-1">
                            {String(ioc.value)}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))}
              </div>
            </section>

            <section className="siem-panel rounded-xl p-4">
              <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-300">Linked Events</h3>
              <div className="max-h-56 overflow-auto rounded border border-cyan-200/15">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-800 text-cyan-100/75">
                    <tr>
                      <th className="px-2 py-2">Event ID</th>
                      <th className="px-2 py-2">Type</th>
                      <th className="px-2 py-2">Status</th>
                      <th className="px-2 py-2">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recent_events.map((evt, idx) => (
                      <tr key={idx} className="border-t border-slate-700 text-slate-200">
                        <td className="px-2 py-2">{String(evt.event_id ?? "-")}</td>
                        <td className="px-2 py-2">{String(evt.event_type ?? "-")}</td>
                        <td className="px-2 py-2">{String(evt.status ?? "-")}</td>
                        <td className="px-2 py-2">{formatDateTime(String(evt.created_at ?? ""))}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </div>
        ) : null}
      </div>
    </div>
  );
}
