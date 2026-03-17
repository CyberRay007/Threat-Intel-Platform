"use client";

import { useEffect, useState } from "react";
import { X } from "lucide-react";

import { Input } from "@/components/ui/input";
import { PaginationControls } from "@/components/ui/pagination";
import { Sheet } from "@/components/ui/sheet";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { getActorDetail, getActors } from "@/lib/api";
import { ActorDetailResponse, ActorItem } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

export default function ThreatActorsPage() {
  const [actors, setActors] = useState<ActorItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(50);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<ActorDetailResponse | null>(null);

  useEffect(() => {
    let mounted = true;
    getActors({ query: query || undefined, page, limit })
      .then((response) => {
        if (!mounted) return;
        setActors(response.items);
        setTotal(response.total);
      })
      .catch(() => {
        if (!mounted) return;
        setActors([]);
      });

    return () => {
      mounted = false;
    };
  }, [query, page, limit]);

  useEffect(() => {
    setPage(1);
  }, [query]);

  const openActor = async (actorId: number) => {
    try {
      const detail = await getActorDetail(actorId);
      setSelected(detail);
    } catch {
      setSelected(null);
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">Threat Actor Intelligence</h1>
          <p className="text-sm text-slate-400">Attribution-centric view of actors, campaigns, and exposure.</p>
        </div>
        <span className="rounded-full border border-rose-400/25 bg-rose-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-rose-300">
          {total} actor{total !== 1 ? "s" : ""} indexed
        </span>
      </div>

      <section className="flex flex-wrap items-center gap-3 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search actor name, country, or motivation…"
          className="max-w-sm"
        />
        <select
          aria-label="Rows per page"
          value={String(limit)}
          onChange={(e) => setLimit(Number(e.target.value))}
          className="h-10 rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
        >
          <option value="25">25</option>
          <option value="50">50</option>
          <option value="100">100</option>
        </select>
      </section>

      <section className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/70">
        <Table>
          <THead>
            <TR>
              <TH>Actor Name</TH>
              <TH>Country</TH>
              <TH>Motivation</TH>
              <TH>IOCs</TH>
              <TH>Campaigns</TH>
              <TH>Last Active</TH>
            </TR>
          </THead>
          <TBody>
            {actors.map((actor) => (
              <TR
                key={actor.id}
                className="cursor-pointer border-t border-slate-800 text-slate-200 hover:bg-slate-800/40"
                onClick={() => openActor(actor.id)}
              >
                <TD>
                  <span className="font-semibold text-slate-100">{actor.name}</span>
                </TD>
                <TD>
                  {actor.country ? (
                    <span className="rounded border border-slate-600/60 bg-slate-800 px-2 py-0.5 text-[11px] uppercase tracking-wide text-slate-300">
                      {actor.country}
                    </span>
                  ) : (
                    <span className="text-slate-500">—</span>
                  )}
                </TD>
                <TD>
                  {actor.motivation ? (
                    <span className="rounded border border-amber-400/25 bg-amber-400/10 px-2 py-0.5 text-[11px] uppercase tracking-wide text-amber-200">
                      {actor.motivation}
                    </span>
                  ) : (
                    <span className="text-slate-500">—</span>
                  )}
                </TD>
                <TD>
                  <span className={`font-mono text-sm ${actor.ioc_count > 50 ? "text-rose-300" : actor.ioc_count > 10 ? "text-amber-300" : "text-slate-300"}`}>
                    {actor.ioc_count}
                  </span>
                </TD>
                <TD>{actor.campaign_count}</TD>
                <TD className="text-xs text-slate-400">{formatDateTime(actor.last_seen)}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </section>

      <PaginationControls page={page} limit={limit} total={total} onPageChange={setPage} />

      <Sheet open={selected !== null} onClose={() => setSelected(null)} title="Threat Actor Profile" widthClassName="max-w-2xl">
        {selected ? (
          <>
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-sm text-slate-300">Actor Profile</h2>
              <button type="button" aria-label="Close threat actor panel" onClick={() => setSelected(null)} className="rounded-md border border-slate-700 p-1.5 hover:bg-slate-800">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-4 text-sm">
              {/* Identity header */}
              <section className="rounded-lg border border-slate-700 bg-slate-900/80 p-4">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <p className="text-lg font-bold text-slate-100">{selected.actor.name}</p>
                    <p className="text-xs text-slate-400">
                      Active {formatDateTime(selected.actor.first_seen)} → {formatDateTime(selected.actor.last_seen)}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {selected.actor.country && (
                      <span className="rounded border border-slate-600/60 bg-slate-800 px-2 py-0.5 text-[10px] uppercase tracking-wide text-slate-300">
                        {selected.actor.country}
                      </span>
                    )}
                    {selected.actor.motivation && (
                      <span className="rounded border border-amber-400/25 bg-amber-400/10 px-2 py-0.5 text-[10px] uppercase tracking-wide text-amber-200">
                        {selected.actor.motivation}
                      </span>
                    )}
                  </div>
                </div>
              </section>

              {/* Risk posture */}
              <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="mb-2 text-xs uppercase tracking-wide text-slate-400">Risk Posture</p>
                <div className="flex flex-wrap gap-3 text-xs">
                  <span className="text-slate-300">
                    <span className="font-semibold text-slate-100">{selected.iocs.length}</span> associated IOC{selected.iocs.length !== 1 ? "s" : ""}
                  </span>
                  <span className="text-slate-300">
                    <span className="font-semibold text-slate-100">{selected.campaigns.length}</span> campaign{selected.campaigns.length !== 1 ? "s" : ""}
                  </span>
                  <span className="text-slate-300">
                    <span className={`font-semibold ${selected.recent_alerts.length > 5 ? "text-rose-300" : selected.recent_alerts.length > 0 ? "text-amber-300" : "text-slate-100"}`}>
                      {selected.recent_alerts.length}
                    </span>{" "}
                    recent alert{selected.recent_alerts.length !== 1 ? "s" : ""}
                  </span>
                </div>
              </section>

              {/* Associated IOCs */}
              <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="mb-2 text-xs uppercase tracking-wide text-slate-400">Associated IOCs</p>
                <div className="max-h-40 overflow-auto">
                  {selected.iocs.length === 0 ? (
                    <p className="text-slate-500">No IOCs linked.</p>
                  ) : (
                    <ul className="space-y-1">
                      {selected.iocs.map((ioc) => (
                        <li key={ioc.id} className="flex items-center gap-2 rounded border border-slate-700 bg-slate-800/70 px-2 py-1">
                          <span className="rounded border border-cyan-400/20 bg-cyan-400/10 px-1.5 py-0.5 text-[10px] uppercase text-cyan-200">{ioc.type}</span>
                          <span className="font-mono text-xs text-slate-200">{ioc.value}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </section>

              {/* Campaigns */}
              <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="mb-2 text-xs uppercase tracking-wide text-slate-400">Campaigns</p>
                {selected.campaigns.length === 0 ? (
                  <p className="text-slate-500">No campaigns linked.</p>
                ) : (
                  <ul className="space-y-1">
                    {selected.campaigns.map((campaign, idx) => (
                      <li key={idx} className="rounded border border-slate-700 bg-slate-800/50 px-2 py-1.5 text-slate-200">
                        {String(campaign.name ?? "Unnamed campaign")}
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              {/* Recent alerts */}
              <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="mb-2 text-xs uppercase tracking-wide text-slate-400">Recent Alerts Involving Actor</p>
                <div className="max-h-48 overflow-auto">
                  {selected.recent_alerts.length === 0 ? (
                    <p className="text-slate-500">No recent alerts.</p>
                  ) : (
                    <table className="w-full text-left text-xs">
                      <thead className="text-slate-400">
                        <tr>
                          <th className="py-2 pr-3">Alert</th>
                          <th className="py-2 pr-3">Severity</th>
                          <th className="py-2 pr-3">Status</th>
                          <th className="py-2">Observable</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selected.recent_alerts.map((alert) => (
                          <tr key={alert.id} className="border-t border-slate-700">
                            <td className="py-2 pr-3 text-slate-300">#{alert.id}</td>
                            <td className="py-2 pr-3">
                              <span className={`rounded px-1.5 py-0.5 text-[10px] uppercase font-semibold ${
                                alert.severity === "critical" ? "bg-rose-500/20 text-rose-300" :
                                alert.severity === "high"     ? "bg-orange-500/20 text-orange-300" :
                                alert.severity === "medium"   ? "bg-amber-500/20 text-amber-300" :
                                                                "bg-slate-600/40 text-slate-300"
                              }`}>
                                {alert.severity}
                              </span>
                            </td>
                            <td className="py-2 pr-3 text-slate-400">{alert.status}</td>
                            <td className="py-2 font-mono text-slate-200">{alert.observable_value}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </section>
            </div>
          </>
        ) : null}
      </Sheet>
    </div>
  );
}
