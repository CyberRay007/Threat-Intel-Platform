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
      <div>
        <h1 className="text-2xl font-semibold text-slate-100">Threat Actor Intelligence</h1>
        <p className="text-sm text-slate-400">Attribution-centric view of actors, campaigns, and exposure.</p>
      </div>

      <div className="flex w-full max-w-2xl items-center gap-2">
        <Input
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search actor name"
        className="max-w-md"
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
      </div>

      <section className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/70">
        <Table>
          <THead>
            <TR>
              <TH>Actor Name</TH>
              <TH>Country</TH>
              <TH>Motivation</TH>
              <TH>Number of IOCs</TH>
              <TH>Campaigns</TH>
            </TR>
          </THead>
          <TBody>
            {actors.map((actor) => (
              <TR
                key={actor.id}
                className="cursor-pointer border-t border-slate-800 text-slate-200 hover:bg-slate-800/40"
                onClick={() => openActor(actor.id)}
              >
                <TD className="font-semibold">{actor.name}</TD>
                <TD>{actor.country ?? "-"}</TD>
                <TD>{actor.motivation ?? "-"}</TD>
                <TD>{actor.ioc_count}</TD>
                <TD>{actor.campaign_count}</TD>
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
              <h2 className="text-sm text-slate-300">Actor Detail</h2>
              <button type="button" aria-label="Close threat actor panel" onClick={() => setSelected(null)} className="rounded-md border border-slate-700 p-1.5 hover:bg-slate-800">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-4 text-sm">
              <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="text-lg font-semibold text-slate-100">{selected.actor.name}</p>
                <p className="text-slate-400">Country: {selected.actor.country ?? "-"}</p>
                <p className="text-slate-400">Motivation: {selected.actor.motivation ?? "-"}</p>
                <p className="text-slate-400">First Seen: {formatDateTime(selected.actor.first_seen)}</p>
                <p className="text-slate-400">Last Seen: {formatDateTime(selected.actor.last_seen)}</p>
              </section>

              <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="mb-2 text-xs uppercase tracking-wide text-slate-400">Associated IOCs</p>
                <div className="max-h-40 overflow-auto">
                  <ul className="space-y-1">
                    {selected.iocs.map((ioc) => (
                      <li key={ioc.id} className="rounded border border-slate-700 bg-slate-800/70 px-2 py-1 font-mono text-xs text-slate-200">
                        [{ioc.type}] {ioc.value}
                      </li>
                    ))}
                  </ul>
                </div>
              </section>

              <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="mb-2 text-xs uppercase tracking-wide text-slate-400">Campaigns</p>
                {selected.campaigns.length === 0 ? (
                  <p className="text-slate-400">No campaigns linked.</p>
                ) : (
                  <ul className="list-disc space-y-1 pl-5 text-slate-200">
                    {selected.campaigns.map((campaign, idx) => (
                      <li key={idx}>{String(campaign.name ?? "Unnamed campaign")}</li>
                    ))}
                  </ul>
                )}
              </section>

              <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="mb-2 text-xs uppercase tracking-wide text-slate-400">Recent Alerts Involving Actor</p>
                <div className="max-h-48 overflow-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="text-slate-400">
                      <tr>
                        <th className="py-2">Alert ID</th>
                        <th className="py-2">Severity</th>
                        <th className="py-2">Status</th>
                        <th className="py-2">Observable</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selected.recent_alerts.map((alert) => (
                        <tr key={alert.id} className="border-t border-slate-700 text-slate-200">
                          <td className="py-2">#{alert.id}</td>
                          <td className="py-2">{alert.severity}</td>
                          <td className="py-2">{alert.status}</td>
                          <td className="py-2">{alert.observable_value}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </div>
          </>
        ) : null}
      </Sheet>
    </div>
  );
}
