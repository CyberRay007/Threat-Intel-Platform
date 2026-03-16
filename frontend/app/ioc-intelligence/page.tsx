"use client";

import { useEffect, useMemo, useState } from "react";

import { Input } from "@/components/ui/input";
import { PaginationControls } from "@/components/ui/pagination";
import { Select } from "@/components/ui/select";
import { Sheet } from "@/components/ui/sheet";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { getIocs } from "@/lib/api";
import { IOCItem } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

export default function IOCIntelligencePage() {
  const [query, setQuery] = useState("");
  const [iocType, setIocType] = useState("");
  const [items, setItems] = useState<IOCItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(50);
  const [selected, setSelected] = useState<IOCItem | null>(null);

  useEffect(() => {
    let mounted = true;

    getIocs({ query: query || undefined, ioc_type: iocType || undefined, page, limit })
      .then((response) => {
        if (!mounted) return;
        setItems(response.items);
        setTotal(response.total);
      })
      .catch(() => {
        if (!mounted) return;
        setItems([]);
      });

    return () => {
      mounted = false;
    };
  }, [query, iocType, page, limit]);

  useEffect(() => {
    setPage(1);
  }, [query, iocType]);

  const visibleItems = useMemo(() => items, [items]);

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold text-slate-100">IOC Intelligence Explorer</h1>
        <p className="text-sm text-slate-400">Search and pivot across domains, hashes, and IP intelligence.</p>
      </div>

      <section className="grid gap-3 rounded-xl border border-slate-800 bg-slate-950/70 p-4 md:grid-cols-4">
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search domain / hash / IP"
          className="md:col-span-2"
        />
        <Select value={iocType} onChange={(e) => setIocType(e.target.value)}>
          <option value="">All Types</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="ip">IP</option>
          <option value="file_hash">File Hash</option>
        </Select>
        <Select value={String(limit)} onChange={(e) => setLimit(Number(e.target.value))}>
          <option value="25">25</option>
          <option value="50">50</option>
          <option value="100">100</option>
        </Select>
      </section>

      <section className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/70">
        <Table>
          <THead>
            <TR>
              <TH>IOC Value</TH>
              <TH>IOC Type</TH>
              <TH>Confidence</TH>
              <TH>Threat Type</TH>
              <TH>Malware Family</TH>
              <TH>First Seen</TH>
              <TH>Last Seen</TH>
            </TR>
          </THead>
          <TBody>
            {visibleItems.map((item) => (
              <TR
                key={item.id}
                className="cursor-pointer border-t border-slate-800 text-slate-200 hover:bg-slate-800/40"
                onClick={() => setSelected(item)}
              >
                <TD className="font-mono text-xs">{item.value}</TD>
                <TD>{item.type}</TD>
                <TD>{item.confidence}</TD>
                <TD>{item.threat_type ?? "-"}</TD>
                <TD>{item.malware_family ?? "-"}</TD>
                <TD>{formatDateTime(item.first_seen)}</TD>
                <TD>{formatDateTime(item.last_seen)}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </section>

      <PaginationControls page={page} limit={limit} total={total} onPageChange={setPage} />

      <Sheet open={selected !== null} onClose={() => setSelected(null)} title="IOC Intelligence Panel" widthClassName="max-w-xl">
        {selected ? (
          <>
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-sm text-slate-300">IOC Detail</h2>
              <button type="button" aria-label="Close IOC panel" onClick={() => setSelected(null)} className="rounded-md border border-slate-700 p-1.5 hover:bg-slate-800">
                X
              </button>
            </div>

            <div className="space-y-4 text-sm">
              <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="text-xs uppercase tracking-wide text-slate-400">Indicator</p>
                <p className="font-mono text-slate-100">{selected.value}</p>
                <p className="text-slate-400">Type: {selected.type}</p>
                <p className="text-slate-400">Confidence: {selected.confidence}</p>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="mb-2 text-xs uppercase tracking-wide text-slate-400">Campaign</p>
                {(selected.campaigns ?? []).length === 0 ? (
                  <p className="text-slate-400">No campaigns linked.</p>
                ) : (
                  <ul className="list-disc space-y-1 pl-5 text-slate-200">
                    {(selected.campaigns ?? []).map((campaign) => (
                      <li key={campaign}>{campaign}</li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="mb-2 text-xs uppercase tracking-wide text-slate-400">Relationships</p>
                {(selected.relationships ?? []).length === 0 ? (
                  <p className="text-slate-400">No relationship records.</p>
                ) : (
                  <ul className="space-y-2 text-slate-200">
                    {(selected.relationships ?? []).map((rel, idx) => (
                      <li key={idx} className="rounded border border-slate-700 bg-slate-800/70 p-2">
                        {String(rel.relationship_type ?? "related")}: {String(rel.entity_type ?? "entity")} #{String(rel.entity_id ?? "-")}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3">
                <p className="mb-2 text-xs uppercase tracking-wide text-slate-400">Feeds Where It Appeared</p>
                {(selected.feeds ?? []).length === 0 ? (
                  <p className="text-slate-400">No feed source metadata.</p>
                ) : (
                  <ul className="list-disc space-y-1 pl-5 text-slate-200">
                    {(selected.feeds ?? []).map((feed) => (
                      <li key={feed}>{feed}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </>
        ) : null}
      </Sheet>
    </div>
  );
}
