"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { PaginationControls } from "@/components/ui/pagination";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { getEvents } from "@/lib/api";
import { EventRow } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

export default function EventStreamPage() {
  const [events, setEvents] = useState<EventRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(100);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let mounted = true;

    const load = async () => {
      setLoading(true);
      try {
        const payload = await getEvents({ page, limit });
        if (!mounted) return;
        setEvents(payload.events);
        setTotal(payload.total);
      } finally {
        if (mounted) setLoading(false);
      }
    };

    load();
    if (!autoRefresh) {
      return () => {
        mounted = false;
      };
    }

    const timer = setInterval(load, 5000);
    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, [autoRefresh, page, limit]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">Event Stream Monitor</h1>
          <p className="text-sm text-slate-400">Live ingress view into the detection engine.</p>
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
            className="h-4 w-4 accent-sky-500"
          />
          Auto refresh every 5s
        </label>
        <div className="flex items-center gap-2 text-sm text-slate-300">
          <span>Rows</span>
          <select
            aria-label="Rows per page"
            value={String(limit)}
            onChange={(e) => {
              setPage(1);
              setLimit(Number(e.target.value));
            }}
            className="h-9 rounded-md border border-slate-700 bg-slate-900 px-2"
          >
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="200">200</option>
          </select>
        </div>
      </div>

      {loading ? <p className="text-sm text-slate-400">Refreshing stream...</p> : null}

      <section className="max-h-[70vh] overflow-auto rounded-xl border border-slate-800 bg-slate-950/70">
        <Table>
          <THead className="sticky top-0">
            <TR>
              <TH>Timestamp</TH>
              <TH>Observable</TH>
              <TH>Event Type</TH>
              <TH>Detection Result</TH>
              <TH>Alert Link</TH>
            </TR>
          </THead>
          <TBody>
            {events.map((event) => (
              <TR key={event.id}>
                <TD>{formatDateTime(event.timestamp)}</TD>
                <TD>{event.observable ?? "-"}</TD>
                <TD>{event.event_type}</TD>
                <TD>
                  <span
                    className={
                      event.detection_result === "alerted"
                        ? "rounded bg-red-500/20 px-2 py-1 text-xs text-red-300"
                        : "rounded bg-sky-500/20 px-2 py-1 text-xs text-sky-300"
                    }
                  >
                    {event.detection_result}
                  </span>
                </TD>
                <TD>
                  {event.alert_id ? (
                    <Link href="/alerts" className="text-sky-300 hover:text-sky-200">
                      Alert #{event.alert_id}
                    </Link>
                  ) : (
                    "-"
                  )}
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </section>

      <PaginationControls page={page} limit={limit} total={total} onPageChange={setPage} />
    </div>
  );
}
