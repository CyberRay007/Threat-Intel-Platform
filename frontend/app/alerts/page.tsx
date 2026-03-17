"use client";

import { useEffect, useMemo, useState } from "react";
import {
  ColumnDef,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";

import { InvestigationDrawer } from "@/components/panels/investigation-drawer";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PaginationControls } from "@/components/ui/pagination";
import { Select } from "@/components/ui/select";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { getAlerts } from "@/lib/api";
import { AlertRow } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

export default function AlertsConsolePage() {
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(50);
  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [observableType, setObservableType] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    let mounted = true;
    setLoading(true);

    getAlerts({
      severity: severity || undefined,
      status: status || undefined,
      observable_type: observableType || undefined,
      start_date: startDate || undefined,
      end_date: endDate || undefined,
      page,
      limit,
    })
      .then((response) => {
        if (!mounted) return;
        setAlerts(response.alerts);
        setTotal(response.total);
        setError(null);
      })
      .catch(() => {
        if (!mounted) return;
        setError("Failed to load alerts.");
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, [severity, status, observableType, startDate, endDate, page, limit]);

  useEffect(() => {
    setPage(1);
  }, [severity, status, observableType, startDate, endDate]);

  const filteredAlerts = useMemo(() => {
    if (!search.trim()) return alerts;
    const q = search.toLowerCase();
    return alerts.filter((a) =>
      `${a.observable_value} ${a.observable_type} ${a.id}`.toLowerCase().includes(q),
    );
  }, [alerts, search]);

  const columns = useMemo<ColumnDef<AlertRow>[]>(
    () => [
      { header: "Alert ID", accessorKey: "id" },
      { header: "Observable Value", accessorKey: "observable_value" },
      { header: "Observable Type", accessorKey: "observable_type" },
      {
        header: "Severity",
        accessorKey: "severity",
        cell: ({ row }) => <SeverityBadge severity={String(row.original.severity)} />,
      },
      { header: "Status", accessorKey: "status" },
      {
        header: "Occurrence Count",
        cell: ({ row }) => row.original.occurrence_count ?? row.original.occurrences ?? 0,
      },
      {
        header: "First Seen",
        cell: ({ row }) => formatDateTime(row.original.first_seen_at),
      },
      {
        header: "Last Seen",
        cell: ({ row }) => formatDateTime(row.original.last_seen_at),
      },
    ],
    [],
  );

  const table = useReactTable({
    data: filteredAlerts,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold text-cyan-50">Alerts Console</h1>
        <p className="text-sm text-slate-300/75">Filter, prioritize, and pivot directly into investigations.</p>
      </div>

      <section className="siem-panel sticky top-4 z-20 grid gap-3 rounded-2xl p-4 md:grid-cols-2 lg:grid-cols-6">
        <Input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search alerts and observables"
          className="lg:col-span-2"
        />
        <Select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </Select>
        <Select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All Status</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </Select>
        <Select value={observableType} onChange={(e) => setObservableType(e.target.value)}>
          <option value="">All Observable Types</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="ip">IP</option>
          <option value="file_hash">File Hash</option>
        </Select>
        <div className="grid grid-cols-2 gap-2 lg:col-span-2">
          <Input type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} />
          <Input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} />
        </div>
        <div className="flex items-center gap-2 lg:col-span-1">
          <Select value={String(limit)} onChange={(e) => setLimit(Number(e.target.value))}>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </Select>
          <Button variant="outline" onClick={() => setPage(1)}>
            Reset
          </Button>
        </div>
      </section>

      {error ? <p className="text-sm text-red-300">{error}</p> : null}
      {loading ? <p className="text-sm text-slate-400">Loading alerts...</p> : null}

      <section className="siem-panel overflow-x-auto rounded-2xl">
        <Table>
          <THead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TH key={header.id}>
                    {header.isPlaceholder
                      ? null
                      : flexRender(header.column.columnDef.header, header.getContext())}
                  </TH>
                ))}
              </tr>
            ))}
          </THead>
          <TBody>
            {table.getRowModel().rows.map((row) => (
              <TR
                key={row.id}
                className="cursor-pointer border-t border-cyan-100/10 text-slate-200 hover:bg-cyan-400/5"
                onClick={() => setSelectedAlertId(row.original.id)}
              >
                {row.getVisibleCells().map((cell) => (
                  <TD key={cell.id} className="py-3">
                    {cell.column.id === "status" ? (
                      <span className="rounded border border-slate-600/75 bg-slate-800/80 px-2 py-1 text-[10px] uppercase tracking-wide text-slate-200">
                        {String(cell.getValue() ?? "-")}
                      </span>
                    ) : cell.column.columnDef.cell ? (
                      flexRender(cell.column.columnDef.cell, cell.getContext())
                    ) : (
                      String(cell.getValue() ?? "-")
                    )}
                  </TD>
                ))}
              </TR>
            ))}
          </TBody>
        </Table>
      </section>

      <PaginationControls page={page} limit={limit} total={total} onPageChange={setPage} />

      <InvestigationDrawer
        alertId={selectedAlertId}
        open={selectedAlertId !== null}
        onClose={() => setSelectedAlertId(null)}
      />
    </div>
  );
}
