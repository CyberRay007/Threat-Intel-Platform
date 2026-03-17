export default function FeedsPage() {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold text-slate-100">Feed Operations</h1>
        <p className="text-sm text-slate-400">Visibility into ingestion health, reliability, and IOC throughput.</p>
      </div>

      <section className="grid gap-4 md:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <p className="text-xs uppercase tracking-wide text-slate-400">Active Feeds</p>
          <p className="mt-2 text-2xl font-semibold text-slate-100">-</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <p className="text-xs uppercase tracking-wide text-slate-400">Last Ingestion</p>
          <p className="mt-2 text-2xl font-semibold text-slate-100">-</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <p className="text-xs uppercase tracking-wide text-slate-400">Success Rate</p>
          <p className="mt-2 text-2xl font-semibold text-slate-100">-</p>
        </div>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-[0.12em] text-cyan-100/80">Pipeline Controls</h2>
        <p className="text-sm text-slate-400">Feed enable/disable and manual re-ingestion controls can be attached to backend ingestion jobs here.</p>
      </section>
    </div>
  );
}
