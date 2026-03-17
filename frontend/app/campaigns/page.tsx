export default function CampaignsPage() {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold text-slate-100">Campaign Intelligence</h1>
        <p className="text-sm text-slate-400">Track campaigns, linked actors, and associated indicators.</p>
      </div>

      <section className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-[0.12em] text-cyan-100/80">Campaign Catalog</h2>
        <p className="text-sm text-slate-400">This page is reserved for campaign list, actor linkage, and IOC mapping views.</p>
      </section>
    </div>
  );
}
