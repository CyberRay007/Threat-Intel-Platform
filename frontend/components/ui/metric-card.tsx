import { ReactNode } from "react";

export function MetricCard({
  title,
  value,
  helper,
  icon,
}: {
  title: string;
  value: string | number;
  helper?: string;
  icon?: ReactNode;
}) {
  return (
    <div className="siem-panel rounded-2xl p-4">
      <div className="mb-2 flex items-center justify-between">
        <p className="text-[11px] uppercase tracking-[0.18em] text-cyan-100/70">{title}</p>
        <div className="rounded-full border border-cyan-300/25 bg-slate-950/50 p-1.5">
          {icon}
        </div>
      </div>
      <div className="flex items-end justify-between gap-3">
        <p className="text-3xl font-semibold leading-none text-cyan-50">{value}</p>
        <div className="h-11 w-11 rounded-full border-4 border-cyan-300/35 border-r-cyan-100/90" />
      </div>
      {helper ? <p className="mt-2 text-[11px] text-slate-300/70">{helper}</p> : null}
    </div>
  );
}
