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
    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
      <div className="mb-3 flex items-center justify-between">
        <p className="text-xs uppercase tracking-[0.16em] text-slate-400">{title}</p>
        {icon}
      </div>
      <p className="text-3xl font-semibold text-slate-100">{value}</p>
      {helper ? <p className="mt-2 text-xs text-slate-400">{helper}</p> : null}
    </div>
  );
}
