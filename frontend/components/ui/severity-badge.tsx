import { cn } from "@/lib/utils";

const severityColorMap: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  low: "bg-sky-500/20 text-sky-300 border-sky-500/40",
  info: "bg-blue-500/20 text-blue-300 border-blue-500/40",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const key = (severity || "info").toLowerCase();
  const classes = severityColorMap[key] ?? severityColorMap.info;
  return (
    <span
      className={cn(
        "inline-flex rounded-md border px-2 py-1 text-xs font-semibold uppercase tracking-wide",
        classes,
      )}
    >
      {key}
    </span>
  );
}
