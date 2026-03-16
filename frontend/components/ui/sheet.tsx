"use client";

import { ReactNode } from "react";

import { Button } from "@/components/ui/button";

export function Sheet({
  open,
  onClose,
  title,
  children,
  widthClassName = "max-w-2xl",
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  widthClassName?: string;
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/55">
      <div className={`h-full w-full ${widthClassName} overflow-y-auto border-l border-slate-700 bg-slate-950 p-6 shadow-2xl`}>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
          <Button variant="outline" size="sm" aria-label="Close panel" onClick={onClose}>
            Close
          </Button>
        </div>
        {children}
      </div>
    </div>
  );
}
