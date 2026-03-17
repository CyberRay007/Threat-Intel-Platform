"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";

import { AppShell } from "@/components/layout/app-shell";
import { getAuthToken, getSavedUserEmail, subscribeToAuthChanges } from "@/lib/api";

const AUTH_ROUTES = new Set(["/login", "/signup"]);

export function RootShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);

  useEffect(() => {
    setToken(getAuthToken());
    setEmail(getSavedUserEmail());
    setReady(true);

    return subscribeToAuthChanges((detail) => {
      setToken(detail.token);
      setEmail(detail.email);
    });
  }, []);

  useEffect(() => {
    if (!ready || !pathname) return;

    const isAuthRoute = AUTH_ROUTES.has(pathname);
    if (!token && !isAuthRoute) {
      router.replace(`/login?next=${encodeURIComponent(pathname)}`);
      return;
    }

    if (token && isAuthRoute) {
      router.replace("/");
    }
  }, [pathname, ready, router, token]);

  if (!ready) {
    return (
      <div className="siem-grid-bg flex min-h-screen items-center justify-center bg-slate-950 px-6 text-slate-200">
        <div className="siem-panel rounded-2xl px-6 py-4 text-sm uppercase tracking-[0.18em] text-cyan-100/80">
          Initializing analyst session...
        </div>
      </div>
    );
  }

  const isAuthRoute = pathname ? AUTH_ROUTES.has(pathname) : false;

  if (!token && !isAuthRoute) {
    return (
      <div className="siem-grid-bg flex min-h-screen items-center justify-center bg-slate-950 px-6 text-slate-200">
        <div className="siem-panel rounded-2xl px-6 py-4 text-sm uppercase tracking-[0.18em] text-cyan-100/80">
          Redirecting to secure login...
        </div>
      </div>
    );
  }

  if (isAuthRoute) {
    return <>{children}</>;
  }

  return <AppShell userEmail={email}>{children}</AppShell>;
}
