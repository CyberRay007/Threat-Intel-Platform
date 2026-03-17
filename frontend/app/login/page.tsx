"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import { Eye, EyeOff, LockKeyhole } from "lucide-react";

import { loginWithPassword } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const nextPath = searchParams.get("next") || "/";

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await loginWithPassword(email.trim(), password);
      router.replace(nextPath);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="siem-grid-bg flex min-h-screen items-center justify-center px-6 py-10">
      <div className="w-full max-w-md">
        <div className="siem-panel rounded-[28px] p-8">
          <div className="mb-6 flex items-center gap-3">
            <div className="rounded-xl bg-emerald-400/15 p-3 text-emerald-300">
              <LockKeyhole className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-2xl font-semibold text-slate-50">Sign In</h2>
              <p className="text-sm text-slate-400">Analyst console access</p>
            </div>
          </div>

          <form className="space-y-5" onSubmit={handleSubmit}>
            <div className="space-y-1.5">
              <label className="text-xs uppercase tracking-[0.16em] text-slate-400">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@company.local"
                required
                className="flex h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs uppercase tracking-[0.16em] text-slate-400">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  className="flex h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 pr-10 text-sm text-slate-100 placeholder:text-slate-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  tabIndex={-1}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {error && (
              <p className="rounded-xl border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-sky-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
            >
              {loading ? "Signing in..." : "Login to Analyst Console"}
            </button>
          </form>

          <p className="mt-6 text-sm text-slate-400">
            New user?{" "}
            <Link href="/signup" className="text-cyan-300 hover:text-cyan-200">
              Create an account
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
