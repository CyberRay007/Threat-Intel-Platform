"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Check, Eye, EyeOff, UserPlus, X } from "lucide-react";

import { loginWithPassword, registerUser } from "@/lib/api";

const PASSWORD_RULES = [
  { id: "length",  label: "At least 8 characters",        test: (p: string) => p.length >= 8 },
  { id: "upper",   label: "Uppercase letter (A–Z)",        test: (p: string) => /[A-Z]/.test(p) },
  { id: "lower",   label: "Lowercase letter (a–z)",        test: (p: string) => /[a-z]/.test(p) },
  { id: "number",  label: "Number (0–9)",                  test: (p: string) => /[0-9]/.test(p) },
  { id: "special", label: "Special character (!@#$%...)",  test: (p: string) => /[^A-Za-z0-9]/.test(p) },
];

export default function SignupPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const passwordTouched = password.length > 0;
  const ruleResults = PASSWORD_RULES.map((rule) => ({ ...rule, passed: rule.test(password) }));
  const allPassed = ruleResults.every((r) => r.passed);
  const passwordsMatch = confirmPassword.length > 0 && password === confirmPassword;

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);

    if (!allPassed) {
      setError("Password does not meet all requirements.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      await registerUser(email.trim(), password);
      await loginWithPassword(email.trim(), password);
      router.replace("/");
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Account creation failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="siem-grid-bg flex min-h-screen items-center justify-center px-6 py-10">
      <div className="w-full max-w-md">
        <div className="siem-panel rounded-[28px] p-8">
          <div className="mb-6 flex items-center gap-3">
            <div className="rounded-xl bg-cyan-400/15 p-3 text-cyan-300">
              <UserPlus className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-2xl font-semibold text-slate-50">Create Account</h2>
              <p className="text-sm text-slate-400">Register your analyst credentials</p>
            </div>
          </div>

          <form className="space-y-5" onSubmit={handleSubmit}>
            {/* Email */}
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

            {/* Password */}
            <div className="space-y-1.5">
              <label className="text-xs uppercase tracking-[0.16em] text-slate-400">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Create a strong password"
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

              {/* Live strength criteria */}
              {passwordTouched && (
                <ul className="mt-2 space-y-1.5 rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2">
                  {ruleResults.map((rule) => (
                    <li
                      key={rule.id}
                      className={`flex items-center gap-2 text-xs transition-colors duration-200 ${
                        rule.passed ? "text-emerald-400" : "text-slate-500"
                      }`}
                    >
                      {rule.passed
                        ? <Check className="h-3 w-3 shrink-0" />
                        : <X className="h-3 w-3 shrink-0" />}
                      {rule.label}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Confirm password */}
            <div className="space-y-1.5">
              <label className="text-xs uppercase tracking-[0.16em] text-slate-400">Confirm Password</label>
              <div className="relative">
                <input
                  type={showConfirm ? "text" : "password"}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Repeat the password"
                  required
                  className={`flex h-10 w-full rounded-md bg-slate-900 px-3 py-2 pr-10 text-sm text-slate-100 placeholder:text-slate-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 border transition-colors duration-200 ${
                    confirmPassword.length === 0
                      ? "border-slate-700"
                      : passwordsMatch
                      ? "border-emerald-500"
                      : "border-red-500/70"
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirm((v) => !v)}
                  tabIndex={-1}
                  aria-label={showConfirm ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                >
                  {showConfirm ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {confirmPassword.length > 0 && !passwordsMatch && (
                <p className="text-xs text-red-400">Passwords do not match</p>
              )}
            </div>

            {error && (
              <p className="rounded-xl border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading || !allPassed || !passwordsMatch}
              className="w-full rounded-lg bg-cyan-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50"
            >
              {loading ? "Creating account..." : "Sign Up and Enter Console"}
            </button>
          </form>

          <p className="mt-6 text-sm text-slate-400">
            Already registered?{" "}
            <Link href="/login" className="text-cyan-300 hover:text-cyan-200">
              Login instead
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
