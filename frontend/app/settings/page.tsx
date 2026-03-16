"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { clearAuthToken, getAuthToken, loginWithPassword, setAuthToken } from "@/lib/api";

export default function SettingsPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [manualToken, setManualToken] = useState("");
  const [currentToken, setCurrentToken] = useState<string | null>(null);
  const [message, setMessage] = useState<string>("");

  useEffect(() => {
    setCurrentToken(getAuthToken());
  }, []);

  const handleLogin = async () => {
    setMessage("");
    try {
      const payload = await loginWithPassword(username.trim(), password);
      setCurrentToken(payload.access_token);
      setMessage("Login successful. Bearer token saved.");
    } catch {
      setMessage("Login failed. Check credentials.");
    }
  };

  const handleSaveManualToken = () => {
    if (!manualToken.trim()) return;
    setAuthToken(manualToken.trim());
    setCurrentToken(manualToken.trim());
    setMessage("Token saved.");
  };

  const handleClearToken = () => {
    clearAuthToken();
    setCurrentToken(null);
    setMessage("Token cleared.");
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-slate-100">Settings</h1>
      <p className="max-w-2xl text-sm text-slate-400">
        Configure API base URL, refresh cadence, and analyst defaults in this section.
      </p>

      <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-300">
        Use NEXT_PUBLIC_API_BASE_URL to point this UI to your FastAPI backend.
      </div>

      <section className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-300">JWT Authentication</h2>
        <div className="grid gap-3 md:grid-cols-2">
          <Input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Email / username" />
          <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" />
        </div>
        <div className="mt-3 flex gap-2">
          <Button onClick={handleLogin}>Login and Save Token</Button>
          <Button variant="outline" onClick={handleClearToken}>Clear Token</Button>
        </div>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-300">Manual Bearer Token</h2>
        <Input value={manualToken} onChange={(e) => setManualToken(e.target.value)} placeholder="Paste access token" />
        <div className="mt-3">
          <Button variant="secondary" onClick={handleSaveManualToken}>Save Token</Button>
        </div>
      </section>

      <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-300">
        <p>Current token status: {currentToken ? "Loaded" : "Not set"}</p>
        {message ? <p className="mt-2 text-sky-300">{message}</p> : null}
      </div>
    </div>
  );
}
