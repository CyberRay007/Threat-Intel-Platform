"use client";

import { useEffect, useMemo, useState } from "react";
import { FileSearch, Globe2, LoaderCircle, Radar } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { listFileScans, listUrlScans, submitFileScan, submitUrlScan } from "@/lib/api";
import { FileScan, UrlScan } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";

function riskTone(score: number) {
  if (score >= 85) return "text-rose-300 border-rose-500/30 bg-rose-500/10";
  if (score >= 60) return "text-orange-300 border-orange-500/30 bg-orange-500/10";
  if (score >= 35) return "text-amber-300 border-amber-500/30 bg-amber-500/10";
  return "text-cyan-200 border-cyan-500/30 bg-cyan-500/10";
}

export default function ScanCenterPage() {
  const [target, setTarget] = useState("");
  const [urlSubmitError, setUrlSubmitError] = useState<string | null>(null);
  const [fileSubmitError, setFileSubmitError] = useState<string | null>(null);
  const [submittingUrl, setSubmittingUrl] = useState(false);
  const [submittingFile, setSubmittingFile] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [urlScans, setUrlScans] = useState<UrlScan[]>([]);
  const [fileScans, setFileScans] = useState<FileScan[]>([]);
  const [activeUrlScanId, setActiveUrlScanId] = useState<number | null>(null);
  const [activeFileScanId, setActiveFileScanId] = useState<number | null>(null);

  useEffect(() => {
    let mounted = true;

    const load = async () => {
      try {
        const [urlPayload, filePayload] = await Promise.all([
          listUrlScans({ page: 1, limit: 8 }),
          listFileScans({ page: 1, limit: 8 }),
        ]);
        if (!mounted) return;
        setUrlScans(urlPayload.scans);
        setFileScans(filePayload.scans);
      } catch {
        if (!mounted) return;
        setUrlScans([]);
        setFileScans([]);
      }
    };

    load();
    const timer = setInterval(load, 6000);
    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  const selectedUrlScan = useMemo(
    () => urlScans.find((scan) => scan.id === activeUrlScanId) ?? urlScans[0] ?? null,
    [activeUrlScanId, urlScans],
  );
  const selectedFileScan = useMemo(
    () => fileScans.find((scan) => scan.id === activeFileScanId) ?? fileScans[0] ?? null,
    [activeFileScanId, fileScans],
  );

  const handleUrlSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmittingUrl(true);
    setUrlSubmitError(null);
    try {
      const created = await submitUrlScan(target.trim());
      setTarget("");
      setActiveUrlScanId(created.id);
      setUrlScans((previous) => [created, ...previous.filter((item) => item.id !== created.id)].slice(0, 8));
    } catch (submitError) {
      setUrlSubmitError(submitError instanceof Error ? submitError.message : "Unable to submit scan");
    } finally {
      setSubmittingUrl(false);
    }
  };

  const handleFileSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedFile) {
      setFileSubmitError("Choose a file first.");
      return;
    }

    setSubmittingFile(true);
    setFileSubmitError(null);
    try {
      const created = await submitFileScan(selectedFile);
      setSelectedFile(null);
      setActiveFileScanId(created.id);
      setFileScans((previous) => [created, ...previous.filter((item) => item.id !== created.id)].slice(0, 8));
    } catch (submitError) {
      setFileSubmitError(submitError instanceof Error ? submitError.message : "Unable to submit file scan");
    } finally {
      setSubmittingFile(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">Scan Center</h1>
          <p className="text-sm text-slate-400">Launch backend URL, domain, and file scans from the analyst console.</p>
        </div>
        <div className="rounded-full border border-cyan-300/25 bg-cyan-300/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.16em] text-cyan-100">
          Live backend submissions
        </div>
      </div>

      <section className="grid gap-4 xl:grid-cols-2">
        <form className="siem-panel rounded-2xl p-5" onSubmit={handleUrlSubmit}>
          <div className="mb-4 flex items-center gap-3">
            <div className="rounded-xl bg-cyan-400/15 p-3 text-cyan-300">
              <Globe2 className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100">URL / Domain Scan</h2>
              <p className="text-sm text-slate-400">Submit a suspicious domain, link, or phishing URL to /scans/scan.</p>
            </div>
          </div>
          <div className="space-y-3">
            <Input
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="http://secure-account-review.net/login or suspicious-domain.biz"
            />
            {urlSubmitError ? <p className="rounded-xl border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">{urlSubmitError}</p> : null}
            <Button type="submit" disabled={submittingUrl || !target.trim()} className="w-full">
              {submittingUrl ? "Submitting scan..." : "Run URL / Domain Scan"}
            </Button>
          </div>
        </form>

        <form className="siem-panel rounded-2xl p-5" onSubmit={handleFileSubmit}>
          <div className="mb-4 flex items-center gap-3">
            <div className="rounded-xl bg-amber-400/15 p-3 text-amber-300">
              <FileSearch className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-100">File Malware Scan</h2>
              <p className="text-sm text-slate-400">Upload a file to /scans/scan/file for malware and risk analysis.</p>
            </div>
          </div>
          <div className="space-y-3">
            <label htmlFor="file-upload" className="text-xs uppercase tracking-[0.16em] text-slate-400">
              Upload file sample
            </label>
            <input
              id="file-upload"
              type="file"
              onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
              className="block w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 file:mr-4 file:rounded-md file:border-0 file:bg-slate-800 file:px-3 file:py-2 file:text-sm file:text-slate-100"
            />
            {selectedFile ? <p className="text-xs text-slate-400">Selected: {selectedFile.name}</p> : null}
            {fileSubmitError ? <p className="rounded-xl border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">{fileSubmitError}</p> : null}
            <Button type="submit" disabled={submittingFile || !selectedFile} className="w-full">
              {submittingFile ? "Uploading sample..." : "Run File Scan"}
            </Button>
          </div>
        </form>
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
        <div className="siem-panel rounded-2xl p-5">
          <div className="mb-4 flex items-center gap-3">
            <Radar className="h-5 w-5 text-cyan-300" />
            <div>
              <h2 className="text-lg font-semibold text-slate-100">Recent URL / Domain Scans</h2>
              <p className="text-sm text-slate-400">Most recent backend scan jobs for this authenticated user.</p>
            </div>
          </div>
          <div className="space-y-2">
            {urlScans.length === 0 ? (
              <p className="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-3 text-sm text-slate-400">No URL scans yet.</p>
            ) : (
              urlScans.map((scan) => (
                <button
                  key={scan.id}
                  type="button"
                  onClick={() => setActiveUrlScanId(scan.id)}
                  className={`flex w-full items-center justify-between rounded-xl border px-4 py-3 text-left transition ${activeUrlScanId === scan.id ? "border-cyan-300/40 bg-cyan-400/10" : "border-slate-800 bg-slate-950/60 hover:bg-slate-900/80"}`}
                >
                  <div>
                    <p className="font-mono text-xs text-slate-100">{scan.target_url}</p>
                    <p className="mt-1 text-xs text-slate-400">Queued {formatDateTime(scan.created_at)}</p>
                  </div>
                  <div className="text-right">
                    <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${riskTone(scan.result?.risk_score ?? scan.risk_score ?? 0)}`}>
                      {scan.status}
                    </span>
                    <p className="mt-1 text-xs text-slate-300">Risk {scan.result?.risk_score ?? scan.risk_score ?? 0}</p>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        <div className="siem-panel rounded-2xl p-5">
          <h2 className="mb-4 text-lg font-semibold text-slate-100">Selected URL Scan</h2>
          {selectedUrlScan ? (
            <div className="space-y-4">
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                <p className="font-mono text-xs text-cyan-100">{selectedUrlScan.target_url}</p>
                <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <p className="text-slate-400">Status</p>
                    <p className="text-slate-100">{selectedUrlScan.status}</p>
                  </div>
                  <div>
                    <p className="text-slate-400">Overall Risk</p>
                    <p className="text-slate-100">{selectedUrlScan.result?.risk_score ?? selectedUrlScan.risk_score}</p>
                  </div>
                  <div>
                    <p className="text-slate-400">Structural</p>
                    <p className="text-slate-100">{selectedUrlScan.result?.structural_score ?? selectedUrlScan.structural_score}</p>
                  </div>
                  <div>
                    <p className="text-slate-400">Feed Intel</p>
                    <p className="text-slate-100">{selectedUrlScan.result?.feed_intel_score ?? selectedUrlScan.feed_intel_score}</p>
                  </div>
                  <div>
                    <p className="text-slate-400">VirusTotal</p>
                    <p className="text-slate-100">{selectedUrlScan.result?.vt_score ?? selectedUrlScan.vt_score}</p>
                  </div>
                  <div>
                    <p className="text-slate-400">Historical</p>
                    <p className="text-slate-100">{selectedUrlScan.result?.historical_score ?? selectedUrlScan.historical_score}</p>
                  </div>
                </div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                <p className="mb-2 text-xs uppercase tracking-[0.16em] text-slate-400">Backend Summary</p>
                <p className="text-sm text-slate-200">{selectedUrlScan.result?.summary || "Scan queued or no summary returned yet."}</p>
              </div>
            </div>
          ) : (
            <p className="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-3 text-sm text-slate-400">Submit a URL or domain scan to populate this panel.</p>
          )}
        </div>
      </section>

      <section className="siem-panel rounded-2xl p-5">
        <h2 className="mb-4 text-lg font-semibold text-slate-100">Recent File Scans</h2>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {fileScans.length === 0 ? (
            <p className="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-3 text-sm text-slate-400">No file scans yet.</p>
          ) : (
            fileScans.map((scan) => (
              <button
                key={scan.id}
                type="button"
                onClick={() => setActiveFileScanId(scan.id)}
                className={`rounded-xl border px-4 py-3 text-left transition ${activeFileScanId === scan.id ? "border-amber-300/40 bg-amber-400/10" : "border-slate-800 bg-slate-950/60 hover:bg-slate-900/80"}`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="truncate text-sm font-semibold text-slate-100">{scan.filename}</p>
                    <p className="mt-1 font-mono text-[10px] text-slate-400">{scan.sha256.slice(0, 22)}...</p>
                  </div>
                  <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${riskTone(scan.risk_score)}`}>
                    {scan.status}
                  </span>
                </div>
                <div className="mt-3 text-xs text-slate-300">
                  <p>Risk score: {scan.risk_score}</p>
                  <p>Submitted: {formatDateTime(scan.created_at)}</p>
                </div>
              </button>
            ))
          )}
        </div>
        {selectedFileScan ? (
          <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-200">
            <p className="font-semibold text-slate-100">Focused file scan</p>
            <p className="mt-2">Filename: {selectedFileScan.filename}</p>
            <p>SHA256: <span className="font-mono text-xs">{selectedFileScan.sha256}</span></p>
            <p>Status: {selectedFileScan.status}</p>
            <p>Risk score: {selectedFileScan.risk_score}</p>
          </div>
        ) : null}
      </section>
    </div>
  );
}
