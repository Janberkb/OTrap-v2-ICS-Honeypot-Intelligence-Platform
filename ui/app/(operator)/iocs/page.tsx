"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";
import { Search, Download, RefreshCw, ChevronDown } from "lucide-react";
import { formatDateTime } from "@/components/ui";
import { apiPath } from "@/lib/api";

const IOC_TYPES = ["", "ip", "domain", "url", "hash_md5", "hash_sha256"];

const TYPE_BADGE: Record<string, string> = {
  ip:          "badge-critical",
  domain:      "badge-high",
  url:         "badge-medium",
  hash_md5:    "badge-low",
  hash_sha256: "badge-low",
};

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color =
    pct >= 90 ? "bg-severity-critical" :
    pct >= 70 ? "bg-severity-high" :
    pct >= 50 ? "bg-severity-medium" :
    "bg-severity-low";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-bg-base rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs tabular-nums text-text-muted">{pct}%</span>
    </div>
  );
}

export default function IoCsPage() {
  const router = useRouter();
  const [iocs,         setIocs]         = useState<any[]>([]);
  const [total,        setTotal]        = useState(0);
  const [page,         setPage]         = useState(0);
  const [loading,      setLoading]      = useState(false);
  const [iocType,      setIocType]      = useState("");
  const [search,       setSearch]       = useState("");
  const [searchInput,  setSearchInput]  = useState("");
  const [minConf,      setMinConf]      = useState("");
  const [showExport,   setShowExport]   = useState(false);
  const exportRef = useRef<HTMLDivElement>(null);

  const PAGE_SIZE = 50;

  // Close export dropdown on outside click
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (exportRef.current && !exportRef.current.contains(e.target as Node))
        setShowExport(false);
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const loadIocs = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({
      limit:  String(PAGE_SIZE),
      offset: String(page * PAGE_SIZE),
    });
    if (iocType)  params.set("ioc_type", iocType);
    if (search)   params.set("search", search);
    if (minConf)  params.set("min_confidence", String(Number(minConf) / 100));

    try {
      const r = await fetch(apiPath(`/iocs?${params.toString()}`), { credentials: "include" });
      if (!r.ok) return;
      const d = await r.json();
      setIocs(d.items ?? []);
      setTotal(d.total ?? 0);
    } finally {
      setLoading(false);
    }
  }, [iocType, search, minConf, page]);

  useEffect(() => { loadIocs(); }, [loadIocs]);
  useEffect(() => { setPage(0); }, [iocType, search, minConf]);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setSearch(searchInput);
  }

  function exportSTIX() {
    const params = new URLSearchParams();
    if (iocType) params.set("ioc_type", iocType);
    if (search)  params.set("search", search);
    window.open(apiPath(`/iocs/export/stix?${params.toString()}`), "_blank", "noopener,noreferrer");
    setShowExport(false);
  }

  return (
    <div className="p-6 space-y-4 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text-primary">IOC Intelligence</h1>
          <p className="text-sm text-text-muted mt-0.5">
            {total.toLocaleString()} unique indicators of compromise
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative" ref={exportRef}>
            <button onClick={() => setShowExport((s) => !s)} className="btn-secondary flex items-center gap-2">
              <Download className="w-4 h-4" />
              Export
              <ChevronDown className="w-3 h-3" />
            </button>
            {showExport && (
              <div className="absolute right-0 mt-1 w-36 bg-bg-surface border border-bg-border rounded-lg shadow-xl z-20 overflow-hidden">
                <button onClick={exportSTIX} className="w-full text-left px-3 py-2 text-xs hover:bg-bg-elevated transition-colors">
                  STIX 2.1
                </button>
              </div>
            )}
          </div>
          <button onClick={loadIocs} className="btn-secondary p-2">
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4 flex flex-wrap items-end gap-3">
        {/* Type filter */}
        <div className="w-36">
          <label className="text-xs text-text-muted block mb-1">Type</label>
          <select
            className="select w-full"
            value={iocType}
            onChange={(e) => setIocType(e.target.value)}
          >
            {IOC_TYPES.map((t) => (
              <option key={t} value={t}>{t || "All types"}</option>
            ))}
          </select>
        </div>

        {/* Min confidence */}
        <div className="w-40">
          <label className="text-xs text-text-muted block mb-1">
            Min Confidence{minConf ? ` — ${minConf}%` : ""}
          </label>
          <input
            type="range" min="0" max="100" step="5"
            className="w-full accent-accent"
            value={minConf || "0"}
            onChange={(e) => setMinConf(e.target.value === "0" ? "" : e.target.value)}
          />
        </div>

        {/* Search */}
        <form onSubmit={handleSearch} className="flex-1 min-w-48 flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-faint pointer-events-none" />
            <input
              type="text"
              className="input w-full pl-8 text-sm"
              placeholder="Search value…"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
            />
          </div>
          <button type="submit" className="btn-secondary text-xs px-3">Search</button>
          {(search || iocType || minConf) && (
            <button
              type="button"
              onClick={() => { setSearch(""); setSearchInput(""); setIocType(""); setMinConf(""); }}
              className="btn-secondary text-xs px-3"
            >
              Clear
            </button>
          )}
        </form>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Confidence</th>
                <th>Sessions</th>
                <th>First Seen</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {loading && iocs.length === 0 ? (
                <tr><td colSpan={6} className="text-center text-text-faint py-12">Loading…</td></tr>
              ) : iocs.length === 0 ? (
                <tr><td colSpan={6} className="text-center text-text-faint py-12">No IOCs found</td></tr>
              ) : iocs.map((ioc, i) => (
                <tr key={i}>
                  <td>
                    <span className={TYPE_BADGE[ioc.ioc_type] ?? "badge-noise"}>
                      {ioc.ioc_type}
                    </span>
                  </td>
                  <td className="font-mono text-xs max-w-xs truncate" title={ioc.value}>
                    {ioc.value}
                  </td>
                  <td>
                    <ConfidenceBar value={ioc.confidence} />
                  </td>
                  <td className="text-xs tabular-nums">
                    <button
                      className="text-accent hover:underline"
                      onClick={() => router.push(
                        ioc.ioc_type === "ip"
                          ? `/sessions?source_ip=${encodeURIComponent(ioc.value)}`
                          : `/sessions?has_iocs=true`
                      )}
                      title={ioc.ioc_type === "ip" ? `View sessions from ${ioc.value}` : "View sessions with IOCs"}
                    >
                      {ioc.session_count}
                    </button>
                  </td>
                  <td className="text-xs text-text-muted whitespace-nowrap">
                    {formatDateTime(ioc.first_seen_at)}
                  </td>
                  <td className="text-xs text-text-muted whitespace-nowrap">
                    {formatDateTime(ioc.last_seen_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-bg-border">
          <span className="text-xs text-text-muted">
            Showing {total === 0 ? 0 : page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total.toLocaleString()}
          </span>
          <div className="flex gap-2">
            <button
              disabled={page === 0}
              onClick={() => setPage((p) => p - 1)}
              className="btn-secondary text-xs px-3 py-1 disabled:opacity-40"
            >
              Previous
            </button>
            <button
              disabled={(page + 1) * PAGE_SIZE >= total}
              onClick={() => setPage((p) => p + 1)}
              className="btn-secondary text-xs px-3 py-1 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
