"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";
import { Filter, Download, RefreshCw, ChevronUp, ChevronDown } from "lucide-react";
import { SeverityBadge, SignalTierBadge, formatDateTime, formatDuration } from "@/components/ui";
import { apiPath } from "@/lib/api";

const SEVERITIES      = ["", "noise", "low", "medium", "high", "critical"];
const SIGNAL_TIERS    = ["", "noise", "recon", "suspicious", "impact"];
const PROTOCOLS       = ["", "s7comm", "modbus", "http", "https", "tcp"];
const TRIAGE_STATUSES = ["", "new", "investigating", "reviewed", "false_positive", "escalated"];

const TRIAGE_BADGE: Record<string, string> = {
  new:            "badge-medium",
  investigating:  "badge-noise",
  reviewed:       "badge-low",
  false_positive: "text-xs px-2 py-0.5 rounded-full bg-bg-elevated text-text-muted font-medium",
  escalated:      "badge-critical",
};

interface Filters {
  severity:      string;
  signal_tier:   string;
  protocol:      string;
  source_ip:     string;
  cpu_stop:      string;
  has_iocs:      string;
  is_actionable: string;
  from_dt:       string;
  to_dt:         string;
  triage_status: string;
}

const DEFAULT_FILTERS: Filters = {
  severity: "", signal_tier: "", protocol: "", source_ip: "",
  cpu_stop: "", has_iocs: "", is_actionable: "", from_dt: "", to_dt: "",
  triage_status: "",
};

type SortDir = "asc" | "desc";
const SORTABLE = ["severity", "event_count", "ioc_count", "duration_seconds", "started_at"];

export default function SessionsPage() {
  const router = useRouter();
  const [sessions,    setSessions]    = useState<any[]>([]);
  const [total,       setTotal]       = useState(0);
  const [page,        setPage]        = useState(0);
  const [loading,     setLoading]     = useState(false);
  const [filters,     setFilters]     = useState<Filters>(DEFAULT_FILTERS);
  const [showFilters, setShowFilters] = useState(false);
  const [sortBy,      setSortBy]      = useState("started_at");
  const [sortDir,     setSortDir]     = useState<SortDir>("desc");
  const [showExport,  setShowExport]  = useState(false);
  const exportRef = useRef<HTMLDivElement>(null);

  const PAGE_SIZE = 50;

  // Close export dropdown on outside click
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (exportRef.current && !exportRef.current.contains(e.target as Node)) setShowExport(false);
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  function toggleSort(col: string) {
    if (sortBy === col) {
      setSortDir((d) => d === "desc" ? "asc" : "desc");
    } else {
      setSortBy(col);
      setSortDir("desc");
    }
  }

  const loadSessions = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({
      limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE),
      sort_by: sortBy, sort_dir: sortDir,
    });
    Object.entries(filters).forEach(([k, v]) => { if (v) params.set(k, v); });

    try {
      const r = await fetch(apiPath(`/sessions?${params.toString()}`), { credentials: "include" });
      if (!r.ok) return;
      const d = await r.json();
      setSessions(d.items ?? []);
      setTotal(d.total ?? 0);
    } finally {
      setLoading(false);
    }
  }, [filters, page, sortBy, sortDir]);

  useEffect(() => { loadSessions(); }, [loadSessions]);

  // Reset page when filters/sort change
  useEffect(() => { setPage(0); }, [filters, sortBy, sortDir]);

  function exportCSV() {
    const params = new URLSearchParams({ columns: "id,source_ip,severity,signal_tier,primary_protocol,cpu_stop_occurred,ioc_count,event_count,started_at,updated_at" });
    if (filters.severity) params.set("severity", filters.severity);
    window.open(apiPath(`/sessions/export/csv?${params.toString()}`), "_blank", "noopener,noreferrer");
    setShowExport(false);
  }

  function exportJSON() {
    const params = new URLSearchParams();
    if (filters.severity) params.set("severity", filters.severity);
    window.open(apiPath(`/sessions/export/json?${params.toString()}`), "_blank", "noopener,noreferrer");
    setShowExport(false);
  }

  function setFilter(key: keyof Filters, val: string) {
    setFilters((f) => ({ ...f, [key]: val }));
  }

  return (
    <div className="p-6 space-y-4 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Sessions</h1>
          <p className="text-sm text-text-muted mt-0.5">
            {total.toLocaleString()} total sessions
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowFilters((s) => !s)} className="btn-secondary flex items-center gap-2">
            <Filter className="w-4 h-4" />
            Filters
            {Object.values(filters).some(Boolean) && (
              <span className="w-1.5 h-1.5 rounded-full bg-accent" />
            )}
          </button>
          <div className="relative" ref={exportRef}>
            <button onClick={() => setShowExport((s) => !s)} className="btn-secondary flex items-center gap-2">
              <Download className="w-4 h-4" />
              Export
              <ChevronDown className="w-3 h-3" />
            </button>
            {showExport && (
              <div className="absolute right-0 mt-1 w-36 bg-bg-surface border border-bg-border rounded-lg shadow-xl z-20 overflow-hidden">
                <button onClick={exportCSV} className="w-full text-left px-3 py-2 text-xs hover:bg-bg-elevated transition-colors">CSV</button>
                <button onClick={exportJSON} className="w-full text-left px-3 py-2 text-xs hover:bg-bg-elevated transition-colors">JSON</button>
              </div>
            )}
          </div>
          <button onClick={loadSessions} className="btn-secondary p-2">
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Filter panel */}
      {showFilters && (
        <div className="card p-4 grid grid-cols-2 md:grid-cols-4 gap-3 animate-slide-in">
          <div>
            <label>Severity</label>
            <select className="select" value={filters.severity} onChange={(e) => setFilter("severity", e.target.value)}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s || "All"}</option>)}
            </select>
          </div>
          <div>
            <label>Signal Tier</label>
            <select className="select" value={filters.signal_tier} onChange={(e) => setFilter("signal_tier", e.target.value)}>
              {SIGNAL_TIERS.map((s) => <option key={s} value={s}>{s || "All"}</option>)}
            </select>
          </div>
          <div>
            <label>Protocol</label>
            <select className="select" value={filters.protocol} onChange={(e) => setFilter("protocol", e.target.value)}>
              {PROTOCOLS.map((s) => <option key={s} value={s}>{s || "All"}</option>)}
            </select>
          </div>
          <div>
            <label>Source IP</label>
            <input type="text" className="input" placeholder="10.0.0.1"
              value={filters.source_ip} onChange={(e) => setFilter("source_ip", e.target.value)} />
          </div>
          <div>
            <label>CPU STOP</label>
            <select className="select" value={filters.cpu_stop} onChange={(e) => setFilter("cpu_stop", e.target.value)}>
              <option value="">All</option>
              <option value="true">Yes ⚡</option>
              <option value="false">No</option>
            </select>
          </div>
          <div>
            <label>Has IOCs</label>
            <select className="select" value={filters.has_iocs} onChange={(e) => setFilter("has_iocs", e.target.value)}>
              <option value="">All</option>
              <option value="true">Yes</option>
              <option value="false">No</option>
            </select>
          </div>
          <div>
            <label>Actionable</label>
            <select className="select" value={filters.is_actionable} onChange={(e) => setFilter("is_actionable", e.target.value)}>
              <option value="">All</option>
              <option value="true">Yes</option>
              <option value="false">No</option>
            </select>
          </div>
          <div>
            <label>Triage Status</label>
            <select className="select" value={filters.triage_status} onChange={(e) => setFilter("triage_status", e.target.value)}>
              {TRIAGE_STATUSES.map((s) => <option key={s} value={s}>{s ? s.replace(/_/g, " ") : "All"}</option>)}
            </select>
          </div>
          <div className="flex items-end">
            <button onClick={() => setFilters(DEFAULT_FILTERS)} className="btn-secondary w-full text-xs">
              Clear Filters
            </button>
          </div>
          <div>
            <label>From (UTC)</label>
            <input type="datetime-local" className="input" value={filters.from_dt}
              onChange={(e) => setFilter("from_dt", e.target.value)} />
          </div>
          <div>
            <label>To (UTC)</label>
            <input type="datetime-local" className="input" value={filters.to_dt}
              onChange={(e) => setFilter("to_dt", e.target.value)} />
          </div>
        </div>
      )}

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Source IP</th>
                {(["severity", "signal_tier", "protocol", "phase", "event_count", "ioc_count", "duration_seconds", "started_at"] as const).map((col) => {
                  const labels: Record<string, string> = {
                    severity: "Severity", signal_tier: "Signal Tier", protocol: "Protocol",
                    phase: "Phase", event_count: "Events", ioc_count: "IOCs",
                    duration_seconds: "Duration", started_at: "Started",
                  };
                  const sortable = SORTABLE.includes(col);
                  return (
                    <th key={col}
                      className={sortable ? "cursor-pointer select-none hover:text-text-primary" : ""}
                      onClick={sortable ? () => toggleSort(col) : undefined}
                    >
                      <span className="flex items-center gap-1">
                        {labels[col]}
                        {sortable && sortBy === col && (
                          sortDir === "desc" ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />
                        )}
                      </span>
                    </th>
                  );
                })}
                <th>Status</th>
                <th>Flags</th>
              </tr>
            </thead>
            <tbody>
              {loading && sessions.length === 0 ? (
                <tr><td colSpan={11} className="text-center text-text-faint py-12">Loading…</td></tr>
              ) : sessions.length === 0 ? (
                <tr><td colSpan={11} className="text-center text-text-faint py-12">No sessions match your filters</td></tr>
              ) : sessions.map((s) => (
                <tr key={s.id} onClick={() => router.push(`/sessions/${s.id}`)}>
                  <td className="font-mono text-xs">{s.source_ip}</td>
                  <td><SeverityBadge severity={s.severity} /></td>
                  <td><SignalTierBadge tier={s.signal_tier} /></td>
                  <td className="text-xs text-text-muted uppercase">{s.primary_protocol}</td>
                  <td className="text-xs text-text-muted">{s.attack_phase?.replace(/_/g, " ")}</td>
                  <td className="text-xs tabular-nums">{s.event_count}</td>
                  <td className="text-xs tabular-nums">{s.ioc_count > 0 ? <span className="text-accent">{s.ioc_count}</span> : "0"}</td>
                  <td className="text-xs text-text-muted">{formatDuration(s.duration_seconds)}</td>
                  <td className="text-xs text-text-muted whitespace-nowrap">{formatDateTime(s.started_at)}</td>
                  <td>
                    <span className={TRIAGE_BADGE[s.triage_status] ?? "badge-noise"}>
                      {(s.triage_status || "new").replace(/_/g, " ")}
                    </span>
                  </td>
                  <td className="text-xs">
                    {s.cpu_stop_occurred && <span title="CPU STOP" className="text-severity-critical mr-1">⚡</span>}
                    {s.has_iocs && <span title="Has IOCs" className="text-accent">●</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-bg-border">
          <span className="text-xs text-text-muted">
            Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total.toLocaleString()}
          </span>
          <div className="flex gap-2">
            <button disabled={page === 0} onClick={() => setPage((p) => p - 1)} className="btn-secondary text-xs px-3 py-1 disabled:opacity-40">
              Previous
            </button>
            <button disabled={(page + 1) * PAGE_SIZE >= total} onClick={() => setPage((p) => p + 1)} className="btn-secondary text-xs px-3 py-1 disabled:opacity-40">
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
