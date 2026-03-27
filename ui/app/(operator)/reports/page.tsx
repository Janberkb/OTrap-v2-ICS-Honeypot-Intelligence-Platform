"use client";

import { useEffect, useState } from "react";
import { apiPath } from "@/lib/api";
import { buildReportSummary, buildReportWindow, normalizeReportData } from "@/lib/report-utils";
import {
  FileDown, Plus, Trash2, Loader2, FileText,
  CheckSquare, Square, AlertTriangle,
} from "lucide-react";

// ─── Constants ────────────────────────────────────────────────────────────────

const RANGE_OPTIONS = [
  { value: 24,  label: "Last 24 Hours" },
  { value: 168, label: "Last 7 Days"   },
  { value: 720, label: "Last 30 Days"  },
];

// Dark-theme severity colours
const D_SEV_COLOR: Record<string, string> = {
  critical: "#f87171", high: "#fb923c", medium: "#fbbf24", low: "#4ade80", noise: "#a8a29e",
};
const D_SEV_BG: Record<string, string> = {
  critical: "#450a0a", high: "#431407", medium: "#422006", low: "#052e16", noise: "#1c1917",
};
const D_SEV_BORDER: Record<string, string> = {
  critical: "#7f1d1d", high: "#7c2d12", medium: "#78350f", low: "#14532d", noise: "#44403c",
};

// Protocol bar colours (readable on dark)
const D_PROTO_COLOR: Record<string, string> = {
  s7comm: "#60a5fa", s7: "#60a5fa", modbus: "#a78bfa",
  http: "#22d3ee", https: "#06b6d4", default: "#94a3b8",
};

const TRIAGE_LABEL: Record<string, string> = {
  new: "New", investigating: "Investigating", reviewed: "Reviewed",
  false_positive: "False Positive", escalated: "Escalated",
};

// Design tokens (matching app palette)
const C = {
  pageBg:    "#080c14",
  surface:   "#0f1623",
  elevated:  "#162032",
  border:    "#1e2d45",
  borderFaint: "#131f30",
  textPrimary: "#f0f4ff",
  textMuted:   "#94a3b8",
  textFaint:   "#4b5563",
  accent:      "#3b82f6",
  accentDim:   "#1d3a6e",
};

// ─── Types ────────────────────────────────────────────────────────────────────

interface ReportMeta {
  id: string; title: string; range_label: string;
  range_hours: number; generated_at: string;
}

// ─── Report Viewer Overlay ────────────────────────────────────────────────────

function ReportViewer({ reportId, onClose }: { reportId: string; onClose: () => void }) {
  const [data,    setData]    = useState<any>(null);
  const [title,   setTitle]   = useState("");
  const [range,   setRange]   = useState("");
  const [genDate, setGenDate] = useState("");
  const [loading,     setLoading]     = useState(true);
  const [error,       setError]       = useState("");
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    fetch(apiPath(`/reports/${reportId}`), { credentials: "include" })
      .then(r => { if (!r.ok) throw new Error("Report not found"); return r.json(); })
      .then(report => {
        setTitle(report.title);
        setRange(report.range_label);
        const d = normalizeReportData(report.data, report.generated_at);
        setData(d);
        setGenDate(new Date(d.generated_at).toLocaleString("en-GB", { dateStyle: "long", timeStyle: "short" }));
      })
      .catch(() => setError("Failed to load report"))
      .finally(() => setLoading(false));
  }, [reportId]);

  const sessions  = data?.sessions  ?? [];
  const attackers = data?.attackers ?? [];
  const histogram = data?.histogram ?? [];
  const iocs      = data?.iocs      ?? [];
  const stats     = data?.stats     ?? {};
  const protocols = stats?.protocols ?? [];
  const reportSummary = buildReportSummary({ stats, sessions, attackers, histogram, iocs });

  const totalEvents  = reportSummary.totalEvents;
  const criticalHigh = reportSummary.criticalHigh;
  const cpuStops     = reportSummary.cpuStops;

  const sevDist: Record<string, number> = {};
  sessions.forEach((s: any) => { sevDist[s.severity] = (sevDist[s.severity] ?? 0) + 1; });

  const techniqueMap = new Map<string, { id: string; name: string; tactic: string; count: number }>();
  sessions.forEach((s: any) =>
    (s.mitre_techniques ?? []).forEach((t: any) => {
      if (techniqueMap.has(t.technique_id)) techniqueMap.get(t.technique_id)!.count++;
      else techniqueMap.set(t.technique_id, { id: t.technique_id, name: t.technique_name, tactic: t.tactic, count: 1 });
    })
  );
  const techniques = [...techniqueMap.values()].sort((a, b) => b.count - a.count);

  async function handleDownload() {
    setDownloading(true);
    try {
      const { pdf }      = await import("@react-pdf/renderer");
      const { buildPDF } = await import("./ReportPDF");
      const blob = await pdf(buildPDF({ data, title, rangeLabel: range, genDate })).toBlob();
      const url = URL.createObjectURL(blob);
      const a   = document.createElement("a");
      a.href     = url;
      a.download = `${title.replace(/[^a-z0-9\s-]/gi, "").trim().replace(/\s+/g, "_") || "report"}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 100);
    } catch (e) {
      console.error("PDF generation failed", e);
    } finally {
      setDownloading(false);
    }
  }

  return (
    <>
      <style>{`
        * { box-sizing: border-box; }
        body, html { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; }
        .r-table-row-even { background: ${C.surface}; }
        .r-table-row-odd  { background: #111827; }
      `}</style>

      <div className="report-print-area" style={{
        position: "fixed", inset: 0, zIndex: 9999,
        overflowY: "auto", background: C.pageBg,
      }}>

        {/* ── Action bar (no-print) ─────────────────────────────────────── */}
        <div className="no-print" style={{
          position: "sticky", top: 0, zIndex: 10,
          background: "#060a12", borderBottom: `1px solid ${C.border}`,
          padding: "9px 24px", display: "flex", alignItems: "center", gap: 12,
        }}>
          <div style={{ color: C.accent, fontWeight: 700, fontSize: 14 }}>OTrap Reports</div>
          {title && (
            <>
              <div style={{ width: 1, height: 18, background: C.border }} />
              <span style={{ fontSize: 12, color: C.textPrimary, maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{title}</span>
              {range && <span style={{ fontSize: 11, color: C.textFaint, flexShrink: 0 }}>{range}</span>}
            </>
          )}

          <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
            <button onClick={handleDownload} disabled={loading || !!error || downloading}
              style={{ display: "flex", alignItems: "center", gap: 6, background: C.accent, color: "white", border: "none", borderRadius: 6, padding: "7px 16px", fontSize: 13, cursor: (loading || !!error || downloading) ? "not-allowed" : "pointer", fontWeight: 600, opacity: (loading || !!error || downloading) ? 0.5 : 1 }}>
              {downloading ? "Generating…" : "↓ Download PDF"}
            </button>
            <button onClick={onClose}
              style={{ display: "flex", alignItems: "center", gap: 5, background: C.elevated, color: C.textMuted, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 14px", fontSize: 13, cursor: "pointer" }}>
              ✕ Close
            </button>
          </div>
        </div>

        {/* ── Report body ───────────────────────────────────────────────── */}
        <div style={{ maxWidth: 1080, margin: "0 auto", padding: "28px 24px", background: C.pageBg, color: C.textPrimary }}>

          {loading && (
            <div style={{ textAlign: "center", padding: "80px 0", color: C.textMuted, fontSize: 14 }}>Loading report…</div>
          )}
          {error && (
            <div style={{ textAlign: "center", padding: "80px 0", color: D_SEV_COLOR.critical, fontSize: 14 }}>{error}</div>
          )}

          {!loading && !error && data && (
            <>
              {/* ═══ HEADER ══════════════════════════════════════════════ */}
              <div style={{ background: C.surface, borderLeft: `4px solid ${C.accent}`, borderRadius: "0 8px 8px 0", padding: "20px 24px", marginBottom: 28, display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
                    <div style={{ width: 34, height: 34, background: C.accent, borderRadius: 7, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                      <span style={{ color: "white", fontSize: 17, fontWeight: 900, lineHeight: 1 }}>⬡</span>
                    </div>
                    <div>
                      <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                        <span style={{ fontSize: 20, fontWeight: 800, color: C.textPrimary, letterSpacing: -0.5 }}>OTrap</span>
                        <span style={{ fontSize: 10, fontWeight: 600, color: C.textFaint, letterSpacing: 1.5, textTransform: "uppercase" }}>v2.0</span>
                      </div>
                      <div style={{ fontSize: 12, color: C.textMuted, marginTop: 1 }}>OT / ICS Deception Platform — Security Incident Report</div>
                    </div>
                  </div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: C.textPrimary, paddingLeft: 46 }}>{title}</div>
                </div>
                <div style={{ textAlign: "right", flexShrink: 0, marginLeft: 24 }}>
                  <div style={{ display: "inline-block", background: "#3d2a00", border: "1px solid #92400e", borderRadius: 5, padding: "3px 10px", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1.2, color: "#fbbf24", marginBottom: 10 }}>
                    CONFIDENTIAL
                  </div>
                  <div style={{ fontSize: 12, color: C.textMuted, lineHeight: 1.8 }}>
                    <div><span style={{ color: C.textFaint }}>Period:</span> {range}</div>
                    <div><span style={{ color: C.textFaint }}>Generated:</span> {genDate}</div>
                    <div><span style={{ color: C.textFaint }}>Sessions:</span> {sessions.length}</div>
                  </div>
                </div>
              </div>

              {/* ═══ EXECUTIVE SUMMARY ═══════════════════════════════════ */}
              <div className="r-no-break" style={{ marginBottom: 28 }}>
                <DSectionTitle>Executive Summary</DSectionTitle>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10, marginBottom: 10 }}>
                  <DKpiCard label="Total Sessions"      value={sessions.length}                              accent={C.accent} />
                  <DKpiCard label="Unique Attackers"    value={attackers.length}                             accent="#a78bfa" />
                  <DKpiCard label="Events Recorded"     value={totalEvents}                                  accent="#22d3ee" />
                  <DKpiCard label="Critical / High"     value={criticalHigh}    alert={criticalHigh > 0}     accent={D_SEV_COLOR.critical} />
                  <DKpiCard label="CPU Stop Events"     value={cpuStops}        alert={cpuStops > 0}         accent={D_SEV_COLOR.critical} />
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
                  <DKpiCard label="IOCs Identified"     value={iocs.length}                                  accent="#4ade80" />
                  <DKpiCard label="Actionable Sessions" value={reportSummary.actionableSessions}            accent="#fbbf24" />
                  <DKpiCard label="External Countries"  value={reportSummary.externalCountryCount}          accent="#22d3ee" />
                </div>
              </div>

              {/* ═══ OPERATOR CONTEXT ═══════════════════════════════════ */}
              <div className="r-no-break" style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr 1fr", gap: 16, marginBottom: 28 }}>
                <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px" }}>
                  <DChartTitle>Operator Focus</DChartTitle>
                  <div style={{ display: "grid", gap: 10 }}>
                    {reportSummary.impactSummary.map((line, index) => (
                      <div key={index} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                        <span style={{ width: 18, height: 18, borderRadius: 999, background: C.accentDim, color: "#93c5fd", display: "inline-flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, flexShrink: 0 }}>{index + 1}</span>
                        <span style={{ fontSize: 12, lineHeight: 1.6, color: C.textMuted }}>{line}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px" }}>
                  <DChartTitle>Top Findings</DChartTitle>
                  {reportSummary.topFindings.length === 0 ? (
                    <p style={{ fontSize: 12, color: C.textFaint }}>No sessions recorded in this period.</p>
                  ) : (
                    <div style={{ display: "grid", gap: 10 }}>
                      {reportSummary.topFindings.map((session: any) => {
                        const severity = String(session.severity ?? "noise").toLowerCase();
                        return (
                          <div key={session.id} style={{ display: "grid", gap: 4, paddingBottom: 10, borderBottom: `1px solid ${C.borderFaint}` }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                              <DSevBadge sev={session.severity} />
                              <span style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 11, color: C.textPrimary }}>{session.source_ip}</span>
                            </div>
                            <div style={{ fontSize: 11, color: C.textMuted, lineHeight: 1.5 }}>
                              {session.primary_protocol?.toUpperCase() ?? "UNKNOWN"} · {session.event_count ?? 0} events · {session.ioc_count ?? 0} IOCs
                              {session.cpu_stop_occurred && <span style={{ color: D_SEV_COLOR[severity] ?? D_SEV_COLOR.critical }}> · CPU STOP</span>}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
                <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px" }}>
                  <DChartTitle>Recommended Actions</DChartTitle>
                  <div style={{ display: "grid", gap: 10 }}>
                    {reportSummary.recommendations.map((line, index) => (
                      <div key={index} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                        <span style={{ width: 18, height: 18, borderRadius: 999, background: C.accentDim, color: "#93c5fd", display: "inline-flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, flexShrink: 0 }}>{index + 1}</span>
                        <span style={{ fontSize: 12, lineHeight: 1.6, color: C.textMuted }}>{line}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* ═══ SEVERITY + PROTOCOL ═════════════════════════════════ */}
              <div className="r-no-break" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 28 }}>
                {/* Severity */}
                <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px" }}>
                  <DChartTitle>Severity Distribution</DChartTitle>
                  {["critical","high","medium","low","noise"].map(sev => {
                    const count = sevDist[sev] ?? 0;
                    const pct = sessions.length > 0 ? (count / sessions.length) * 100 : 0;
                    return (
                      <div key={sev} style={{ marginBottom: 10 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                          <span style={{ fontSize: 11, fontWeight: 700, color: D_SEV_COLOR[sev], textTransform: "uppercase", letterSpacing: 0.5 }}>{sev}</span>
                          <span style={{ fontSize: 11, color: C.textFaint }}>{count} <span style={{ opacity: 0.6 }}>({pct.toFixed(0)}%)</span></span>
                        </div>
                        <div style={{ height: 7, background: C.border, borderRadius: 4, overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${pct}%`, background: D_SEV_COLOR[sev], borderRadius: 4, opacity: 0.85 }} />
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Protocol */}
                <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px" }}>
                  <DChartTitle>Protocol Distribution</DChartTitle>
                  {protocols.length === 0 ? (
                    <p style={{ fontSize: 12, color: C.textFaint }}>No protocol data available</p>
                  ) : (() => {
                    const total = protocols.reduce((s: number, p: any) => s + p.count, 0);
                    return protocols.map((p: any) => {
                      const pct = total > 0 ? (p.count / total) * 100 : 0;
                      const col = D_PROTO_COLOR[p.protocol] ?? D_PROTO_COLOR.default;
                      return (
                        <div key={p.protocol} style={{ marginBottom: 10 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                            <span style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: col }}>{p.protocol}</span>
                            <span style={{ fontSize: 11, color: C.textFaint }}>{p.count} <span style={{ opacity: 0.6 }}>({pct.toFixed(0)}%)</span></span>
                          </div>
                          <div style={{ height: 7, background: C.border, borderRadius: 4, overflow: "hidden" }}>
                            <div style={{ height: "100%", width: `${pct}%`, background: col, borderRadius: 4, opacity: 0.8 }} />
                          </div>
                        </div>
                      );
                    });
                  })()}
                </div>
              </div>

              {/* ═══ EVENT TIMELINE ══════════════════════════════════════ */}
              {histogram.length > 0 && (
                <div className="r-no-break" style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "16px 20px", marginBottom: 28 }}>
                  <DChartTitle>Event Timeline — {histogram.length > 24 ? "7-Day" : "24-Hour"} Activity &nbsp;<span style={{ fontWeight: 400, color: C.textFaint }}>({totalEvents} total events)</span></DChartTitle>
                  <DEventBarChart buckets={histogram} />
                </div>
              )}

              {/* ═══ TOP ATTACK SOURCES ══════════════════════════════════ */}
              {attackers.length > 0 && (
                <div style={{ marginBottom: 28 }}>
                  <DSectionTitle>Top Attack Sources</DSectionTitle>
                  <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
                    <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
                      <thead>
                        <tr style={{ background: C.elevated }}>
                          <DTH>#</DTH><DTH>Source IP</DTH><DTH>Country</DTH><DTH>Organisation</DTH>
                          <DTH align="right">Events</DTH><DTH align="right">Sessions</DTH>
                          <DTH>Max Sev.</DTH><DTH>CPU Stop</DTH><DTH>Last Seen</DTH>
                        </tr>
                      </thead>
                      <tbody>
                        {attackers.map((a: any, i: number) => (
                          <tr key={a.source_ip} className={i % 2 === 0 ? "r-table-row-even" : "r-table-row-odd"}>
                            <DTD style={{ color: C.textFaint }}>{i + 1}</DTD>
                            <DTD mono>{a.source_ip}</DTD>
                            <DTD>{[a.flag, a.country_name].filter(Boolean).join(" ") || "—"}</DTD>
                            <DTD style={{ color: C.textMuted }}>{a.org ?? "—"}</DTD>
                            <DTD align="right"><strong style={{ color: C.textPrimary }}>{a.event_count}</strong></DTD>
                            <DTD align="right">{a.session_count}</DTD>
                            <DTD><DSevBadge sev={a.max_severity} /></DTD>
                            <DTD>{a.cpu_stop_ever ? <span style={{ color: D_SEV_COLOR.critical, fontWeight: 700 }}>YES</span> : <span style={{ color: C.textFaint }}>—</span>}</DTD>
                            <DTD style={{ color: C.textMuted }}>{a.last_seen ? rfmt(a.last_seen) : "—"}</DTD>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* ═══ SESSION INVENTORY ═══════════════════════════════════ */}
              <div className="r-page-break" style={{ marginBottom: 28 }}>
                <DSectionTitle>Session Inventory <span style={{ fontWeight: 400, color: C.textFaint, fontSize: 11 }}>({sessions.length} sessions)</span></DSectionTitle>
                <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
                  <table style={{ width: "100%", fontSize: 10.5, borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ background: C.elevated }}>
                        <DTH>Source IP</DTH><DTH>Protocol</DTH><DTH>Severity</DTH><DTH>Signal Tier</DTH>
                        <DTH align="right">Events</DTH><DTH align="right">IOCs</DTH>
                        <DTH>Triage</DTH><DTH>CPU Stop</DTH><DTH>Started</DTH><DTH align="right">Duration</DTH>
                      </tr>
                    </thead>
                    <tbody>
                      {sessions.map((s: any, i: number) => (
                        <tr key={s.id} className={i % 2 === 0 ? "r-table-row-even" : "r-table-row-odd"}>
                          <DTD mono>{s.source_ip}</DTD>
                          <DTD style={{ textTransform: "uppercase", fontWeight: 700, color: D_PROTO_COLOR[s.primary_protocol ?? ""] ?? C.textMuted, fontSize: 10 }}>
                            {s.primary_protocol ?? "—"}
                          </DTD>
                          <DTD><DSevBadge sev={s.severity} /></DTD>
                          <DTD style={{ color: C.textFaint, fontStyle: "italic" }}>{s.signal_tier ?? "—"}</DTD>
                          <DTD align="right">{s.event_count}</DTD>
                          <DTD align="right">{s.ioc_count}</DTD>
                          <DTD style={{ color: C.textMuted }}>{TRIAGE_LABEL[s.triage_status] ?? s.triage_status}</DTD>
                          <DTD>{s.cpu_stop_occurred ? <span style={{ color: D_SEV_COLOR.critical, fontWeight: 700 }}>YES</span> : <span style={{ color: C.textFaint }}>—</span>}</DTD>
                          <DTD style={{ color: C.textMuted }}>{s.started_at ? rfmt(s.started_at) : "—"}</DTD>
                          <DTD align="right" style={{ color: C.textMuted }}>{s.duration_seconds != null ? `${s.duration_seconds.toFixed(1)}s` : "—"}</DTD>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* ═══ IOC TABLE ═══════════════════════════════════════════ */}
              {iocs.length > 0 && (
                <div className="r-page-break" style={{ marginBottom: 28 }}>
                  <DSectionTitle>Indicators of Compromise <span style={{ fontWeight: 400, color: C.textFaint, fontSize: 11 }}>({iocs.length} IOCs)</span></DSectionTitle>
                  {reportSummary.redactedIndicatorCount > 0 && (
                    <div style={{ marginBottom: 10, padding: "10px 12px", borderRadius: 7, background: "#111827", border: `1px solid ${C.border}`, fontSize: 11, color: C.textMuted }}>
                      Credential indicators are intentionally redacted in reports and PDF exports.
                    </div>
                  )}
                  <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
                    <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
                      <thead>
                        <tr style={{ background: C.elevated }}>
                          <DTH>Type</DTH><DTH>Value</DTH><DTH align="right">Confidence</DTH>
                          <DTH align="right">Sessions</DTH><DTH>First Seen</DTH><DTH>Last Seen</DTH>
                        </tr>
                      </thead>
                      <tbody>
                        {iocs.map((ioc: any, i: number) => (
                          <tr key={`${ioc.ioc_type}:${ioc.value}`} className={i % 2 === 0 ? "r-table-row-even" : "r-table-row-odd"}>
                            <DTD>
                              <span style={{ background: C.accentDim, color: "#93c5fd", fontSize: 10, fontWeight: 700, textTransform: "uppercase", padding: "2px 7px", borderRadius: 4, letterSpacing: 0.5 }}>
                                {ioc.ioc_type}
                              </span>
                            </DTD>
                            <DTD mono>{ioc.value}</DTD>
                            <DTD align="right"><DConfidenceBar pct={Math.round((ioc.confidence ?? 0) * 100)} /></DTD>
                            <DTD align="right">{ioc.session_count}</DTD>
                            <DTD style={{ color: C.textMuted }}>{ioc.first_seen_at ? rfmt(ioc.first_seen_at) : "—"}</DTD>
                            <DTD style={{ color: C.textMuted }}>{ioc.last_seen_at  ? rfmt(ioc.last_seen_at)  : "—"}</DTD>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* ═══ MITRE ATT&CK ════════════════════════════════════════ */}
              {techniques.length > 0 && (
                <div className="r-no-break" style={{ marginBottom: 28 }}>
                  <DSectionTitle>MITRE ATT&CK for ICS — Observed Techniques</DSectionTitle>
                  <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
                    <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
                      <thead>
                        <tr style={{ background: C.elevated }}>
                          <DTH>Technique ID</DTH><DTH>Technique Name</DTH><DTH>Tactic</DTH><DTH align="right">Occurrences</DTH>
                        </tr>
                      </thead>
                      <tbody>
                        {techniques.map((t, i) => (
                          <tr key={t.id} className={i % 2 === 0 ? "r-table-row-even" : "r-table-row-odd"}>
                            <DTD mono>
                              <span style={{ background: "#3d2b00", color: "#fbbf24", fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4 }}>{t.id}</span>
                            </DTD>
                            <DTD>{t.name}</DTD>
                            <DTD style={{ color: C.textFaint }}>{t.tactic}</DTD>
                            <DTD align="right"><strong>{t.count}</strong></DTD>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* ═══ GEOGRAPHIC DISTRIBUTION ═════════════════════════════ */}
              {(stats?.top_countries?.length ?? 0) > 0 && (
                <div className="r-no-break" style={{ marginBottom: 28 }}>
                  <DSectionTitle>Geographic Distribution</DSectionTitle>
                  {reportSummary.hasPrivateCountryTraffic && (
                    <div style={{ marginBottom: 10, padding: "10px 12px", borderRadius: 7, background: "#111827", border: `1px solid ${C.border}`, fontSize: 11, color: C.textMuted }}>
                      Private-network traffic is shown separately and excluded from the external country KPI.
                    </div>
                  )}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
                    {stats.top_countries.map((c: any) => (
                      <div key={c.country_code} style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 7, padding: "10px 14px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: 12, color: C.textPrimary }}>{[c.flag, c.country_name].filter(Boolean).join(" ") || c.country_code}</span>
                        <span style={{ fontSize: 15, fontWeight: 800, color: C.accent }}>{c.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ═══ FOOTER ══════════════════════════════════════════════ */}
              <div style={{ marginTop: 40, borderTop: `1px solid ${C.border}`, paddingTop: 14, display: "flex", justifyContent: "space-between", fontSize: 10, color: C.textFaint, background: C.surface, margin: "40px -24px -28px", padding: "14px 24px" }}>
                <div>
                  <strong style={{ color: C.textMuted }}>OTrap v2.0</strong> — Enterprise OT/ICS Deception Platform
                  &nbsp;·&nbsp; {range} &nbsp;·&nbsp; Generated {genDate}
                </div>
                <div style={{ color: "#fbbf24", fontWeight: 600 }}>CONFIDENTIAL — Internal Use Only</div>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
}

// ─── Dark-theme helper components ─────────────────────────────────────────────

function DSectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
      <div style={{ width: 3, height: 16, background: C.accent, borderRadius: 2, flexShrink: 0 }} />
      <h3 style={{ margin: 0, fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1.2, color: C.textMuted }}>
        {children}
      </h3>
      <div style={{ flex: 1, height: 1, background: C.border }} />
    </div>
  );
}
function DChartTitle({ children }: { children: React.ReactNode }) {
  return <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: C.textMuted, marginBottom: 14 }}>{children}</div>;
}
function DKpiCard({ label, value, accent, alert }: { label: string; value: number; accent: string; alert?: boolean }) {
  const alertBg     = "#1a0808";
  const alertBorder = "#7f1d1d";
  return (
    <div style={{ background: alert && value > 0 ? alertBg : C.elevated, border: `1px solid ${alert && value > 0 ? alertBorder : C.border}`, borderRadius: 8, padding: "14px 16px" }}>
      <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: 0.9, color: C.textFaint, marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 800, color: accent, lineHeight: 1 }}>{value}</div>
    </div>
  );
}
function DTH({ children, align }: { children?: React.ReactNode; align?: string }) {
  return <th style={{ textAlign: (align as any) ?? "left", padding: "9px 12px", fontSize: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.7, color: C.textFaint, borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap" }}>{children}</th>;
}
function DTD({ children, mono, align, style }: { children?: React.ReactNode; mono?: boolean; align?: string; style?: React.CSSProperties }) {
  return <td style={{ padding: "7px 12px", borderBottom: `1px solid ${C.borderFaint}`, fontFamily: mono ? "'Courier New', monospace" : "inherit", textAlign: (align as any) ?? "left", fontSize: 11, color: C.textPrimary, ...style }}>{children}</td>;
}
function DSevBadge({ sev }: { sev: string }) {
  if (!sev) return <span style={{ color: C.textFaint }}>—</span>;
  const s = sev.toLowerCase();
  return (
    <span style={{ display: "inline-block", background: D_SEV_BG[s] ?? C.elevated, color: D_SEV_COLOR[s] ?? C.textMuted, border: `1px solid ${D_SEV_BORDER[s] ?? C.border}`, fontWeight: 700, fontSize: 10, textTransform: "uppercase", padding: "2px 7px", borderRadius: 10 }}>
      {sev}
    </span>
  );
}
function DConfidenceBar({ pct }: { pct: number }) {
  const color = pct >= 90 ? D_SEV_COLOR.critical : pct >= 70 ? D_SEV_COLOR.medium : C.textFaint;
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 6 }}>
      <div style={{ width: 52, height: 6, background: C.border, borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontSize: 10, color, fontWeight: 600, minWidth: 30, textAlign: "right" }}>{pct}%</span>
    </div>
  );
}
function DEventBarChart({ buckets }: { buckets: { hour: string; count: number }[] }) {
  const max = Math.max(...buckets.map(b => b.count), 1);
  const W = 960, H = 150;
  const pad = { top: 10, right: 16, bottom: 30, left: 38 };
  const cW = W - pad.left - pad.right, cH = H - pad.top - pad.bottom;
  const bW = Math.max(2, (cW / buckets.length) - 2);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: "auto", display: "block" }}>
      {[0, 0.25, 0.5, 0.75, 1].map(t => {
        const y = pad.top + cH * (1 - t);
        return (
          <g key={t}>
            <line x1={pad.left} y1={y} x2={pad.left + cW} y2={y} stroke={C.border} strokeWidth={1} />
            <text x={pad.left - 5} y={y + 3.5} textAnchor="end" fontSize={8} fill={C.textFaint}>{Math.round(max * t)}</text>
          </g>
        );
      })}
      {buckets.map((b, i) => {
        const bH = Math.max(0, (b.count / max) * cH);
        const x = pad.left + (i / buckets.length) * cW;
        const y = pad.top + cH - bH;
        const fill = b.count > max * 0.7 ? D_SEV_COLOR.critical : b.count > max * 0.4 ? D_SEV_COLOR.high : C.accent;
        const showLabel = buckets.length <= 24 || i % Math.ceil(buckets.length / 24) === 0;
        return (
          <g key={i}>
            <rect x={x + 1} y={y} width={bW} height={bH} fill={fill} opacity={0.8} rx={1.5} />
            {showLabel && <text x={x + bW / 2 + 1} y={H - 6} textAnchor="middle" fontSize={7.5} fill={C.textFaint}>{b.hour}</text>}
          </g>
        );
      })}
      <line x1={pad.left} y1={pad.top} x2={pad.left} y2={pad.top + cH} stroke={C.border} strokeWidth={1} />
      <line x1={pad.left} y1={pad.top + cH} x2={pad.left + cW} y2={pad.top + cH} stroke={C.border} strokeWidth={1} />
    </svg>
  );
}
function rfmt(iso: string): string {
  try { return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }); }
  catch { return iso; }
}

// ─── Reports List Page ────────────────────────────────────────────────────────

export default function ReportsPage() {
  const [reports,     setReports]     = useState<ReportMeta[]>([]);
  const [loading,     setLoading]     = useState(true);
  const [error,       setError]       = useState("");
  const [selected,    setSelected]    = useState<Set<string>>(new Set());
  const [showModal,   setShowModal]   = useState(false);
  const [generating,  setGenerating]  = useState(false);
  const [genError,    setGenError]    = useState("");
  const [genProgress, setGenProgress] = useState("");
  const [deleting,    setDeleting]    = useState<string | null>(null);
  const [bulkDel,     setBulkDel]     = useState(false);
  const [title,       setTitle]       = useState("");
  const [rangeHours,  setRangeHours]  = useState(168);
  const [viewingId,   setViewingId]   = useState<string | null>(null);

  async function fetchList() {
    try {
      const r = await fetch(apiPath("/reports"), { credentials: "include" });
      if (!r.ok) throw new Error();
      setReports((await r.json()).items ?? []);
    } catch { setError("Failed to load reports"); }
    finally  { setLoading(false); }
  }
  useEffect(() => { void fetchList(); }, []);

  function openModal() {
    const opt     = RANGE_OPTIONS.find(o => o.value === rangeHours)!;
    const dateStr = new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
    setTitle(`OTrap Security Report — ${opt.label} — ${dateStr}`);
    setGenError(""); setGenProgress(""); setShowModal(true);
  }

  async function generateReport() {
    setGenerating(true); setGenError("");
    const opt       = RANGE_OPTIONS.find(o => o.value === rangeHours)!;
    const histHours = Math.min(rangeHours, 168);
    const { from, to } = buildReportWindow(rangeHours);
    try {
      setGenProgress("Fetching session data…");
      const sessionParams = new URLSearchParams({
        limit: "200",
        sort_by: "started_at",
        sort_dir: "desc",
        from_dt: from,
        to_dt: to,
      });
      const iocParams = new URLSearchParams({
        limit: "100",
        from_dt: from,
        to_dt: to,
      });
      const [sRes, sessRes, atkRes, histRes, iocRes] = await Promise.all([
        fetch(apiPath(`/sessions/stats?hours=${rangeHours}`),                { credentials: "include" }),
        fetch(apiPath(`/sessions?${sessionParams.toString()}`),              { credentials: "include" }),
        fetch(apiPath(`/events/top-attackers?hours=${rangeHours}&limit=25`), { credentials: "include" }),
        fetch(apiPath(`/events/histogram?hours=${histHours}`),               { credentials: "include" }),
        fetch(apiPath(`/iocs?${iocParams.toString()}`),                      { credentials: "include" }),
      ]);
      const [statsData, sessData, atkData, histData, iocData] = await Promise.all([
        sRes.ok    ? sRes.json()    : {},
        sessRes.ok ? sessRes.json() : { items: [] },
        atkRes.ok  ? atkRes.json()  : { items: [] },
        histRes.ok ? histRes.json() : { buckets: [] },
        iocRes.ok  ? iocRes.json()  : { items: [] },
      ]);
      setGenProgress("Saving report…");
      const snapshot = normalizeReportData({
        stats: statsData, sessions: sessData.items ?? [], attackers: atkData.items ?? [],
        histogram: histData.buckets ?? [], iocs: iocData.items ?? [],
        generated_at: new Date().toISOString(),
      });
      const saveRes = await fetch(apiPath("/reports"), {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: title.trim() || `OTrap Report — ${opt.label}`, range_label: opt.label, range_hours: rangeHours, data: snapshot }),
      });
      if (!saveRes.ok) { const d = await saveRes.json().catch(() => ({})); throw new Error(d?.detail ?? "Failed to save"); }
      setShowModal(false); setGenProgress("");
      await fetchList();
    } catch (e: any) { setGenError(e?.message ?? "An error occurred"); }
    finally { setGenerating(false); }
  }

  async function deleteOne(id: string) {
    setDeleting(id);
    try {
      await fetch(apiPath(`/reports/${id}`), { method: "DELETE", credentials: "include" });
      setReports(prev => prev.filter(r => r.id !== id));
      setSelected(prev => { const s = new Set(prev); s.delete(id); return s; });
    } finally { setDeleting(null); }
  }

  async function bulkDelete() {
    if (!selected.size) return;
    setBulkDel(true);
    try {
      await fetch(apiPath("/reports/bulk-delete"), {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: [...selected] }),
      });
      setReports(prev => prev.filter(r => !selected.has(r.id)));
      setSelected(new Set());
    } finally { setBulkDel(false); }
  }

  function toggleAll() {
    setSelected(selected.size === reports.length ? new Set() : new Set(reports.map(r => r.id)));
  }
  function toggleOne(id: string) {
    setSelected(prev => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s; });
  }

  const allSelected  = reports.length > 0 && selected.size === reports.length;
  const someSelected = selected.size > 0 && !allSelected;

  return (
    <>
      {viewingId && <ReportViewer reportId={viewingId} onClose={() => setViewingId(null)} />}

      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold text-text-primary flex items-center gap-2">
              <FileDown className="w-5 h-5 text-accent" />Reports
            </h1>
            <p className="text-xs text-text-muted mt-0.5">Generate and manage security incident reports</p>
          </div>
          <button onClick={openModal} className="btn-primary flex items-center gap-2 text-sm">
            <Plus className="w-4 h-4" />Generate Report
          </button>
        </div>

        {selected.size > 0 && (
          <div className="flex items-center gap-3 px-4 py-2.5 rounded-lg bg-accent/10 border border-accent/20">
            <span className="text-sm font-medium text-text-primary">{selected.size} selected</span>
            <div className="flex-1" />
            <button onClick={bulkDelete} disabled={bulkDel}
              className="flex items-center gap-1.5 text-sm text-severity-critical hover:text-red-400 font-medium disabled:opacity-50">
              {bulkDel ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
              Delete Selected
            </button>
          </div>
        )}

        <div className="card overflow-hidden">
          {loading ? (
            <div className="flex items-center justify-center py-16 gap-2 text-text-muted">
              <Loader2 className="w-5 h-5 animate-spin" /><span className="text-sm">Loading reports…</span>
            </div>
          ) : error ? (
            <div className="flex items-center justify-center py-16 gap-2 text-severity-critical">
              <AlertTriangle className="w-5 h-5" /><span className="text-sm">{error}</span>
            </div>
          ) : reports.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 gap-3">
              <FileText className="w-10 h-10 text-text-faint" />
              <div className="text-center">
                <p className="text-sm font-medium text-text-primary">No reports yet</p>
                <p className="text-xs text-text-muted mt-1">Click "Generate Report" to create your first security report</p>
              </div>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-bg-border bg-bg-elevated">
                  <th className="w-10 px-4 py-3">
                    <button onClick={toggleAll} className="text-text-faint hover:text-accent transition-colors">
                      {allSelected ? <CheckSquare className="w-4 h-4 text-accent" /> : someSelected ? <CheckSquare className="w-4 h-4 text-accent opacity-50" /> : <Square className="w-4 h-4" />}
                    </button>
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Title</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Range</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-text-muted uppercase tracking-wide">Generated</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold text-text-muted uppercase tracking-wide">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-bg-border">
                {reports.map(r => (
                  <tr key={r.id} className={`hover:bg-bg-elevated/50 transition-colors ${selected.has(r.id) ? "bg-accent/5" : ""}`}>
                    <td className="px-4 py-3">
                      <button onClick={() => toggleOne(r.id)} className="text-text-faint hover:text-accent transition-colors">
                        {selected.has(r.id) ? <CheckSquare className="w-4 h-4 text-accent" /> : <Square className="w-4 h-4" />}
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <FileText className="w-4 h-4 text-text-faint flex-shrink-0" />
                        <span className="font-medium text-text-primary">{r.title}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-accent/10 text-accent border border-accent/20">
                        {r.range_label}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-text-muted text-xs font-mono">{rfmt(r.generated_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <button onClick={() => setViewingId(r.id)}
                          className="flex items-center gap-1.5 text-xs text-accent hover:text-accent/80 font-medium transition-colors px-2 py-1 rounded border border-accent/20 hover:bg-accent/10">
                          <FileDown className="w-3.5 h-3.5" />View / Download
                        </button>
                        <button onClick={() => void deleteOne(r.id)} disabled={deleting === r.id}
                          className="p-1.5 text-text-faint hover:text-severity-critical transition-colors disabled:opacity-40" title="Delete">
                          {deleting === r.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-bg-surface border border-bg-border rounded-xl p-6 w-full max-w-md shadow-xl">
            <div className="flex items-center gap-2 mb-5">
              <div className="p-2 rounded-lg bg-accent/10 border border-accent/20">
                <FileDown className="w-4 h-4 text-accent" />
              </div>
              <h2 className="font-semibold text-sm text-text-primary">Generate Security Report</h2>
            </div>
            <div className="space-y-4">
              <div>
                <label className="text-xs text-text-muted block mb-1.5">Report Title</label>
                <input type="text" className="input w-full" value={title}
                  onChange={e => setTitle(e.target.value)} disabled={generating} />
              </div>
              <div>
                <label className="text-xs text-text-muted block mb-1.5">Time Range</label>
                <div className="grid grid-cols-3 gap-2">
                  {RANGE_OPTIONS.map(opt => (
                    <button key={opt.value} onClick={() => {
                      setRangeHours(opt.value);
                      const dateStr = new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
                      setTitle(`OTrap Security Report — ${opt.label} — ${dateStr}`);
                    }} disabled={generating}
                      className={`py-2 px-3 rounded-lg text-xs font-medium border transition-colors ${rangeHours === opt.value ? "bg-accent text-white border-accent" : "bg-bg-elevated text-text-muted border-bg-border hover:border-accent/40 hover:text-text-primary"}`}>
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>
              <div className="rounded-lg bg-bg-elevated border border-bg-border px-4 py-3 text-xs text-text-muted space-y-1">
                <p className="font-medium text-text-primary">Report will include:</p>
                <ul className="space-y-0.5 list-disc list-inside">
                  <li>Executive summary with KPIs</li>
                  <li>Severity &amp; protocol distribution</li>
                  <li>Event timeline chart</li>
                  <li>Top attack sources &amp; session inventory</li>
                  <li>IOCs &amp; MITRE ATT&amp;CK techniques</li>
                </ul>
              </div>
              {genProgress && !genError && (
                <div className="flex items-center gap-2 text-xs text-accent">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />{genProgress}
                </div>
              )}
              {genError && <p className="text-xs text-severity-critical">{genError}</p>}
            </div>
            <div className="flex gap-2 mt-5">
              <button onClick={() => void generateReport()} disabled={generating}
                className="btn-primary flex-1 flex items-center justify-center gap-2 text-sm disabled:opacity-50">
                {generating ? <><Loader2 className="w-4 h-4 animate-spin" />Generating…</> : <><FileDown className="w-4 h-4" />Generate</>}
              </button>
              <button onClick={() => setShowModal(false)} disabled={generating} className="btn-secondary text-sm px-4">Cancel</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
