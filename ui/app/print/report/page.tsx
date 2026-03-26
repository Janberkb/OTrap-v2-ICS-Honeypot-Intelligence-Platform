"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { apiPath } from "@/lib/api";

// ─── Constants ──────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "#dc2626",
  high:     "#ea580c",
  medium:   "#d97706",
  low:      "#16a34a",
  noise:    "#6b7280",
};

const SEV_BG: Record<string, string> = {
  critical: "#fef2f2",
  high:     "#fff7ed",
  medium:   "#fffbeb",
  low:      "#f0fdf4",
  noise:    "#f9fafb",
};

const PROTO_COLOR: Record<string, string> = {
  s7comm: "#3b82f6", s7: "#3b82f6",
  modbus: "#8b5cf6",
  http:   "#06b6d4", https: "#0891b2",
  default: "#6b7280",
};

const TRIAGE_LABEL: Record<string, string> = {
  new:            "New",
  investigating:  "Investigating",
  reviewed:       "Reviewed",
  false_positive: "False Positive",
  escalated:      "Escalated",
};

// ─── Report inner component (needs Suspense for useSearchParams) ─────────────

function ReportInner() {
  const searchParams = useSearchParams();
  const reportId = searchParams.get("id");

  const [stats,    setStats]    = useState<any>(null);
  const [sessions, setSessions] = useState<any[]>([]);
  const [attackers,setAttackers]= useState<any[]>([]);
  const [histogram,setHistogram]= useState<any[]>([]);
  const [iocs,     setIocs]     = useState<any[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [genDate,  setGenDate]  = useState("");
  const [reportTitle, setReportTitle] = useState("");
  const [rangeLabel,  setRangeLabel]  = useState("");

  useEffect(() => {
    if (reportId) {
      void loadFromStore(reportId);
    }
  }, [reportId]);

  async function loadFromStore(id: string) {
    setLoading(true);
    try {
      const res = await fetch(apiPath(`/reports/${id}`), { credentials: "include" });
      if (!res.ok) throw new Error("Report not found");
      const report = await res.json();
      const d = report.data ?? {};
      setStats(d.stats ?? {});
      setSessions(d.sessions ?? []);
      setAttackers(d.attackers ?? []);
      setHistogram(d.histogram ?? []);
      setIocs(d.iocs ?? []);
      setReportTitle(report.title);
      setRangeLabel(report.range_label);
      setGenDate(new Date(d.generated_at ?? report.generated_at).toLocaleString("en-GB", { dateStyle: "long", timeStyle: "short" }));
    } catch {
      setGenDate("—");
    } finally {
      setLoading(false);
    }
  }

  const totalEvents = histogram.reduce((s, b) => s + b.count, 0);
  const criticalHigh = sessions.filter(s => s.severity === "critical" || s.severity === "high").length;
  const cpuStops = sessions.filter(s => s.cpu_stop_occurred).length;

  const sevDist: Record<string, number> = {};
  sessions.forEach(s => { sevDist[s.severity] = (sevDist[s.severity] ?? 0) + 1; });
  const sevOrder = ["critical", "high", "medium", "low", "noise"];

  const protocols = stats?.protocols ?? [];

  const techniqueMap = new Map<string, { id: string; name: string; tactic: string; count: number }>();
  sessions.forEach(s =>
    (s.mitre_techniques ?? []).forEach((t: any) => {
      const key = t.technique_id;
      if (techniqueMap.has(key)) {
        techniqueMap.get(key)!.count++;
      } else {
        techniqueMap.set(key, { id: t.technique_id, name: t.technique_name, tactic: t.tactic, count: 1 });
      }
    })
  );
  const techniques = [...techniqueMap.values()].sort((a, b) => b.count - a.count);

  return (
    <>
      <style>{`
        @media print {
          .no-print { display: none !important; }
          body, html { background: white !important; }
          @page { margin: 18mm 14mm; size: A4 portrait; }
          table { page-break-inside: auto; border-collapse: collapse; }
          tr    { page-break-inside: avoid; }
          thead { display: table-header-group; }
          .page-break { page-break-before: always; }
          .no-break    { page-break-inside: avoid; }
        }
        * { box-sizing: border-box; }
        body, html { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; }
      `}</style>

      {/* ── Floating action bar (hidden on print) ────────────────────────── */}
      <div className="no-print" style={{
        position: "sticky", top: 0, zIndex: 100, background: "#0f172a",
        borderBottom: "1px solid #1e293b", padding: "10px 24px",
        display: "flex", alignItems: "center", gap: 12,
      }}>
        <div style={{ color: "#60a5fa", fontWeight: 700, fontSize: 14, letterSpacing: -0.3 }}>
          OTrap Report Preview
        </div>
        {rangeLabel && (
          <>
            <div style={{ height: 20, width: 1, background: "#334155" }} />
            <span style={{ fontSize: 12, color: "#94a3b8" }}>{rangeLabel}</span>
          </>
        )}
        <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
          <button onClick={() => window.print()}
            style={{ background: "#2563eb", color: "white", border: "none", borderRadius: 4, padding: "7px 18px", fontSize: 13, cursor: "pointer", fontWeight: 600 }}>
            ↓ Print / Save as PDF
          </button>
          <button onClick={() => window.close()}
            style={{ background: "#334155", color: "#cbd5e1", border: "none", borderRadius: 4, padding: "7px 12px", fontSize: 13, cursor: "pointer" }}>
            ✕ Close
          </button>
        </div>
      </div>

      {/* ── Report body ──────────────────────────────────────────────────── */}
      <div style={{ background: "white", minHeight: "100vh", color: "#111827" }}>
        <div style={{ maxWidth: 1040, margin: "0 auto", padding: "32px 28px" }}>

          {loading ? (
            <div style={{ textAlign: "center", padding: "80px 0", color: "#6b7280", fontSize: 14 }}>
              Loading report data…
            </div>
          ) : !reportId ? (
            <div style={{ textAlign: "center", padding: "80px 0", color: "#dc2626", fontSize: 14 }}>
              No report ID specified. Please open a report from the Reports page.
            </div>
          ) : (
            <>
              {/* ═══ HEADER ═══════════════════════════════════════════════ */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", borderBottom: "3px solid #111827", paddingBottom: 20, marginBottom: 28 }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
                    <div style={{ width: 32, height: 32, background: "#1e40af", borderRadius: 6, display: "flex", alignItems: "center", justifyContent: "center" }}>
                      <span style={{ color: "white", fontSize: 16, fontWeight: 900 }}>⬡</span>
                    </div>
                    <span style={{ fontSize: 22, fontWeight: 800, letterSpacing: -0.5 }}>OTrap</span>
                    <span style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", letterSpacing: 1, textTransform: "uppercase", marginTop: 2 }}>v2.0</span>
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 400, color: "#374151", marginLeft: 44 }}>
                    OT / ICS Deception Platform — Security Incident Report
                  </div>
                  {reportTitle && (
                    <div style={{ fontSize: 15, fontWeight: 700, color: "#111827", marginLeft: 44, marginTop: 6 }}>
                      {reportTitle}
                    </div>
                  )}
                </div>
                <div style={{ textAlign: "right" }}>
                  <div style={{ display: "inline-block", background: "#fef3c7", border: "1px solid #f59e0b", borderRadius: 4, padding: "2px 10px", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "#92400e", marginBottom: 6 }}>
                    CONFIDENTIAL
                  </div>
                  <div style={{ fontSize: 12, color: "#6b7280", lineHeight: 1.6 }}>
                    <div><strong>Period:</strong> {rangeLabel}</div>
                    <div><strong>Generated:</strong> {genDate}</div>
                    <div><strong>Total Sessions:</strong> {sessions.length}</div>
                  </div>
                </div>
              </div>

              {/* ═══ EXECUTIVE SUMMARY ════════════════════════════════════ */}
              <div className="no-break" style={{ marginBottom: 32 }}>
                <SectionTitle>Executive Summary</SectionTitle>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12, marginBottom: 16 }}>
                  <KpiCard label="Total Sessions"      value={sessions.length}          color="#1e40af" />
                  <KpiCard label="Unique Attackers"    value={attackers.length}          color="#7c3aed" />
                  <KpiCard label="Events Recorded"     value={totalEvents}               color="#0369a1" />
                  <KpiCard label="Critical / High"     value={criticalHigh}              color="#dc2626" alert={criticalHigh > 0} />
                  <KpiCard label="CPU Stop Events"     value={cpuStops}                  color="#dc2626" alert={cpuStops > 0} />
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
                  <KpiCard label="IOCs Identified"     value={iocs.length}               color="#059669" />
                  <KpiCard label="Actionable Sessions" value={sessions.filter(s => s.is_actionable).length} color="#d97706" />
                  <KpiCard label="Unique Countries"    value={stats?.top_countries?.length ?? 0} color="#0891b2" />
                </div>
              </div>

              {/* ═══ SEVERITY + PROTOCOL DISTRIBUTION ════════════════════ */}
              <div className="no-break" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 32 }}>
                {/* Severity Distribution */}
                <div style={{ border: "1px solid #e5e7eb", borderRadius: 8, padding: "16px 20px" }}>
                  <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "#374151", marginBottom: 14 }}>
                    Severity Distribution
                  </div>
                  {sevOrder.map(sev => {
                    const count = sevDist[sev] ?? 0;
                    const pct = sessions.length > 0 ? (count / sessions.length) * 100 : 0;
                    return (
                      <div key={sev} style={{ marginBottom: 10 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                          <span style={{ fontSize: 11, fontWeight: 600, color: SEV_COLOR[sev], textTransform: "uppercase" }}>{sev}</span>
                          <span style={{ fontSize: 11, color: "#6b7280" }}>{count} ({pct.toFixed(0)}%)</span>
                        </div>
                        <div style={{ height: 8, background: "#f3f4f6", borderRadius: 4, overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${pct}%`, background: SEV_COLOR[sev], borderRadius: 4 }} />
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Protocol Distribution */}
                <div style={{ border: "1px solid #e5e7eb", borderRadius: 8, padding: "16px 20px" }}>
                  <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "#374151", marginBottom: 14 }}>
                    Protocol Distribution
                  </div>
                  {protocols.length === 0 ? (
                    <p style={{ fontSize: 12, color: "#9ca3af" }}>No protocol data available</p>
                  ) : (() => {
                    const total = protocols.reduce((s: number, p: any) => s + p.count, 0);
                    return protocols.map((p: any) => {
                      const pct = total > 0 ? (p.count / total) * 100 : 0;
                      const col = PROTO_COLOR[p.protocol] ?? PROTO_COLOR.default;
                      return (
                        <div key={p.protocol} style={{ marginBottom: 10 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                            <span style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", color: "#374151" }}>{p.protocol}</span>
                            <span style={{ fontSize: 11, color: "#6b7280" }}>{p.count} ({pct.toFixed(0)}%)</span>
                          </div>
                          <div style={{ height: 8, background: "#f3f4f6", borderRadius: 4, overflow: "hidden" }}>
                            <div style={{ height: "100%", width: `${pct}%`, background: col, borderRadius: 4 }} />
                          </div>
                        </div>
                      );
                    });
                  })()}
                </div>
              </div>

              {/* ═══ EVENT TIMELINE ═══════════════════════════════════════ */}
              {histogram.length > 0 && (
                <div className="no-break" style={{ border: "1px solid #e5e7eb", borderRadius: 8, padding: "16px 20px", marginBottom: 32 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "#374151", marginBottom: 14 }}>
                    Event Timeline — {histogram.length > 24 ? "7-Day" : "24-Hour"} Activity ({totalEvents} total events)
                  </div>
                  <EventBarChart buckets={histogram} />
                </div>
              )}

              {/* ═══ TOP ATTACK SOURCES ════════════════════════════════════ */}
              {attackers.length > 0 && (
                <div style={{ marginBottom: 32 }}>
                  <SectionTitle>Top Attack Sources</SectionTitle>
                  <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ background: "#f8fafc" }}>
                        <TH>#</TH>
                        <TH>Source IP</TH>
                        <TH>Country</TH>
                        <TH>Organisation / ISP</TH>
                        <TH align="right">Events</TH>
                        <TH align="right">Sessions</TH>
                        <TH>Max Severity</TH>
                        <TH>CPU Stop</TH>
                        <TH>Last Seen</TH>
                      </tr>
                    </thead>
                    <tbody>
                      {attackers.map((a, i) => (
                        <tr key={a.source_ip} style={{ background: i % 2 === 0 ? "white" : "#f9fafb" }}>
                          <TD>{i + 1}</TD>
                          <TD mono>{a.source_ip}</TD>
                          <TD>{[a.flag, a.country_name].filter(Boolean).join(" ") || "—"}</TD>
                          <TD>{a.org ?? "—"}</TD>
                          <TD align="right"><strong>{a.event_count}</strong></TD>
                          <TD align="right">{a.session_count}</TD>
                          <TD><SevBadge sev={a.max_severity} /></TD>
                          <TD>{a.cpu_stop_ever ? <span style={{ color: "#dc2626", fontWeight: 700 }}>YES</span> : "No"}</TD>
                          <TD>{a.last_seen ? fmt(a.last_seen) : "—"}</TD>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* ═══ SESSION INVENTORY ════════════════════════════════════ */}
              <div className="page-break" style={{ marginBottom: 32 }}>
                <SectionTitle>Session Inventory ({sessions.length} sessions)</SectionTitle>
                <table style={{ width: "100%", fontSize: 10.5, borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ background: "#f8fafc" }}>
                      <TH>Source IP</TH>
                      <TH>Protocol</TH>
                      <TH>Severity</TH>
                      <TH>Signal Tier</TH>
                      <TH align="right">Events</TH>
                      <TH align="right">IOCs</TH>
                      <TH>Triage</TH>
                      <TH>CPU Stop</TH>
                      <TH>Started</TH>
                      <TH align="right">Duration</TH>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.map((s, i) => (
                      <tr key={s.id} style={{ background: i % 2 === 0 ? "white" : "#f9fafb" }}>
                        <TD mono>{s.source_ip}</TD>
                        <TD style={{ textTransform: "uppercase", fontWeight: 600, color: PROTO_COLOR[s.primary_protocol ?? ""] ?? "#374151" }}>
                          {s.primary_protocol ?? "—"}
                        </TD>
                        <TD><SevBadge sev={s.severity} /></TD>
                        <TD style={{ color: "#6b7280", fontStyle: "italic" }}>{s.signal_tier ?? "—"}</TD>
                        <TD align="right">{s.event_count}</TD>
                        <TD align="right">{s.ioc_count}</TD>
                        <TD style={{ color: "#374151" }}>{TRIAGE_LABEL[s.triage_status] ?? s.triage_status}</TD>
                        <TD>{s.cpu_stop_occurred ? <span style={{ color: "#dc2626", fontWeight: 700 }}>YES</span> : "—"}</TD>
                        <TD>{s.started_at ? fmt(s.started_at) : "—"}</TD>
                        <TD align="right">{s.duration_seconds != null ? `${s.duration_seconds.toFixed(1)}s` : "—"}</TD>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* ═══ IOC TABLE ════════════════════════════════════════════ */}
              {iocs.length > 0 && (
                <div className="page-break" style={{ marginBottom: 32 }}>
                  <SectionTitle>Indicators of Compromise ({iocs.length} IOCs)</SectionTitle>
                  <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ background: "#f8fafc" }}>
                        <TH>Type</TH>
                        <TH>Value</TH>
                        <TH align="right">Confidence</TH>
                        <TH align="right">Sessions</TH>
                        <TH>First Seen</TH>
                        <TH>Last Seen</TH>
                      </tr>
                    </thead>
                    <tbody>
                      {iocs.map((ioc, i) => (
                        <tr key={`${ioc.ioc_type}:${ioc.value}`} style={{ background: i % 2 === 0 ? "white" : "#f9fafb" }}>
                          <TD>
                            <span style={{ background: "#eff6ff", color: "#1d4ed8", fontSize: 10, fontWeight: 700, textTransform: "uppercase", padding: "1px 6px", borderRadius: 4, letterSpacing: 0.5 }}>
                              {ioc.ioc_type}
                            </span>
                          </TD>
                          <TD mono>{ioc.value}</TD>
                          <TD align="right">
                            <ConfidenceBar pct={Math.round((ioc.confidence ?? 0) * 100)} />
                          </TD>
                          <TD align="right">{ioc.session_count}</TD>
                          <TD>{ioc.first_seen_at ? fmt(ioc.first_seen_at) : "—"}</TD>
                          <TD>{ioc.last_seen_at  ? fmt(ioc.last_seen_at)  : "—"}</TD>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* ═══ MITRE ATT&CK ════════════════════════════════════════ */}
              {techniques.length > 0 && (
                <div className="no-break" style={{ marginBottom: 32 }}>
                  <SectionTitle>MITRE ATT&CK for ICS — Observed Techniques</SectionTitle>
                  <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ background: "#f8fafc" }}>
                        <TH>Technique ID</TH>
                        <TH>Technique Name</TH>
                        <TH>Tactic</TH>
                        <TH align="right">Occurrences</TH>
                      </tr>
                    </thead>
                    <tbody>
                      {techniques.map((t, i) => (
                        <tr key={t.id} style={{ background: i % 2 === 0 ? "white" : "#f9fafb" }}>
                          <TD mono>
                            <span style={{ background: "#fef3c7", color: "#92400e", fontSize: 10, fontWeight: 700, padding: "1px 6px", borderRadius: 4 }}>
                              {t.id}
                            </span>
                          </TD>
                          <TD>{t.name}</TD>
                          <TD style={{ color: "#6b7280" }}>{t.tactic}</TD>
                          <TD align="right"><strong>{t.count}</strong></TD>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* ═══ GEOGRAPHIC DISTRIBUTION ═════════════════════════════ */}
              {(stats?.top_countries?.length ?? 0) > 0 && (
                <div className="no-break" style={{ marginBottom: 32 }}>
                  <SectionTitle>Geographic Distribution</SectionTitle>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
                    {stats.top_countries.map((c: any) => (
                      <div key={c.country_code} style={{ border: "1px solid #e5e7eb", borderRadius: 6, padding: "10px 14px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: 12 }}>{[c.flag, c.country_name].filter(Boolean).join(" ") || c.country_code}</span>
                        <span style={{ fontSize: 14, fontWeight: 700, color: "#1e40af" }}>{c.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ═══ REPORT FOOTER ════════════════════════════════════════ */}
              <div style={{ marginTop: 48, borderTop: "2px solid #e5e7eb", paddingTop: 14, display: "flex", justifyContent: "space-between", fontSize: 10, color: "#9ca3af" }}>
                <div>
                  <strong style={{ color: "#374151" }}>OTrap v2.0</strong> — Enterprise OT/ICS Deception Platform
                  &nbsp;·&nbsp; {rangeLabel} &nbsp;·&nbsp; Generated {genDate}
                </div>
                <div style={{ color: "#d97706", fontWeight: 600 }}>CONFIDENTIAL — Internal Use Only</div>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
}

// ─── Helper components ───────────────────────────────────────────────────────

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
      <h3 style={{ margin: 0, fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.8, color: "#111827" }}>
        {children}
      </h3>
      <div style={{ flex: 1, height: 1, background: "#e5e7eb" }} />
    </div>
  );
}

function KpiCard({ label, value, color, alert }: { label: string; value: number; color: string; alert?: boolean }) {
  return (
    <div style={{ border: `1px solid ${alert && value > 0 ? "#fca5a5" : "#e5e7eb"}`, borderRadius: 8, padding: "14px 16px", background: alert && value > 0 ? "#fef2f2" : "white" }}>
      <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: 0.8, color: "#6b7280", marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 800, color: alert && value > 0 ? "#dc2626" : color, lineHeight: 1 }}>{value}</div>
    </div>
  );
}

function TH({ children, align }: { children: React.ReactNode; align?: string }) {
  return (
    <th style={{ textAlign: (align as any) ?? "left", padding: "8px 10px", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.6, color: "#374151", borderBottom: "2px solid #e5e7eb", borderTop: "1px solid #e5e7eb", background: "#f8fafc", whiteSpace: "nowrap" }}>
      {children}
    </th>
  );
}

function TD({ children, mono, align, style }: { children?: React.ReactNode; mono?: boolean; align?: string; style?: React.CSSProperties }) {
  return (
    <td style={{ padding: "6px 10px", borderBottom: "1px solid #f1f5f9", fontFamily: mono ? "'Courier New', monospace" : "inherit", textAlign: (align as any) ?? "left", fontSize: 11, ...style }}>
      {children}
    </td>
  );
}

function SevBadge({ sev }: { sev: string }) {
  if (!sev) return <span style={{ color: "#9ca3af" }}>—</span>;
  return (
    <span style={{
      display: "inline-block",
      background: SEV_BG[sev.toLowerCase()] ?? "#f9fafb",
      color: SEV_COLOR[sev.toLowerCase()] ?? "#374151",
      fontWeight: 700, fontSize: 10, textTransform: "uppercase",
      padding: "2px 7px", borderRadius: 10,
      border: `1px solid ${SEV_COLOR[sev.toLowerCase()] ?? "#e5e7eb"}22`,
    }}>
      {sev}
    </span>
  );
}

function ConfidenceBar({ pct }: { pct: number }) {
  const color = pct >= 90 ? "#dc2626" : pct >= 70 ? "#d97706" : "#6b7280";
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 6 }}>
      <div style={{ width: 48, height: 6, background: "#f3f4f6", borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontSize: 10, color, fontWeight: 600, minWidth: 28, textAlign: "right" }}>{pct}%</span>
    </div>
  );
}

function EventBarChart({ buckets }: { buckets: { hour: string; count: number }[] }) {
  const max = Math.max(...buckets.map(b => b.count), 1);
  const W = 960, H = 140;
  const pad = { top: 8, right: 16, bottom: 28, left: 36 };
  const cW = W - pad.left - pad.right;
  const cH = H - pad.top - pad.bottom;
  const bW = Math.max(2, (cW / buckets.length) - 2);
  const yTicks = [0, 0.25, 0.5, 0.75, 1];

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: "auto", display: "block" }}>
      {yTicks.map(t => {
        const y = pad.top + cH * (1 - t);
        return (
          <g key={t}>
            <line x1={pad.left} y1={y} x2={pad.left + cW} y2={y} stroke="#f3f4f6" strokeWidth={1} />
            <text x={pad.left - 4} y={y + 3.5} textAnchor="end" fontSize={8} fill="#9ca3af">{Math.round(max * t)}</text>
          </g>
        );
      })}
      {buckets.map((b, i) => {
        const bH = Math.max(0, (b.count / max) * cH);
        const x = pad.left + (i / buckets.length) * cW;
        const y = pad.top + cH - bH;
        const showLabel = buckets.length <= 24 || i % Math.ceil(buckets.length / 24) === 0;
        return (
          <g key={i}>
            <rect x={x + 1} y={y} width={bW} height={bH}
              fill={b.count > max * 0.7 ? "#dc2626" : b.count > max * 0.4 ? "#d97706" : "#3b82f6"}
              opacity={0.85} rx={1} />
            {showLabel && (
              <text x={x + bW / 2 + 1} y={H - 6} textAnchor="middle" fontSize={7.5} fill="#9ca3af">{b.hour}</text>
            )}
          </g>
        );
      })}
      <line x1={pad.left} y1={pad.top} x2={pad.left} y2={pad.top + cH} stroke="#d1d5db" strokeWidth={1} />
      <line x1={pad.left} y1={pad.top + cH} x2={pad.left + cW} y2={pad.top + cH} stroke="#d1d5db" strokeWidth={1} />
    </svg>
  );
}

function fmt(iso: string): string {
  try {
    return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch { return iso; }
}

// ─── Page export (Suspense wrapper for useSearchParams) ──────────────────────

export default function PrintReportPage() {
  return (
    <Suspense fallback={
      <div style={{ background: "white", minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: "#6b7280", fontFamily: "sans-serif" }}>
        Loading…
      </div>
    }>
      <ReportInner />
    </Suspense>
  );
}
