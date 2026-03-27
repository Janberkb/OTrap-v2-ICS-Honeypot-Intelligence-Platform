/**
 * ReportPDF.tsx — @react-pdf/renderer document component.
 * Dynamically imported (client-side only) via reports/page.tsx.
 */
import React from "react";
import {
  Document, Page, View, Text, StyleSheet,
  Svg, G, Rect, Line,
} from "@react-pdf/renderer";
import { buildReportSummary, normalizeReportData } from "@/lib/report-utils";

// ─── Design tokens (matching app dark palette) ────────────────────────────────

const C = {
  pageBg:      "#080c14",
  surface:     "#0f1623",
  elevated:    "#162032",
  border:      "#1e2d45",
  borderFaint: "#0d1825",
  textPrimary: "#f0f4ff",
  textMuted:   "#94a3b8",
  textFaint:   "#4b5563",
  accent:      "#3b82f6",
  accentDim:   "#1d3a6e",
};

const SEV_COLOR: Record<string, string>  = { critical: "#f87171", high: "#fb923c", medium: "#fbbf24", low: "#4ade80", noise: "#a8a29e" };
const SEV_BG: Record<string, string>     = { critical: "#450a0a", high: "#431407", medium: "#422006", low: "#052e16",  noise: "#1c1917" };
const SEV_BORDER: Record<string, string> = { critical: "#7f1d1d", high: "#7c2d12", medium: "#78350f", low: "#14532d",  noise: "#44403c" };
const PROTO_COLOR: Record<string, string> = { s7comm: "#60a5fa", s7: "#60a5fa", modbus: "#a78bfa", http: "#22d3ee", https: "#06b6d4", default: "#94a3b8" };
const TRIAGE_LABEL: Record<string, string> = { new: "New", investigating: "Investigating", reviewed: "Reviewed", false_positive: "False Positive", escalated: "Escalated" };

// ─── StyleSheet ───────────────────────────────────────────────────────────────

const s = StyleSheet.create({
  page: {
    backgroundColor: C.pageBg,
    fontFamily: "Helvetica",
    paddingTop: 28, paddingBottom: 40,
    paddingHorizontal: 28,
    fontSize: 9,
    color: C.textPrimary,
  },

  // ── Header
  headerBlock: {
    backgroundColor: C.surface,
    borderLeftWidth: 4, borderLeftColor: C.accent,
    paddingVertical: 14, paddingHorizontal: 18,
    marginBottom: 18,
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "flex-start",
  },
  logoRow: { flexDirection: "row", alignItems: "center", marginBottom: 5 },
  logoBox: { width: 28, height: 28, backgroundColor: C.accent, borderRadius: 5, alignItems: "center", justifyContent: "center", marginRight: 10 },
  logoGlyph: { fontSize: 15, color: "#ffffff", fontFamily: "Helvetica-Bold" },
  logoName: { fontSize: 18, fontFamily: "Helvetica-Bold", color: C.textPrimary, letterSpacing: -0.5 },
  logoVersion: { fontSize: 8, color: C.textFaint, letterSpacing: 1, textTransform: "uppercase", marginLeft: 6, marginTop: 4 },
  headerSub: { fontSize: 10, color: C.textMuted, marginLeft: 38 },
  headerTitle: { fontSize: 13, fontFamily: "Helvetica-Bold", color: C.textPrimary, marginLeft: 38, marginTop: 5 },
  confidentialBadge: { backgroundColor: "#3d2a00", borderRadius: 3, paddingHorizontal: 8, paddingVertical: 3, alignSelf: "flex-start", marginBottom: 8, borderWidth: 0.5, borderColor: "#92400e" },
  confidentialText: { fontSize: 8, fontFamily: "Helvetica-Bold", color: "#fbbf24", textTransform: "uppercase", letterSpacing: 1 },
  headerMeta: { fontSize: 9, color: C.textMuted, lineHeight: 1.8, textAlign: "right" },
  headerMetaLabel: { color: C.textFaint },

  // ── Section title
  sectionRow: { flexDirection: "row", alignItems: "center", marginBottom: 8 },
  sectionAccent: { width: 3, height: 11, backgroundColor: C.accent, borderRadius: 1, marginRight: 8 },
  sectionLabel: { fontSize: 8, fontFamily: "Helvetica-Bold", textTransform: "uppercase", letterSpacing: 1, color: C.textMuted },
  sectionLine: { flex: 1, height: 0.5, backgroundColor: C.border, marginLeft: 8 },

  // ── Cards
  card: { backgroundColor: C.surface, borderRadius: 6, borderWidth: 0.5, borderColor: C.border, overflow: "hidden" },
  cardPad: { padding: 12 },
  chartTitle: { fontSize: 8, fontFamily: "Helvetica-Bold", textTransform: "uppercase", letterSpacing: 0.8, color: C.textMuted, marginBottom: 10 },

  // ── KPI
  kpiCard: { flex: 1, backgroundColor: C.elevated, borderRadius: 6, borderWidth: 0.5, borderColor: C.border, padding: 10 },
  kpiCardAlert: { flex: 1, backgroundColor: "#1a0808", borderRadius: 6, borderWidth: 0.5, borderColor: "#7f1d1d", padding: 10 },
  kpiLabel: { fontSize: 7, textTransform: "uppercase", letterSpacing: 0.8, color: C.textFaint, marginBottom: 5 },
  kpiValue: { fontSize: 24, fontFamily: "Helvetica-Bold" },

  // ── Tables
  tableHeaderRow: { flexDirection: "row", backgroundColor: C.elevated, paddingVertical: 7, paddingHorizontal: 10, borderBottomWidth: 0.5, borderBottomColor: C.border },
  tableHeaderCell: { fontSize: 7, fontFamily: "Helvetica-Bold", textTransform: "uppercase", letterSpacing: 0.5, color: C.textFaint },
  tableRowEven: { flexDirection: "row", backgroundColor: C.surface, paddingVertical: 5, paddingHorizontal: 10, borderBottomWidth: 0.5, borderBottomColor: C.borderFaint },
  tableRowOdd:  { flexDirection: "row", backgroundColor: "#111827",  paddingVertical: 5, paddingHorizontal: 10, borderBottomWidth: 0.5, borderBottomColor: C.borderFaint },
  td:       { fontSize: 8,  color: C.textPrimary },
  tdMuted:  { fontSize: 8,  color: C.textMuted },
  tdFaint:  { fontSize: 8,  color: C.textFaint },
  tdMono:   { fontSize: 7.5, color: C.textPrimary, fontFamily: "Courier" },
  tdRight:  { textAlign: "right" },

  // ── Badge
  sevBadge: { borderRadius: 8, paddingHorizontal: 5, paddingVertical: 2, borderWidth: 0.5 },
  sevBadgeText: { fontSize: 7, fontFamily: "Helvetica-Bold", textTransform: "uppercase" },

  // ── Footer
  footer: { position: "absolute", bottom: 18, left: 28, right: 28, borderTopWidth: 0.5, borderTopColor: C.border, paddingTop: 7, flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  footerLeft:  { fontSize: 7, color: C.textFaint },
  footerRight: { fontSize: 7, fontFamily: "Helvetica-Bold", color: "#fbbf24" },

  // ── Executive Summary block
  execRow: { flexDirection: "row", gap: 10, marginTop: 10, marginBottom: 14 },
  riskBox: { width: 90, backgroundColor: C.elevated, borderRadius: 6, borderWidth: 0.5, borderColor: C.border, padding: 10, alignItems: "center", justifyContent: "center" },
  riskScore: { fontSize: 36, fontFamily: "Helvetica-Bold", lineHeight: 1 },
  riskLabel: { fontSize: 6.5, textTransform: "uppercase", letterSpacing: 0.8, color: C.textFaint, marginTop: 4 },
  riskTag:   { fontSize: 7, fontFamily: "Helvetica-Bold", textTransform: "uppercase", letterSpacing: 0.5, marginTop: 6, paddingHorizontal: 6, paddingVertical: 2, borderRadius: 3 },
  findingBox: { flex: 1, backgroundColor: C.surface, borderRadius: 6, borderWidth: 0.5, borderColor: C.border, padding: 10 },
  findingTitle: { fontSize: 7, fontFamily: "Helvetica-Bold", textTransform: "uppercase", letterSpacing: 0.8, color: C.textFaint, marginBottom: 7 },
  findingRow: { flexDirection: "row", alignItems: "center", gap: 6, marginBottom: 6, paddingBottom: 6, borderBottomWidth: 0.5, borderBottomColor: C.borderFaint },
  recBox: { flex: 1, backgroundColor: C.surface, borderRadius: 6, borderWidth: 0.5, borderColor: C.border, padding: 10 },
  recTitle: { fontSize: 7, fontFamily: "Helvetica-Bold", textTransform: "uppercase", letterSpacing: 0.8, color: C.textFaint, marginBottom: 7 },
  recRow: { flexDirection: "row", gap: 6, marginBottom: 6 },
  recBullet: { width: 12, height: 12, borderRadius: 6, backgroundColor: C.accentDim, alignItems: "center", justifyContent: "center", flexShrink: 0, marginTop: 0.5 },
  recBulletText: { fontSize: 7, fontFamily: "Helvetica-Bold", color: C.accent },
  recText: { fontSize: 7.5, color: C.textMuted, lineHeight: 1.5, flex: 1 },
});

// ─── Executive summary helpers ────────────────────────────────────────────────

function calcRiskScore(sessions: any[], cpuStops: number): number {
  let score = 0;
  const critCount = sessions.filter((s: any) => s.severity === "critical").length;
  const highCount = sessions.filter((s: any) => s.severity === "high").length;
  if (critCount > 0) score += 3;
  if (highCount > 0) score += 2;
  if (cpuStops > 0) score += Math.min(cpuStops * 2, 3);
  if (sessions.length > 20) score += 1;
  const totalIocs = sessions.reduce((sum: number, s: any) => sum + (s.ioc_count ?? 0), 0);
  if (totalIocs > 5) score += 1;
  return Math.min(score, 10);
}

function riskLabel(score: number): { label: string; color: string; bg: string; border: string } {
  if (score >= 8) return { label: "Critical Risk",  color: "#f87171", bg: "#450a0a", border: "#7f1d1d" };
  if (score >= 6) return { label: "High Risk",      color: "#fb923c", bg: "#431407", border: "#7c2d12" };
  if (score >= 4) return { label: "Medium Risk",    color: "#fbbf24", bg: "#422006", border: "#78350f" };
  if (score >= 2) return { label: "Low Risk",       color: "#4ade80", bg: "#052e16", border: "#14532d" };
  return               { label: "Minimal Risk",  color: "#94a3b8", bg: C.elevated,  border: C.border  };
}

function getRecommendations(protocols: string[], cpuStops: number): string[] {
  const recs: string[] = [];
  const protos = protocols.map((p: string) => p.toLowerCase());
  if (protos.some(p => ["s7comm", "s7"].includes(p)))
    recs.push("Isolate S7/SIMATIC PLCs on a dedicated OT VLAN and enforce PG/PC whitelist rules via an industrial firewall.");
  if (protos.includes("modbus"))
    recs.push("Enable Modbus function-code whitelisting; restrict to read-only operations (FC01–04) from authorized master IPs only.");
  if (protos.some(p => ["http", "https"].includes(p)))
    recs.push("Enforce authentication on web-based HMI panels and disable any direct internet-facing access to these endpoints.");
  if (cpuStops > 0)
    recs.push("Investigate PLC program integrity after CPU STOP events; verify ladder logic has not been tampered with.");
  recs.push("Conduct structured threat hunting aligned to MITRE ATT&CK for ICS (IEC 62443 / NERC CIP compliance).");
  return recs.slice(0, 3);
}

// ─── Small helpers ────────────────────────────────────────────────────────────

function SectionTitle({ children }: { children: string }) {
  return (
    <View style={s.sectionRow}>
      <View style={s.sectionAccent} />
      <Text style={s.sectionLabel}>{children}</Text>
      <View style={s.sectionLine} />
    </View>
  );
}

function SevBadge({ sev }: { sev: string }) {
  const key = (sev ?? "").toLowerCase();
  return (
    <View style={[s.sevBadge, { backgroundColor: SEV_BG[key] ?? C.elevated, borderColor: SEV_BORDER[key] ?? C.border }]}>
      <Text style={[s.sevBadgeText, { color: SEV_COLOR[key] ?? C.textMuted }]}>{sev?.toUpperCase() ?? "—"}</Text>
    </View>
  );
}

function DistBar({ label, count, total, color }: { label: string; count: number; total: number; color: string }) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <View style={{ marginBottom: 9 }}>
      <View style={{ flexDirection: "row", justifyContent: "space-between", marginBottom: 3 }}>
        <Text style={{ fontSize: 8, fontFamily: "Helvetica-Bold", color, textTransform: "uppercase", letterSpacing: 0.5 }}>{label}</Text>
        <Text style={{ fontSize: 8, color: C.textFaint }}>{count}  <Text style={{ opacity: 0.7 }}>({pct.toFixed(0)}%)</Text></Text>
      </View>
      <View style={{ height: 6, backgroundColor: C.border, borderRadius: 3 }}>
        <View style={{ height: "100%", width: `${pct}%`, backgroundColor: color, borderRadius: 3, opacity: 0.85 }} />
      </View>
    </View>
  );
}

function KpiRow({ cards }: { cards: { label: string; value: number; accent: string; alert?: boolean }[] }) {
  return (
    <View style={{ flexDirection: "row", gap: 8, marginBottom: 8 }}>
      {cards.map((k, i) => (
        <View key={i} style={k.alert && k.value > 0 ? s.kpiCardAlert : s.kpiCard}>
          <Text style={s.kpiLabel}>{k.label}</Text>
          <Text style={[s.kpiValue, { color: k.accent }]}>{k.value}</Text>
        </View>
      ))}
    </View>
  );
}

function BarChart({ buckets }: { buckets: { hour: string; count: number }[] }) {
  const max = Math.max(...buckets.map(b => b.count), 1);
  const W = 539, H = 70;
  const pad = { t: 6, r: 8, b: 18, l: 28 };
  const cW = W - pad.l - pad.r, cH = H - pad.t - pad.b;
  const bW = Math.max(1.5, (cW / buckets.length) - 1.5);

  return (
    <Svg width={W} height={H} viewBox={`0 0 ${W} ${H}`}>
      {[0, 0.5, 1].map(t => {
        const y = pad.t + cH * (1 - t);
        return (
          <G key={t}>
            <Line x1={pad.l} y1={y} x2={pad.l + cW} y2={y} stroke={C.border} strokeWidth={0.5} />
          </G>
        );
      })}
      {buckets.map((b, i) => {
        const bH = Math.max(0, (b.count / max) * cH);
        const x = pad.l + (i / buckets.length) * cW;
        const y = pad.t + cH - bH;
        const fill = b.count > max * 0.7 ? SEV_COLOR.critical : b.count > max * 0.4 ? SEV_COLOR.high : C.accent;
        return <Rect key={i} x={x + 0.5} y={y} width={bW} height={bH} fill={fill} opacity={0.8} rx={1} />;
      })}
      <Line x1={pad.l} y1={pad.t} x2={pad.l} y2={pad.t + cH} stroke={C.border} strokeWidth={0.7} />
      <Line x1={pad.l} y1={pad.t + cH} x2={pad.l + cW} y2={pad.t + cH} stroke={C.border} strokeWidth={0.7} />
    </Svg>
  );
}

function ConfBar({ pct }: { pct: number }) {
  const color = pct >= 90 ? SEV_COLOR.critical : pct >= 70 ? SEV_COLOR.medium : C.textFaint;
  return (
    <View style={{ flexDirection: "row", alignItems: "center", justifyContent: "flex-end", gap: 5 }}>
      <View style={{ width: 40, height: 5, backgroundColor: C.border, borderRadius: 3 }}>
        <View style={{ width: `${pct}%`, height: "100%", backgroundColor: color, borderRadius: 3 }} />
      </View>
      <Text style={{ fontSize: 7.5, color, fontFamily: "Helvetica-Bold", minWidth: 24, textAlign: "right" }}>{pct}%</Text>
    </View>
  );
}

// ─── Page footer ──────────────────────────────────────────────────────────────

function Footer({ range, genDate }: { range: string; genDate: string }) {
  return (
    <View style={s.footer} fixed>
      <Text style={s.footerLeft}>OTrap v2.0 — Enterprise OT/ICS Deception Platform  ·  {range}  ·  Generated {genDate}</Text>
      <Text style={s.footerRight}>CONFIDENTIAL — Internal Use Only</Text>
    </View>
  );
}

// ─── Table building helper ────────────────────────────────────────────────────

type ColDef = { label: string; flex: number; align?: "left" | "right" | "center" };

function TableHeader({ cols }: { cols: ColDef[] }) {
  return (
    <View style={s.tableHeaderRow}>
      {cols.map(c => (
        <Text key={c.label} style={[s.tableHeaderCell, { flex: c.flex, textAlign: c.align ?? "left" }]}>{c.label}</Text>
      ))}
    </View>
  );
}

// ─── Main document component ──────────────────────────────────────────────────

export interface ReportPDFProps {
  data:        any;
  title:       string;
  rangeLabel:  string;
  genDate:     string;
}

function ReportPDF({ data, title, rangeLabel, genDate }: ReportPDFProps) {
  const normalizedData = normalizeReportData(data);
  const sessions  = normalizedData.sessions ?? [];
  const attackers = normalizedData.attackers ?? [];
  const histogram = normalizedData.histogram ?? [];
  const iocs      = normalizedData.iocs ?? [];
  const stats     = normalizedData.stats ?? {};
  const protocols = stats?.protocols ?? [];
  const reportSummary = buildReportSummary(normalizedData);

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

  const protTotal = protocols.reduce((s: number, p: any) => s + p.count, 0);

  return (
    <Document title={title} author="OTrap v2.0" subject="OT/ICS Security Report">

      {/* ══════════════════════════════════════════════════════════════════
          PAGE 1  — Summary
      ═════════════════════════════════════════════════════════════════════ */}
      <Page size="A4" style={s.page}>
        <Footer range={rangeLabel} genDate={genDate} />

        {/* HEADER */}
        <View style={s.headerBlock}>
          <View>
            <View style={s.logoRow}>
              <View style={s.logoBox}>
                <Text style={s.logoGlyph}>⬡</Text>
              </View>
              <View>
                <View style={{ flexDirection: "row", alignItems: "baseline" }}>
                  <Text style={s.logoName}>OTrap</Text>
                  <Text style={s.logoVersion}>v2.0</Text>
                </View>
              </View>
            </View>
            <Text style={s.headerSub}>OT / ICS Deception Platform — Security Incident Report</Text>
            <Text style={s.headerTitle}>{title}</Text>
          </View>
          <View>
            <View style={s.confidentialBadge}>
              <Text style={s.confidentialText}>Confidential</Text>
            </View>
            <Text style={s.headerMeta}>
              <Text style={s.headerMetaLabel}>Period: </Text>{rangeLabel}{"\n"}
              <Text style={s.headerMetaLabel}>Generated: </Text>{genDate}{"\n"}
              <Text style={s.headerMetaLabel}>Sessions: </Text>{sessions.length}
            </Text>
          </View>
        </View>

        {/* EXECUTIVE SUMMARY */}
        <SectionTitle>Executive Summary</SectionTitle>
        <KpiRow cards={[
          { label: "Total Sessions",    value: sessions.length,   accent: C.accent },
          { label: "Unique Attackers",  value: attackers.length,  accent: "#a78bfa" },
          { label: "Events Recorded",   value: totalEvents,        accent: "#22d3ee" },
          { label: "Critical / High",   value: criticalHigh,       accent: SEV_COLOR.critical, alert: true },
          { label: "CPU Stop Events",   value: cpuStops,           accent: SEV_COLOR.critical, alert: true },
        ]} />
        <KpiRow cards={[
          { label: "IOCs Identified",     value: iocs.length,                                         accent: "#4ade80" },
          { label: "Actionable Sessions", value: reportSummary.actionableSessions,                    accent: "#fbbf24" },
          { label: "External Countries",  value: reportSummary.externalCountryCount,                  accent: "#22d3ee" },
        ]} />

        {/* ── RISK SCORE + TOP FINDINGS + RECOMMENDATIONS ── */}
        {(() => {
          const riskScore   = calcRiskScore(sessions, cpuStops);
          const risk        = riskLabel(riskScore);
          const recs = reportSummary.recommendations;

          return (
            <View style={s.execRow}>
              {/* Risk Score */}
              <View style={[s.riskBox, { borderColor: risk.border, backgroundColor: risk.bg }]}>
                <Text style={[s.riskScore, { color: risk.color }]}>{riskScore}</Text>
                <Text style={{ fontSize: 6.5, color: risk.color, opacity: 0.7, marginTop: 2 }}>/10</Text>
                <View style={[s.riskTag, { backgroundColor: risk.bg, borderWidth: 0.5, borderColor: risk.border }]}>
                  <Text style={{ fontSize: 6.5, color: risk.color, fontFamily: "Helvetica-Bold", textTransform: "uppercase", letterSpacing: 0.5 }}>{risk.label}</Text>
                </View>
              </View>

              {/* Operator Focus */}
              <View style={s.findingBox}>
                <Text style={s.findingTitle}>Operator Focus</Text>
                {reportSummary.impactSummary.length === 0
                  ? <Text style={{ fontSize: 8, color: C.textFaint }}>No sessions recorded in this period.</Text>
                  : reportSummary.impactSummary.map((line: string, i: number) => {
                      return (
                        <View key={i} style={[s.findingRow, i === reportSummary.impactSummary.length - 1 ? { borderBottomWidth: 0, marginBottom: 0, paddingBottom: 0 } : {}]}>
                          <View style={{ width: 12, height: 12, borderRadius: 6, backgroundColor: C.accentDim, alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                            <Text style={{ fontSize: 6.5, fontFamily: "Helvetica-Bold", color: C.accent }}>{i + 1}</Text>
                          </View>
                          <Text style={{ fontSize: 7.5, color: C.textMuted, flex: 1, lineHeight: 1.5 }}>{line}</Text>
                        </View>
                      );
                    })
                }
              </View>

              {/* Recommendations */}
              <View style={s.recBox}>
                <Text style={s.recTitle}>Recommendations</Text>
                {recs.map((rec, i) => (
                  <View key={i} style={s.recRow}>
                    <View style={s.recBullet}>
                      <Text style={s.recBulletText}>{i + 1}</Text>
                    </View>
                    <Text style={s.recText}>{rec}</Text>
                  </View>
                ))}
              </View>
            </View>
          );
        })()}

        {/* SEVERITY + PROTOCOL side by side */}
        <View style={{ marginTop: 14, marginBottom: 14, flexDirection: "row", gap: 12 }}>
          {/* Severity */}
          <View style={[s.card, s.cardPad, { flex: 1 }]}>
            <Text style={s.chartTitle}>Severity Distribution</Text>
            {["critical","high","medium","low","noise"].map(sev => (
              <DistBar key={sev} label={sev} count={sevDist[sev] ?? 0} total={sessions.length} color={SEV_COLOR[sev]} />
            ))}
          </View>
          {/* Protocol */}
          <View style={[s.card, s.cardPad, { flex: 1 }]}>
            <Text style={s.chartTitle}>Protocol Distribution</Text>
            {protocols.length === 0
              ? <Text style={{ fontSize: 8, color: C.textFaint }}>No data</Text>
              : protocols.map((p: any) => (
                  <DistBar key={p.protocol} label={p.protocol} count={p.count} total={protTotal} color={PROTO_COLOR[p.protocol] ?? PROTO_COLOR.default} />
                ))
            }
          </View>
        </View>

        {/* EVENT TIMELINE */}
        {histogram.length > 0 && (
          <View style={[s.card, s.cardPad]}>
            <Text style={s.chartTitle}>
              Event Timeline — {histogram.length > 24 ? "7-Day" : "24-Hour"} Activity  ({totalEvents} events)
            </Text>
            <BarChart buckets={histogram} />
          </View>
        )}
      </Page>

      {/* ══════════════════════════════════════════════════════════════════
          PAGE 2  — Attack Sources + Sessions
      ═════════════════════════════════════════════════════════════════════ */}
      <Page size="A4" style={s.page}>
        <Footer range={rangeLabel} genDate={genDate} />

        {/* TOP ATTACK SOURCES */}
        {attackers.length > 0 && (
          <View style={{ marginBottom: 18 }}>
            <SectionTitle>Top Attack Sources</SectionTitle>
            <View style={s.card}>
              <TableHeader cols={[
                { label: "#",            flex: 0.3  },
                { label: "Source IP",    flex: 1.5  },
                { label: "Country",      flex: 1.2  },
                { label: "Organisation", flex: 1.8  },
                { label: "Events",       flex: 0.7, align: "right" },
                { label: "Sessions",     flex: 0.7, align: "right" },
                { label: "Max Sev.",     flex: 0.9  },
                { label: "CPU Stop",     flex: 0.8  },
                { label: "Last Seen",    flex: 1.8  },
              ]} />
              {attackers.map((a: any, i: number) => (
                <View key={a.source_ip} style={i % 2 === 0 ? s.tableRowEven : s.tableRowOdd} wrap={false}>
                  <Text style={[s.tdFaint, { flex: 0.3 }]}>{i + 1}</Text>
                  <Text style={[s.tdMono,  { flex: 1.5 }]}>{a.source_ip}</Text>
                  <Text style={[s.tdMuted, { flex: 1.2 }]}>{[a.flag, a.country_name].filter(Boolean).join(" ") || "—"}</Text>
                  <Text style={[s.tdMuted, { flex: 1.8 }]}>{a.org ?? "—"}</Text>
                  <Text style={[s.td, s.tdRight, { flex: 0.7, fontFamily: "Helvetica-Bold" }]}>{a.event_count}</Text>
                  <Text style={[s.td, s.tdRight, { flex: 0.7 }]}>{a.session_count}</Text>
                  <View style={{ flex: 0.9, justifyContent: "center" }}>
                    <SevBadge sev={a.max_severity} />
                  </View>
                  <Text style={[{ flex: 0.8 }, a.cpu_stop_ever ? { color: SEV_COLOR.critical, fontSize: 8, fontFamily: "Helvetica-Bold" } : s.tdFaint]}>
                    {a.cpu_stop_ever ? "YES" : "—"}
                  </Text>
                  <Text style={[s.tdMuted, { flex: 1.8 }]}>{a.last_seen ? rfmt(a.last_seen) : "—"}</Text>
                </View>
              ))}
            </View>
          </View>
        )}

        {/* SESSION INVENTORY */}
        <SectionTitle>{`Session Inventory  (${sessions.length} sessions)`}</SectionTitle>
        <View style={s.card}>
          <TableHeader cols={[
            { label: "Source IP",   flex: 1.6 },
            { label: "Protocol",    flex: 0.9 },
            { label: "Severity",    flex: 1.0 },
            { label: "Events",      flex: 0.6, align: "right" },
            { label: "IOCs",        flex: 0.5, align: "right" },
            { label: "Triage",      flex: 1.2 },
            { label: "CPU Stop",    flex: 0.8 },
            { label: "Started",     flex: 1.6 },
            { label: "Duration",    flex: 0.8, align: "right" },
          ]} />
          {sessions.map((s: any, i: number) => (
            <View key={s.id} style={i % 2 === 0 ? sStyles.tableRowEven : sStyles.tableRowOdd} wrap={false}>
              <Text style={[sStyles.tdMono, { flex: 1.6 }]}>{s.source_ip}</Text>
              <Text style={[{ flex: 0.9, fontSize: 7.5, textTransform: "uppercase", fontFamily: "Helvetica-Bold", color: PROTO_COLOR[s.primary_protocol ?? ""] ?? C.textMuted }]}>
                {s.primary_protocol ?? "—"}
              </Text>
              <View style={{ flex: 1.0, justifyContent: "center" }}>
                <SevBadge sev={s.severity} />
              </View>
              <Text style={[sStyles.td, sStyles.tdRight, { flex: 0.6 }]}>{s.event_count}</Text>
              <Text style={[sStyles.td, sStyles.tdRight, { flex: 0.5 }]}>{s.ioc_count}</Text>
              <Text style={[sStyles.tdMuted, { flex: 1.2 }]}>{TRIAGE_LABEL[s.triage_status] ?? s.triage_status}</Text>
              <Text style={[{ flex: 0.8, fontSize: 8 }, s.cpu_stop_occurred ? { color: SEV_COLOR.critical, fontFamily: "Helvetica-Bold" } : { color: C.textFaint }]}>
                {s.cpu_stop_occurred ? "YES" : "—"}
              </Text>
              <Text style={[sStyles.tdMuted, { flex: 1.6 }]}>{s.started_at ? rfmt(s.started_at) : "—"}</Text>
              <Text style={[sStyles.tdMuted, sStyles.tdRight, { flex: 0.8 }]}>
                {s.duration_seconds != null ? `${s.duration_seconds.toFixed(1)}s` : "—"}
              </Text>
            </View>
          ))}
        </View>
      </Page>

      {/* ══════════════════════════════════════════════════════════════════
          PAGE 3  — IOCs, MITRE, Geo
      ═════════════════════════════════════════════════════════════════════ */}
      <Page size="A4" style={s.page}>
        <Footer range={rangeLabel} genDate={genDate} />

        {/* IOC TABLE */}
        {iocs.length > 0 && (
          <View style={{ marginBottom: 18 }}>
            <SectionTitle>{`Indicators of Compromise  (${iocs.length} IOCs)`}</SectionTitle>
            {reportSummary.redactedIndicatorCount > 0 && (
              <View style={{ marginBottom: 8, backgroundColor: C.elevated, borderRadius: 6, borderWidth: 0.5, borderColor: C.border, paddingHorizontal: 10, paddingVertical: 8 }}>
                <Text style={{ fontSize: 7.5, color: C.textMuted }}>
                  Credential indicators are intentionally redacted in stored reports and PDF exports.
                </Text>
              </View>
            )}
            <View style={s.card}>
              <TableHeader cols={[
                { label: "Type",        flex: 0.9 },
                { label: "Value",       flex: 3.0 },
                { label: "Confidence",  flex: 1.2, align: "right" },
                { label: "Sessions",    flex: 0.8, align: "right" },
                { label: "First Seen",  flex: 1.6 },
                { label: "Last Seen",   flex: 1.6 },
              ]} />
              {iocs.map((ioc: any, i: number) => (
                <View key={`${ioc.ioc_type}:${ioc.value}`} style={i % 2 === 0 ? s.tableRowEven : s.tableRowOdd} wrap={false}>
                  <View style={{ flex: 0.9, justifyContent: "center" }}>
                    <View style={{ backgroundColor: C.accentDim, borderRadius: 3, paddingHorizontal: 4, paddingVertical: 2, alignSelf: "flex-start" }}>
                      <Text style={{ fontSize: 7, fontFamily: "Helvetica-Bold", textTransform: "uppercase", color: "#93c5fd", letterSpacing: 0.4 }}>{ioc.ioc_type}</Text>
                    </View>
                  </View>
                  <Text style={[s.tdMono, { flex: 3.0 }]}>{ioc.value}</Text>
                  <View style={{ flex: 1.2, justifyContent: "center", alignItems: "flex-end" }}>
                    <ConfBar pct={Math.round((ioc.confidence ?? 0) * 100)} />
                  </View>
                  <Text style={[s.td, s.tdRight, { flex: 0.8 }]}>{ioc.session_count}</Text>
                  <Text style={[s.tdMuted, { flex: 1.6 }]}>{ioc.first_seen_at ? rfmt(ioc.first_seen_at) : "—"}</Text>
                  <Text style={[s.tdMuted, { flex: 1.6 }]}>{ioc.last_seen_at  ? rfmt(ioc.last_seen_at)  : "—"}</Text>
                </View>
              ))}
            </View>
          </View>
        )}

        {/* MITRE ATT&CK */}
        {techniques.length > 0 && (
          <View style={{ marginBottom: 18 }}>
            <SectionTitle>MITRE ATT&CK for ICS — Observed Techniques</SectionTitle>
            <View style={s.card}>
              <TableHeader cols={[
                { label: "Technique ID",   flex: 1.2 },
                { label: "Technique Name", flex: 3.5 },
                { label: "Tactic",         flex: 2.5 },
                { label: "Occurrences",    flex: 1.0, align: "right" },
              ]} />
              {techniques.map((t, i) => (
                <View key={t.id} style={i % 2 === 0 ? s.tableRowEven : s.tableRowOdd} wrap={false}>
                  <View style={{ flex: 1.2, justifyContent: "center" }}>
                    <View style={{ backgroundColor: "#3d2b00", borderRadius: 3, paddingHorizontal: 5, paddingVertical: 2, alignSelf: "flex-start" }}>
                      <Text style={{ fontSize: 7.5, fontFamily: "Helvetica-Bold", color: "#fbbf24" }}>{t.id}</Text>
                    </View>
                  </View>
                  <Text style={[s.td, { flex: 3.5 }]}>{t.name}</Text>
                  <Text style={[s.tdFaint, { flex: 2.5 }]}>{t.tactic}</Text>
                  <Text style={[s.td, s.tdRight, { flex: 1.0, fontFamily: "Helvetica-Bold" }]}>{t.count}</Text>
                </View>
              ))}
            </View>
          </View>
        )}

        {/* GEOGRAPHIC DISTRIBUTION */}
        {(stats?.top_countries?.length ?? 0) > 0 && (
          <View>
            <SectionTitle>Geographic Distribution</SectionTitle>
            {reportSummary.hasPrivateCountryTraffic && (
              <View style={{ marginBottom: 8, backgroundColor: C.elevated, borderRadius: 6, borderWidth: 0.5, borderColor: C.border, paddingHorizontal: 10, paddingVertical: 8 }}>
                <Text style={{ fontSize: 7.5, color: C.textMuted }}>
                  Private-network traffic is shown separately and excluded from the external country KPI.
                </Text>
              </View>
            )}
            <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
              {stats.top_countries.map((c: any) => (
                <View key={c.country_code} style={{ width: "31%", backgroundColor: C.surface, borderRadius: 6, borderWidth: 0.5, borderColor: C.border, paddingHorizontal: 12, paddingVertical: 8, flexDirection: "row", justifyContent: "space-between", alignItems: "center" }}>
                  <Text style={{ fontSize: 9, color: C.textPrimary }}>{[c.flag, c.country_name].filter(Boolean).join(" ") || c.country_code}</Text>
                  <Text style={{ fontSize: 12, fontFamily: "Helvetica-Bold", color: C.accent }}>{c.count}</Text>
                </View>
              ))}
            </View>
          </View>
        )}
      </Page>
    </Document>
  );
}

// Alias for session table styles (to avoid "s" variable conflict in map)
const sStyles = s;

// ─── Entry point (dynamically imported from page.tsx) ─────────────────────────

export function buildPDF(props: ReportPDFProps) {
  return <ReportPDF {...props} />;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function rfmt(iso: string): string {
  try {
    return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch { return iso; }
}
