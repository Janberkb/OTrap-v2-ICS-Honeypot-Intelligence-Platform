"use client";

import { useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { Brain, ChevronLeft, Zap, Shield, Clock, Activity, Download, Network } from "lucide-react";
import { SeverityBadge, SignalTierBadge, formatDateTime, formatDuration } from "@/components/ui";
import { apiPath } from "@/lib/api";

type Tab = "timeline" | "iocs" | "artifacts" | "mitre" | "ai";

const KILL_CHAIN_STEPS = [
  { key: "initial_access",   label: "Initial Access",   short: "Access"   },
  { key: "discovery",        label: "Discovery",        short: "Recon"    },
  { key: "lateral_movement", label: "Lateral Movement", short: "Movement" },
  { key: "impact",           label: "Impact",           short: "Impact"   },
];

const PHASE_COLOR: Record<string, string> = {
  initial_access:   "text-severity-low   bg-severity-low/10   border-severity-low/30",
  discovery:        "text-severity-medium bg-severity-medium/10 border-severity-medium/30",
  lateral_movement: "text-severity-high  bg-severity-high/10  border-severity-high/30",
  impact:           "text-severity-critical bg-severity-critical/10 border-severity-critical/30",
};

function KillChainBanner({ phase }: { phase?: string }) {
  const current = phase ?? "initial_access";
  const currentIdx = KILL_CHAIN_STEPS.findIndex((s) => s.key === current);

  return (
    <div className="card p-3 flex items-center gap-1 overflow-x-auto">
      <span className="text-xs text-text-faint font-medium whitespace-nowrap mr-2">Kill Chain</span>
      {KILL_CHAIN_STEPS.map((step, i) => {
        const isActive  = step.key === current;
        const isPast    = i < currentIdx;
        const isFuture  = i > currentIdx;
        return (
          <div key={step.key} className="flex items-center gap-1 flex-shrink-0">
            <div
              title={step.label}
              className={[
                "px-2.5 py-1 rounded border text-xs font-semibold whitespace-nowrap transition-all",
                isActive  ? PHASE_COLOR[step.key] + " ring-1 ring-current/40" : "",
                isPast    ? "text-text-faint bg-bg-elevated/50 border-bg-border/50" : "",
                isFuture  ? "text-text-faint/40 bg-transparent border-bg-border/20" : "",
              ].join(" ")}
            >
              {step.short}
            </div>
            {i < KILL_CHAIN_STEPS.length - 1 && (
              <span className={`text-xs ${i < currentIdx ? "text-text-faint" : "text-text-faint/30"}`}>→</span>
            )}
          </div>
        );
      })}
      {current && (
        <span className={`ml-auto text-xs font-semibold whitespace-nowrap ${PHASE_COLOR[current]?.split(" ")[0] ?? "text-text-muted"}`}>
          {KILL_CHAIN_STEPS.find((s) => s.key === current)?.label ?? current}
        </span>
      )}
    </div>
  );
}

function isPrivateIp(ip: string): boolean {
  if (!ip) return false;
  if (ip.startsWith("10.") || ip.startsWith("127.") || ip.startsWith("169.254.") || ip.startsWith("::1")) return true;
  if (ip.startsWith("192.168.")) return true;
  const m = ip.match(/^172\.(\d+)\./);
  if (m && parseInt(m[1]) >= 16 && parseInt(m[1]) <= 31) return true;
  return false;
}

export default function SessionDetailPage() {
  const { id }   = useParams<{ id: string }>();
  const router   = useRouter();
  const [session,      setSession]      = useState<any>(null);
  const [timeline,     setTimeline]     = useState<any[]>([]);
  const [iocs,         setIocs]         = useState<any[]>([]);
  const [artifacts,    setArtifacts]    = useState<any[]>([]);
  const [tab,          setTab]          = useState<Tab>("timeline");
  const [loading,      setLoading]      = useState(true);
  const [expanded,     setExpanded]     = useState<Set<number>>(new Set());
  const [triageStatus, setTriageStatus] = useState("new");
  const [triageNote,   setTriageNote]   = useState("");
  const [triageSaving,      setTriageSaving]      = useState(false);
  const [triageSaved,       setTriageSaved]       = useState(false);
  const [relatedSessions,   setRelatedSessions]   = useState<any[]>([]);

  // ── AI Analysis state ──────────────────────────────────────────────────────
  const [aiModels,       setAiModels]       = useState<string[]>([]);
  const [aiEnabled,      setAiEnabled]      = useState(false);
  const [selectedModel,  setSelectedModel]  = useState("");
  const [aiType,         setAiType]         = useState<"threat_narrative" | "triage_assist">("threat_narrative");
  const [isStreaming,    setIsStreaming]     = useState(false);
  const [streamingText,  setStreamingText]  = useState("");
  const [pastAnalyses,   setPastAnalyses]   = useState<any[]>([]);
  const [triageResult,   setTriageResult]   = useState<any>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!id) return;
    Promise.all([
      fetch(apiPath(`/sessions/${id}`), { credentials: "include" }).then((r) => r.json()),
      fetch(apiPath(`/sessions/${id}/timeline`), { credentials: "include" }).then((r) => r.json()),
      fetch(apiPath(`/sessions/${id}/iocs`), { credentials: "include" }).then((r) => r.json()),
      fetch(apiPath(`/sessions/${id}/artifacts`), { credentials: "include" }).then((r) => r.json()),
    ]).then(([sess, tl, iocData, artData]) => {
      setSession(sess);
      setTimeline(tl.timeline ?? []);
      setIocs(iocData.items ?? []);
      setArtifacts(artData.items ?? []);
      setTriageStatus(sess.triage_status || "new");
      setTriageNote(sess.triage_note || "");
      // Fetch related sessions from same IP (exclude current)
      if (sess?.source_ip) {
        fetch(apiPath(`/sessions?source_ip=${encodeURIComponent(sess.source_ip)}&limit=6&sort_by=started_at&sort_dir=desc`), { credentials: "include" })
          .then((r) => r.ok ? r.json() : null)
          .then((d) => {
            if (d) setRelatedSessions((d.items ?? []).filter((s: any) => s.id !== id));
          });
      }
    }).finally(() => setLoading(false));
  }, [id]);

  function getCsrf() {
    return document.cookie.match(/csrf_token=([^;]+)/)?.[1] ?? "";
  }

  async function saveTriage() {
    setTriageSaving(true);
    const r = await fetch(apiPath(`/sessions/${id}/triage`), {
      method: "PATCH", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCsrf() },
      body: JSON.stringify({ triage_status: triageStatus, triage_note: triageNote }),
    });
    if (r.ok) { setTriageSaved(true); setTimeout(() => setTriageSaved(false), 2000); }
    setTriageSaving(false);
  }

  // Load AI models + past analyses when AI tab is first opened
  useEffect(() => {
    if (tab !== "ai" || !id) return;
    // Fetch available models
    fetch(apiPath("/llm/models"), { credentials: "include" })
      .then((r) => r.ok ? r.json() : null)
      .then((d) => {
        if (!d) return;
        setAiEnabled(d.enabled ?? false);
        setAiModels(d.models ?? []);
        if (!selectedModel && d.default_model) setSelectedModel(d.default_model);
      });
    // Fetch past analyses
    fetch(apiPath(`/llm/outputs/session/${id}`), { credentials: "include" })
      .then((r) => r.ok ? r.json() : { items: [] })
      .then((d) => setPastAnalyses(d.items ?? []));
  }, [tab, id]);

  if (loading) return <div className="flex items-center justify-center h-64 text-text-muted">Loading session…</div>;

  if (!session) return <div className="p-6 text-severity-high">Session not found</div>;

  async function startAnalysis() {
    if (isStreaming || !id) return;
    abortRef.current = new AbortController();
    setIsStreaming(true);
    setStreamingText("");
    setTriageResult(null);

    try {
      const resp = await fetch(apiPath(`/llm/analyze/session/${id}`), {
        method: "POST",
        signal: abortRef.current.signal,
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ analysis_type: aiType, model: selectedModel }),
      });
      if (!resp.ok || !resp.body) {
        const err = await resp.json().catch(() => ({}));
        setStreamingText(`[Error ${resp.status}] ${err?.detail || "LLM request failed"}`);
        return;
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let accumulated = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const payload = line.slice(6);
          if (payload === "[DONE]") {
            // Try parsing as triage JSON
            if (aiType === "triage_assist") {
              try { setTriageResult(JSON.parse(accumulated)); } catch { /* not valid JSON */ }
            }
            // Reload past analyses
            fetch(apiPath(`/llm/outputs/session/${id}`), { credentials: "include" })
              .then((r) => r.ok ? r.json() : { items: [] })
              .then((d) => setPastAnalyses(d.items ?? []));
            break;
          }
          try {
            const chunk = JSON.parse(payload) as string;
            accumulated += chunk;
            setStreamingText(accumulated);
          } catch { /* skip malformed */ }
        }
      }
    } catch (e: any) {
      if (e?.name !== "AbortError") setStreamingText("[Analysis cancelled or connection lost]");
    } finally {
      setIsStreaming(false);
    }
  }

  function stopAnalysis() {
    abortRef.current?.abort();
    setIsStreaming(false);
  }

  async function applyTriageRecommendation() {
    if (!triageResult || !id) return;
    const status = triageResult.recommended_status;
    const note = triageResult.suggested_note || "";
    setTriageStatus(status);
    setTriageNote(note);
    await saveTriage();
  }

  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: "timeline",  label: "Timeline",  count: timeline.length },
    { id: "iocs",      label: "IOCs",      count: iocs.length },
    { id: "artifacts", label: "Artifacts", count: artifacts.length },
    { id: "mitre",     label: "MITRE ATT&CK" },
    { id: "ai",        label: "AI Analysis" },
  ];

  return (
    <div className="p-6 space-y-4 animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button onClick={() => router.back()} className="btn-secondary p-2">
          <ChevronLeft className="w-4 h-4" />
        </button>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h1 className="text-lg font-bold font-mono flex items-center gap-2">
              {session.geo?.flag
                ? <span title={session.geo.country_name}>{session.geo.flag}</span>
                : isPrivateIp(session.source_ip)
                  ? (
                    <span
                      className="flex items-center gap-1 text-xs font-semibold px-1.5 py-0.5 rounded bg-bg-elevated text-text-faint border border-bg-border"
                      title="Private / internal network address — no GeoIP available"
                    >
                      <Network className="w-3 h-3" />INT
                    </span>
                  )
                  : null
              }
              <button
                className="hover:text-accent hover:underline transition-colors"
                onClick={() => router.push(`/attackers/${encodeURIComponent(session.source_ip)}`)}
              >
                {session.source_ip}
              </button>
            </h1>
            <SeverityBadge severity={session.severity} />
            <SignalTierBadge tier={session.signal_tier} />
            {session.cpu_stop_occurred && (
              <span className="badge-critical flex items-center gap-1">
                <Zap className="w-3 h-3" />CPU STOP
              </span>
            )}
          </div>
          <p className="text-xs text-text-muted mt-1 font-mono">Session {session.id}</p>
        </div>
        {session.ioc_count > 0 && (
          <a
            href={apiPath(`/sessions/${session.id}/export/stix`)}
            target="_blank" rel="noopener noreferrer"
            className="btn-secondary flex items-center gap-1.5 text-xs"
            title="Export IOCs as STIX 2.1 bundle"
          >
            <Download className="w-3.5 h-3.5" />STIX
          </a>
        )}
      </div>

      {/* Kill Chain Banner */}
      <KillChainBanner phase={session.attack_phase} />

      {/* Meta cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {[
          { label: "Protocol",    value: session.primary_protocol?.toUpperCase() },
          { label: "Phase",       value: session.attack_phase?.replace(/_/g, " ") },
          { label: "Events",      value: session.event_count },
          { label: "IOCs",        value: iocs.length },
          { label: "Duration",    value: formatDuration(session.duration_seconds) },
          { label: "Started",     value: formatDateTime(session.started_at) },
          { label: "Closed",      value: session.closed_at ? formatDateTime(session.closed_at) : "Active" },
          ...(session.source_port ? [{ label: "Src Port", value: String(session.source_port) }] : []),
          ...(session.sensor_id   ? [{ label: "Sensor",   value: session.sensor_id.slice(0, 8) + "…" }] : []),
          ...(session.geo?.country_name
            ? [{ label: "Country", value: `${session.geo.flag ?? ""} ${session.geo.country_name}`.trim() }]
            : isPrivateIp(session.source_ip)
              ? [{ label: "Origin", value: "🔒 Private Network" }]
              : []
          ),
          ...(session.geo?.city ? [{ label: "City",  value: session.geo.city }] : []),
          ...(session.geo?.org  ? [{ label: "ISP/Org", value: session.geo.org }] : []),
        ].map(({ label, value }) => (
          <div key={label} className="kpi-card">
            <span className="kpi-label">{label}</span>
            <span className="text-sm font-semibold text-text-primary mt-0.5">{value ?? "—"}</span>
          </div>
        ))}
      </div>

      {/* Triage panel */}
      <div className="card p-3 flex items-center gap-3 flex-wrap">
        <Shield className="w-4 h-4 text-text-muted flex-shrink-0" />
        <span className="text-xs font-semibold text-text-faint uppercase">Triage</span>
        <select
          className="input text-sm py-1 w-40"
          value={triageStatus}
          onChange={(e) => setTriageStatus(e.target.value)}
        >
          <option value="new">new</option>
          <option value="investigating">investigating</option>
          <option value="reviewed">reviewed</option>
          <option value="false_positive">false positive</option>
          <option value="escalated">escalated</option>
        </select>
        <input
          type="text"
          className="input text-sm py-1 flex-1 min-w-48"
          placeholder="Note (optional)"
          maxLength={500}
          value={triageNote}
          onChange={(e) => setTriageNote(e.target.value)}
        />
        <button
          onClick={saveTriage}
          disabled={triageSaving}
          className="btn-primary text-xs px-4 py-1.5 flex-shrink-0"
        >
          {triageSaved ? "Saved ✓" : triageSaving ? "Saving…" : "Save"}
        </button>
      </div>

      {/* Tabs */}
      <div className="card">
        <div className="flex border-b border-bg-border px-4">
          {tabs.map(({ id: tid, label, count }) => (
            <button key={tid}
              onClick={() => setTab(tid)}
              className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors -mb-px ${
                tab === tid
                  ? "border-accent text-accent"
                  : "border-transparent text-text-muted hover:text-text-primary"
              }`}>
              {label}
              {count !== undefined && (
                <span className="ml-1.5 text-xs bg-bg-elevated px-1.5 py-0.5 rounded-full">{count}</span>
              )}
            </button>
          ))}
        </div>

        <div className="p-4">
          {/* Timeline */}
          {tab === "timeline" && (
            <div className="space-y-0">
              {timeline.length === 0 ? (
                <p className="text-text-faint text-sm text-center py-8">No events</p>
              ) : (
                <div className="relative">
                  <div className="absolute left-[18px] top-0 bottom-0 w-px bg-bg-border" />
                  {timeline.map((ev, i) => (
                    <div key={i} className="flex gap-4 mb-3 relative">
                      <div className={`w-9 h-9 flex-shrink-0 rounded-full border-2 flex items-center justify-center z-10 ${
                        ev.severity === "critical" ? "border-severity-critical bg-red-900/30" :
                        ev.severity === "high"     ? "border-severity-high bg-orange-900/30" :
                        "border-bg-border bg-bg-surface"
                      }`}>
                        <Activity className="w-3.5 h-3.5 text-text-muted" />
                      </div>
                      <div className="flex-1 card p-3 hover:bg-bg-elevated transition-colors cursor-pointer"
                        onClick={() => setExpanded(prev => {
                          const next = new Set(prev);
                          next.has(i) ? next.delete(i) : next.add(i);
                          return next;
                        })}>
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <SeverityBadge severity={ev.severity} />
                              <span className="text-xs font-mono text-text-muted">{ev.event_type}</span>
                              {ev.dst_port && (
                                <span className="text-xs font-mono text-text-faint bg-bg-elevated px-1.5 py-0.5 rounded">
                                  :{ev.dst_port}
                                </span>
                              )}
                            </div>
                            <p className="text-sm text-text-primary">{ev.raw_summary}</p>
                            {ev.classification && (
                              <p className="text-xs text-text-faint mt-0.5">{ev.classification}</p>
                            )}
                          </div>
                          <span className="text-xs text-text-faint whitespace-nowrap font-mono ml-2">
                            {formatDateTime(ev.timestamp)}
                          </span>
                        </div>
                        {expanded.has(i) && ev.metadata && Object.keys(ev.metadata).length > 0 && (
                          <div className="mt-2 pt-2 border-t border-bg-border">
                            <pre className="payload-hex text-xs overflow-x-auto whitespace-pre-wrap break-all">
                              {JSON.stringify(ev.metadata, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* IOCs */}
          {tab === "iocs" && (
            <div>
              {iocs.length === 0 ? (
                <p className="text-text-faint text-sm text-center py-8">No IOCs extracted</p>
              ) : (
                <table className="data-table">
                  <thead><tr><th>Type</th><th>Value</th><th>Context</th><th>Confidence</th><th>First Seen</th></tr></thead>
                  <tbody>
                    {iocs.map((ioc) => (
                      <tr key={ioc.id}>
                        <td><span className="badge-medium">{ioc.ioc_type}</span></td>
                        <td className="font-mono text-xs max-w-xs truncate" title={ioc.value}>{ioc.value}</td>
                        <td className="text-xs text-text-muted">{ioc.context}</td>
                        <td className="text-xs tabular-nums">{(ioc.confidence * 100).toFixed(0)}%</td>
                        <td className="text-xs text-text-muted">{formatDateTime(ioc.first_seen_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* Artifacts */}
          {tab === "artifacts" && (
            <div className="space-y-3">
              {artifacts.length === 0 ? (
                <p className="text-text-faint text-sm text-center py-8">No artifacts captured</p>
              ) : artifacts.map((art) => (
                <div key={art.id} className="rounded-md border border-bg-border p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="badge-noise">{art.artifact_type}</span>
                    <span className="text-xs text-text-faint">{art.encoding}</span>
                    <span className="text-xs text-text-faint">{formatDateTime(art.created_at)}</span>
                  </div>
                  <div className="payload-hex">{art.value}</div>
                </div>
              ))}
            </div>
          )}

          {/* MITRE */}
          {tab === "mitre" && (() => {
            const techniques: any[] = session.mitre_techniques || [];
            if (techniques.length === 0) {
              return <p className="text-text-faint text-sm text-center py-8">No MITRE techniques mapped</p>;
            }
            // Group by tactic
            const byTactic: Record<string, any[]> = {};
            for (const t of techniques) {
              const tac = t.tactic || "Unknown";
              if (!byTactic[tac]) byTactic[tac] = [];
              byTactic[tac].push(t);
            }
            const tacticOrder = [
              "Initial Access", "Execution", "Persistence", "Lateral Movement",
              "Collection", "Discovery", "Command and Control",
              "Impair Process Control", "Inhibit Response Function", "Evasion", "Impact", "Unknown",
            ];
            const sortedTactics = Object.keys(byTactic).sort(
              (a, b) => (tacticOrder.indexOf(a) ?? 99) - (tacticOrder.indexOf(b) ?? 99)
            );
            const uniqueTactics = sortedTactics.length;
            return (
              <div className="space-y-4">
                {/* Coverage header */}
                <div className="card p-3 flex items-center gap-4 flex-wrap">
                  <span className="text-sm font-semibold text-text-primary">
                    {techniques.length} technique{techniques.length !== 1 ? "s" : ""} across {uniqueTactics} tactic{uniqueTactics !== 1 ? "s" : ""}
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {sortedTactics.map(tac => (
                      <span key={tac} className="px-2 py-0.5 rounded-full bg-accent/10 text-accent text-xs font-medium">
                        {tac} ({byTactic[tac].length})
                      </span>
                    ))}
                  </div>
                </div>
                {/* Grouped by tactic */}
                {sortedTactics.map(tactic => (
                  <div key={tactic}>
                    <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2 px-1">
                      {tactic}
                    </h3>
                    <div className="space-y-2">
                      {byTactic[tactic].map((t: any, i: number) => (
                        <div key={i} className="card p-4 flex items-start gap-4">
                          <div className="flex-shrink-0">
                            <span className="inline-block px-2 py-1 bg-accent/10 text-accent text-xs font-mono font-bold rounded">
                              {t.technique_id}
                            </span>
                          </div>
                          <div>
                            <p className="font-semibold text-sm text-text-primary">{t.technique_name}</p>
                            {t.description && (
                              <p className="text-xs text-text-faint mt-1.5 leading-relaxed">{t.description}</p>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            );
          })()}

          {/* AI Analysis */}
          {tab === "ai" && (
            <div className="space-y-4">
              {/* Controls */}
              <div className="card p-4 flex flex-wrap items-center gap-3">
                <Brain className="w-5 h-5 text-accent flex-shrink-0" />
                <div className="flex items-center gap-2 flex-wrap flex-1">
                  {/* Analysis type */}
                  <select
                    className="input text-sm py-1.5"
                    value={aiType}
                    onChange={(e) => setAiType(e.target.value as "threat_narrative" | "triage_assist")}
                    disabled={isStreaming}
                  >
                    <option value="threat_narrative">Threat Narrative</option>
                    <option value="triage_assist">Triage Assistant</option>
                  </select>

                  {/* Model selector */}
                  {aiEnabled && aiModels.length > 0 ? (
                    <select
                      className="input text-sm py-1.5"
                      value={selectedModel}
                      onChange={(e) => setSelectedModel(e.target.value)}
                      disabled={isStreaming}
                    >
                      {aiModels.map((m) => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                  ) : aiEnabled ? (
                    <input
                      type="text"
                      className="input text-sm py-1.5 w-44"
                      placeholder="Model name"
                      value={selectedModel}
                      onChange={(e) => setSelectedModel(e.target.value)}
                      disabled={isStreaming}
                    />
                  ) : null}

                  {/* Action buttons */}
                  {!isStreaming ? (
                    <button
                      onClick={startAnalysis}
                      disabled={!aiEnabled}
                      className="btn-primary text-xs px-4 py-1.5 flex items-center gap-1.5"
                      title={!aiEnabled ? "LLM disabled — set LLM_ENABLED=true in .env" : undefined}
                    >
                      <Brain className="w-3.5 h-3.5" />
                      Analyze
                    </button>
                  ) : (
                    <button onClick={stopAnalysis} className="btn-secondary text-xs px-4 py-1.5">
                      Cancel
                    </button>
                  )}
                </div>

                {/* Status indicator */}
                {!aiEnabled && (
                  <span className="text-xs text-text-faint bg-bg-elevated px-2.5 py-1 rounded border border-bg-border">
                    LLM disabled
                  </span>
                )}
                {isStreaming && (
                  <span className="text-xs text-accent animate-pulse">Generating…</span>
                )}
              </div>

              {/* Streaming output */}
              {streamingText && (
                <div className="card p-4">
                  {/* Triage assist JSON result */}
                  {aiType === "triage_assist" && triageResult ? (
                    <div className="space-y-3">
                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="text-sm font-semibold text-text-primary">Triage Recommendation</span>
                        <span className="badge-medium capitalize">{triageResult.recommended_status}</span>
                        <span className="text-xs text-text-faint">
                          Confidence: {Math.round((triageResult.confidence ?? 0) * 100)}%
                        </span>
                      </div>
                      {triageResult.reasoning && (
                        <p className="text-sm text-text-primary leading-relaxed">{triageResult.reasoning}</p>
                      )}
                      {triageResult.suggested_note && (
                        <p className="text-xs text-text-muted italic">&ldquo;{triageResult.suggested_note}&rdquo;</p>
                      )}
                      <button onClick={applyTriageRecommendation} className="btn-primary text-xs px-4 py-1.5">
                        Apply Recommendation
                      </button>
                    </div>
                  ) : (
                    <pre className="text-sm text-text-primary whitespace-pre-wrap leading-relaxed font-sans">
                      {streamingText}
                      {isStreaming && <span className="inline-block w-2 h-4 bg-accent ml-0.5 animate-pulse align-middle" />}
                    </pre>
                  )}
                </div>
              )}

              {/* Past analyses */}
              {pastAnalyses.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">Past Analyses</h3>
                  {pastAnalyses.map((a) => (
                    <details key={a.id} className="card group">
                      <summary className="px-4 py-3 flex items-center gap-3 cursor-pointer list-none select-none hover:bg-bg-elevated transition-colors rounded-lg">
                        <Brain className="w-4 h-4 text-text-faint flex-shrink-0" />
                        <span className="text-sm font-medium capitalize text-text-primary">
                          {a.output_type.replace(/_/g, " ")}
                        </span>
                        <span className="text-xs text-text-faint font-mono">{a.model_used}</span>
                        <span className="text-xs text-text-faint ml-auto">{formatDateTime(a.created_at)}</span>
                      </summary>
                      <div className="px-4 pb-4 border-t border-bg-border mt-0">
                        <pre className="text-sm text-text-primary whitespace-pre-wrap leading-relaxed font-sans pt-3">
                          {a.content}
                        </pre>
                      </div>
                    </details>
                  ))}
                </div>
              )}

              {/* Empty state */}
              {!streamingText && pastAnalyses.length === 0 && (
                <div className="text-center py-12 text-text-faint">
                  <Brain className="w-10 h-10 mx-auto mb-3 opacity-30" />
                  <p className="text-sm">No analyses yet.</p>
                  <p className="text-xs mt-1">
                    {aiEnabled
                      ? "Select an analysis type and click Analyze."
                      : "Enable LLM in your .env file to use AI analysis."}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Related sessions from same IP */}
      {relatedSessions.length > 0 && (
        <div className="card overflow-hidden">
          <div className="px-4 py-3 border-b border-bg-border flex items-center justify-between">
            <h2 className="font-semibold text-sm text-text-primary">
              Other Sessions from {session.source_ip}
              <span className="ml-2 text-xs font-normal text-text-faint">({relatedSessions.length} shown)</span>
            </h2>
            <button
              onClick={() => router.push(`/attackers/${encodeURIComponent(session.source_ip)}`)}
              className="text-xs text-accent hover:underline"
            >
              Full profile →
            </button>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Started</th>
                <th>Severity</th>
                <th>Signal</th>
                <th>Protocol</th>
                <th>Phase</th>
                <th>Events</th>
                <th>Duration</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {relatedSessions.map((s) => (
                <tr key={s.id} className="cursor-pointer" onClick={() => router.push(`/sessions/${s.id}`)}>
                  <td className="text-xs font-mono whitespace-nowrap">{formatDateTime(s.started_at)}</td>
                  <td><SeverityBadge severity={s.severity} /></td>
                  <td><SignalTierBadge tier={s.signal_tier} /></td>
                  <td className="text-xs uppercase text-text-muted">{s.primary_protocol}</td>
                  <td className="text-xs text-text-muted">{s.attack_phase?.replace(/_/g, " ")}</td>
                  <td className="text-xs tabular-nums">{s.event_count}</td>
                  <td className="text-xs text-text-muted">{formatDuration(s.duration_seconds)}</td>
                  <td className="text-xs capitalize text-text-muted">{(s.triage_status || "new").replace(/_/g, " ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
