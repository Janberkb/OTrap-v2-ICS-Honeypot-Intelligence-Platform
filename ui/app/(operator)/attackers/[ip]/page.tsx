"use client";

import { useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  Brain, ChevronLeft, Globe, Building2, MapPin, Shield, Activity,
  AlertTriangle, Zap, Clock, Network,
} from "lucide-react";
import { SeverityBadge, SignalTierBadge, formatDateTime, formatDuration } from "@/components/ui";
import { apiPath } from "@/lib/api";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "noise"];
const SEV_COLOR: Record<string, string> = {
  critical: "text-severity-critical",
  high:     "text-severity-high",
  medium:   "text-severity-medium",
  low:      "text-severity-low",
  noise:    "text-text-faint",
};

export default function AttackerProfilePage() {
  const { ip }  = useParams<{ ip: string }>();
  const router  = useRouter();
  const [profile,  setProfile]  = useState<any>(null);
  const [sessions, setSessions] = useState<any[]>([]);
  const [iocs,     setIocs]     = useState<any[]>([]);
  const [loading,  setLoading]  = useState(true);

  // AI Analysis state
  const [aiEnabled,      setAiEnabled]      = useState(false);
  const [aiModels,       setAiModels]       = useState<string[]>([]);
  const [selectedModel,  setSelectedModel]  = useState("");
  const [isStreaming,    setIsStreaming]     = useState(false);
  const [streamingText,  setStreamingText]  = useState("");
  const abortRef = useRef<AbortController | null>(null);

  const decodedIp = decodeURIComponent(ip);

  useEffect(() => {
    if (!decodedIp) return;
    Promise.all([
      fetch(apiPath(`/attackers/${encodeURIComponent(decodedIp)}`), { credentials: "include" }).then((r) => r.ok ? r.json() : null),
      fetch(apiPath(`/sessions?source_ip=${encodeURIComponent(decodedIp)}&limit=20&sort_by=started_at&sort_dir=desc`), { credentials: "include" }).then((r) => r.ok ? r.json() : null),
      fetch(apiPath(`/iocs?search=${encodeURIComponent(decodedIp)}&ioc_type=ip`), { credentials: "include" }).then((r) => r.ok ? r.json() : null),
    ]).then(([prof, sess, iocData]) => {
      if (prof)     setProfile(prof);
      if (sess)     setSessions(sess.items ?? []);
      if (iocData)  setIocs(iocData.items ?? []);
    }).finally(() => setLoading(false));
  }, [decodedIp]);

  useEffect(() => {
    fetch(apiPath("/llm/models"), { credentials: "include" })
      .then((r) => r.ok ? r.json() : null)
      .then((d) => {
        if (!d) return;
        setAiEnabled(d.enabled ?? false);
        setAiModels(d.models ?? []);
        if (!selectedModel && d.default_model) setSelectedModel(d.default_model);
      });
  }, []);

  async function startAttackerAnalysis() {
    if (isStreaming || !decodedIp) return;
    abortRef.current = new AbortController();
    setIsStreaming(true);
    setStreamingText("");
    try {
      const resp = await fetch(apiPath(`/llm/analyze/attacker/${encodeURIComponent(decodedIp)}`), {
        method: "POST",
        signal: abortRef.current.signal,
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ model: selectedModel }),
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
          if (payload === "[DONE]") break;
          try {
            const chunk = JSON.parse(payload) as string;
            accumulated += chunk;
            setStreamingText(accumulated);
          } catch { /* skip */ }
        }
      }
    } catch (e: any) {
      if (e?.name !== "AbortError") setStreamingText("[Analysis cancelled or connection lost]");
    } finally {
      setIsStreaming(false);
    }
  }

  function stopAttackerAnalysis() {
    abortRef.current?.abort();
    setIsStreaming(false);
  }

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center py-24 text-text-faint text-sm">
        Loading attacker profile…
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="p-6">
        <button onClick={() => router.back()} className="btn-secondary flex items-center gap-2 mb-6">
          <ChevronLeft className="w-4 h-4" />Back
        </button>
        <div className="card p-12 text-center text-text-faint text-sm">No data found for {decodedIp}</div>
      </div>
    );
  }

  const geo      = profile.geo ?? {};
  const ti       = profile.threat_intel ?? {};
  const gn       = ti.greynoise ?? null;
  const ab       = ti.abuseipdb ?? null;
  const topSev   = SEVERITY_ORDER.find((s) => (profile.severity_dist?.[s] ?? 0) > 0);
  const totalSevCount = Object.values(profile.severity_dist ?? {}).reduce((a: number, b) => a + (b as number), 0);

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button onClick={() => router.back()} className="btn-secondary p-2">
          <ChevronLeft className="w-4 h-4" />
        </button>
        <div className="flex items-center gap-3">
          {geo.flag && <span className="text-3xl">{geo.flag}</span>}
          <div>
            <h1 className="text-xl font-bold font-mono text-text-primary">{decodedIp}</h1>
            <p className="text-sm text-text-muted">
              {[geo.city, geo.country_name].filter(Boolean).join(", ") || "Unknown location"}
              {geo.org && <span className="ml-2 text-text-faint">· {geo.org}</span>}
            </p>
          </div>
          {profile.cpu_stop_ever && (
            <span className="flex items-center gap-1 text-severity-critical text-xs font-semibold bg-severity-critical/10 border border-severity-critical/30 px-2 py-1 rounded">
              <Zap className="w-3 h-3" />CPU STOP
            </span>
          )}
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Sessions",   value: profile.session_count,  icon: Shield,        color: "text-accent" },
          { label: "Events",     value: profile.event_count,    icon: Activity,      color: "text-severity-medium" },
          { label: "IOCs",       value: profile.ioc_count,      icon: AlertTriangle, color: "text-severity-high" },
          { label: "First Seen", value: formatDateTime(profile.first_seen), icon: Clock, color: "text-text-muted" },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="kpi-card">
            <div className="flex items-center justify-between mb-2">
              <span className="kpi-label">{label}</span>
              <Icon className={`w-4 h-4 ${color}`} />
            </div>
            <span className={`kpi-value ${color}`}>{value ?? "—"}</span>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* GeoIP + Severity distribution */}
        <div className="space-y-4">
          {/* GeoIP card */}
          <div className="card p-4 space-y-3">
            <h2 className="font-semibold text-sm text-text-primary">Location</h2>
            {[
              { icon: Globe,     label: "Country", value: geo.country_name },
              { icon: MapPin,    label: "City",    value: geo.city },
              { icon: Building2, label: "ISP/Org", value: geo.org },
            ].map(({ icon: Icon, label, value }) => value ? (
              <div key={label} className="flex items-center gap-3">
                <Icon className="w-4 h-4 text-text-faint flex-shrink-0" />
                <div>
                  <p className="text-xs text-text-faint">{label}</p>
                  <p className="text-sm text-text-primary">{value}</p>
                </div>
              </div>
            ) : null)}
          </div>

          {/* Severity distribution */}
          {totalSevCount > 0 && (
            <div className="card p-4">
              <h2 className="font-semibold text-sm text-text-primary mb-3">Severity Breakdown</h2>
              <div className="space-y-2">
                {SEVERITY_ORDER.filter((s) => profile.severity_dist?.[s]).map((s) => {
                  const count = profile.severity_dist[s];
                  const pct   = Math.round((count / totalSevCount) * 100);
                  return (
                    <div key={s} className="flex items-center gap-2">
                      <span className={`text-xs w-16 capitalize ${SEV_COLOR[s]}`}>{s}</span>
                      <div className="flex-1 h-1.5 bg-bg-base rounded-full overflow-hidden">
                        <div className={`h-full rounded-full ${
                          s === "critical" ? "bg-severity-critical" :
                          s === "high"     ? "bg-severity-high" :
                          s === "medium"   ? "bg-severity-medium" :
                          s === "low"      ? "bg-severity-low" :
                          "bg-bg-border"
                        }`} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-xs tabular-nums text-text-muted w-6 text-right">{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Protocol distribution */}
          {profile.protocol_dist?.length > 0 && (
            <div className="card p-4">
              <h2 className="font-semibold text-sm text-text-primary mb-3">Protocols</h2>
              <div className="flex flex-wrap gap-2">
                {profile.protocol_dist.map((p: any) => (
                  <span key={p.protocol} className="text-xs px-2 py-1 rounded bg-bg-elevated text-text-muted uppercase font-mono">
                    {p.protocol} <span className="text-text-faint">×{p.count}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Threat Intelligence */}
          {(gn !== null || ab !== null) && (
            <div className="card p-4 space-y-3">
              <h2 className="font-semibold text-sm text-text-primary">Threat Intelligence</h2>

              {/* GreyNoise */}
              {gn !== null && (
                <div className="space-y-1.5">
                  <p className="text-xs text-text-faint font-medium uppercase tracking-wider">GreyNoise</p>
                  {!gn.seen ? (
                    <span className="inline-flex items-center gap-1 text-xs text-text-faint bg-bg-elevated px-2 py-1 rounded">
                      Not observed
                    </span>
                  ) : (
                    <div className="flex flex-wrap gap-1.5">
                      {gn.riot && (
                        <span className="inline-flex items-center gap-1 text-xs font-medium bg-severity-low/10 text-severity-low border border-severity-low/30 px-2 py-1 rounded">
                          ✓ RIOT (known benign)
                        </span>
                      )}
                      {!gn.riot && gn.classification === "malicious" && (
                        <span className="inline-flex items-center gap-1 text-xs font-medium bg-severity-critical/10 text-severity-critical border border-severity-critical/30 px-2 py-1 rounded">
                          ✕ Malicious
                        </span>
                      )}
                      {!gn.riot && gn.classification === "benign" && (
                        <span className="inline-flex items-center gap-1 text-xs font-medium bg-severity-low/10 text-severity-low border border-severity-low/30 px-2 py-1 rounded">
                          ✓ Benign
                        </span>
                      )}
                      {gn.noise && (
                        <span className="text-xs text-text-faint bg-bg-elevated px-2 py-1 rounded">Internet noise</span>
                      )}
                      {gn.name && (
                        <span className="text-xs text-text-muted bg-bg-elevated px-2 py-1 rounded">{gn.name}</span>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* AbuseIPDB */}
              {ab !== null && (
                <div className="space-y-1.5">
                  <p className="text-xs text-text-faint font-medium uppercase tracking-wider">AbuseIPDB</p>
                  {ab.is_whitelisted ? (
                    <span className="inline-flex items-center gap-1 text-xs font-medium bg-severity-low/10 text-severity-low border border-severity-low/30 px-2 py-1 rounded">
                      ✓ Whitelisted
                    </span>
                  ) : (
                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-text-muted">Abuse confidence</span>
                        <span className={`text-xs font-semibold tabular-nums ${
                          ab.abuse_score >= 80 ? "text-severity-critical" :
                          ab.abuse_score >= 40 ? "text-severity-high" :
                          ab.abuse_score >= 10 ? "text-severity-medium" :
                          "text-text-faint"
                        }`}>{ab.abuse_score}%</span>
                      </div>
                      <div className="h-1.5 bg-bg-base rounded-full overflow-hidden">
                        <div className={`h-full rounded-full transition-all ${
                          ab.abuse_score >= 80 ? "bg-severity-critical" :
                          ab.abuse_score >= 40 ? "bg-severity-high" :
                          ab.abuse_score >= 10 ? "bg-severity-medium" :
                          "bg-bg-border"
                        }`} style={{ width: `${ab.abuse_score}%` }} />
                      </div>
                      {ab.total_reports > 0 && (
                        <p className="text-xs text-text-faint">{ab.total_reports} report{ab.total_reports !== 1 ? "s" : ""} in last 90 days</p>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* No API keys configured hint */}
          {gn === null && ab === null && (
            <div className="card p-4 border-dashed">
              <h2 className="font-semibold text-sm text-text-faint mb-1">Threat Intelligence</h2>
              <p className="text-xs text-text-faint">
                Set <code className="text-accent">GREYNOISE_API_KEY</code> and/or <code className="text-accent">ABUSEIPDB_API_KEY</code> in your <code>.env</code> to enable external enrichment.
              </p>
            </div>
          )}
        </div>

        {/* Sessions */}
        <div className="xl:col-span-2 space-y-4">
          <div className="card overflow-hidden">
            <div className="px-4 py-3 border-b border-bg-border flex items-center justify-between">
              <h2 className="font-semibold text-sm text-text-primary">Sessions</h2>
              <button
                onClick={() => router.push(`/sessions?source_ip=${encodeURIComponent(decodedIp)}`)}
                className="text-xs text-accent hover:underline"
              >
                View all →
              </button>
            </div>
            {sessions.length === 0 ? (
              <div className="py-8 text-center text-text-faint text-sm">No sessions</div>
            ) : (
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
                  {sessions.map((s) => (
                    <tr key={s.id} className="cursor-pointer" onClick={() => router.push(`/sessions/${s.id}`)}>
                      <td className="text-xs font-mono whitespace-nowrap">{formatDateTime(s.started_at)}</td>
                      <td><SeverityBadge severity={s.severity} /></td>
                      <td><SignalTierBadge tier={s.signal_tier} /></td>
                      <td className="text-xs uppercase text-text-muted">{s.primary_protocol}</td>
                      <td className="text-xs text-text-muted">{s.attack_phase?.replace(/_/g, " ")}</td>
                      <td className="text-xs tabular-nums">{s.event_count}</td>
                      <td className="text-xs text-text-muted">{formatDuration(s.duration_seconds)}</td>
                      <td className="text-xs">
                        <span className="capitalize text-text-muted">{(s.triage_status || "new").replace(/_/g, " ")}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* IOCs */}
          {iocs.length > 0 && (
            <div className="card overflow-hidden">
              <div className="px-4 py-3 border-b border-bg-border">
                <h2 className="font-semibold text-sm text-text-primary">IOCs</h2>
              </div>
              <table className="data-table">
                <thead>
                  <tr><th>Type</th><th>Value</th><th>Confidence</th><th>Sessions</th><th>Last Seen</th></tr>
                </thead>
                <tbody>
                  {iocs.map((ioc, i) => (
                    <tr key={i}>
                      <td className="text-xs uppercase font-mono text-text-muted">{ioc.ioc_type}</td>
                      <td className="text-xs font-mono">{ioc.value}</td>
                      <td className="text-xs tabular-nums">{Math.round((ioc.confidence ?? 0) * 100)}%</td>
                      <td className="text-xs tabular-nums">{ioc.session_count}</td>
                      <td className="text-xs text-text-muted whitespace-nowrap">{formatDateTime(ioc.last_seen_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* AI Threat Assessment */}
      <div className="card p-4 space-y-4">
        <div className="flex items-center gap-3 flex-wrap">
          <Brain className="w-5 h-5 text-accent flex-shrink-0" />
          <span className="font-semibold text-sm text-text-primary">AI Threat Assessment</span>

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

          {!isStreaming ? (
            <button
              onClick={startAttackerAnalysis}
              disabled={!aiEnabled}
              className="btn-primary text-xs px-4 py-1.5 flex items-center gap-1.5"
              title={!aiEnabled ? "LLM disabled — set LLM_ENABLED=true in .env" : undefined}
            >
              <Brain className="w-3.5 h-3.5" />
              Analyze Attacker
            </button>
          ) : (
            <button onClick={stopAttackerAnalysis} className="btn-secondary text-xs px-4 py-1.5">
              Cancel
            </button>
          )}

          {!aiEnabled && (
            <span className="text-xs text-text-faint bg-bg-elevated px-2.5 py-1 rounded border border-bg-border">LLM disabled</span>
          )}
          {isStreaming && <span className="text-xs text-accent animate-pulse">Generating…</span>}
        </div>

        {streamingText ? (
          <pre className="text-sm text-text-primary whitespace-pre-wrap leading-relaxed font-sans border-t border-bg-border pt-4">
            {streamingText}
            {isStreaming && <span className="inline-block w-2 h-4 bg-accent ml-0.5 animate-pulse align-middle" />}
          </pre>
        ) : (
          <p className="text-xs text-text-faint border-t border-bg-border pt-3">
            {aiEnabled
              ? "Generate an AI-powered threat intelligence assessment for this attacker based on all observed sessions, IOCs, and external enrichment."
              : "Enable LLM in your .env file (LLM_ENABLED=true) to use AI threat assessment."}
          </p>
        )}
      </div>
    </div>
  );
}
