"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { ChevronLeft, Zap, Shield, Clock, Activity } from "lucide-react";
import { SeverityBadge, SignalTierBadge, formatDateTime, formatDuration } from "@/components/ui";
import { apiPath } from "@/lib/api";

type Tab = "timeline" | "iocs" | "artifacts" | "mitre";

export default function SessionDetailPage() {
  const { id }   = useParams<{ id: string }>();
  const router   = useRouter();
  const [session,   setSession]   = useState<any>(null);
  const [timeline,  setTimeline]  = useState<any[]>([]);
  const [iocs,      setIocs]      = useState<any[]>([]);
  const [artifacts, setArtifacts] = useState<any[]>([]);
  const [tab,       setTab]       = useState<Tab>("timeline");
  const [loading,   setLoading]   = useState(true);

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
    }).finally(() => setLoading(false));
  }, [id]);

  if (loading) return <div className="flex items-center justify-center h-64 text-text-muted">Loading session…</div>;
  if (!session) return <div className="p-6 text-severity-high">Session not found</div>;

  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: "timeline",  label: "Timeline",  count: timeline.length },
    { id: "iocs",      label: "IOCs",      count: iocs.length },
    { id: "artifacts", label: "Artifacts", count: artifacts.length },
    { id: "mitre",     label: "MITRE ATT&CK" },
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
            <h1 className="text-lg font-bold font-mono">{session.source_ip}</h1>
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
      </div>

      {/* Meta cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {[
          { label: "Protocol",   value: session.primary_protocol?.toUpperCase() },
          { label: "Phase",      value: session.attack_phase?.replace(/_/g, " ") },
          { label: "Events",     value: session.event_count },
          { label: "IOCs",       value: session.ioc_count },
          { label: "Duration",   value: formatDuration(session.duration_seconds) },
          { label: "Started",    value: formatDateTime(session.started_at) },
        ].map(({ label, value }) => (
          <div key={label} className="kpi-card">
            <span className="kpi-label">{label}</span>
            <span className="text-sm font-semibold text-text-primary mt-0.5">{value ?? "—"}</span>
          </div>
        ))}
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
                      <div className="flex-1 card p-3 hover:bg-bg-elevated transition-colors">
                        <div className="flex items-start justify-between gap-2">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <SeverityBadge severity={ev.severity} />
                              <span className="text-xs font-mono text-text-muted">{ev.event_type}</span>
                            </div>
                            <p className="text-sm text-text-primary">{ev.raw_summary}</p>
                            {ev.classification && (
                              <p className="text-xs text-text-faint mt-0.5">{ev.classification}</p>
                            )}
                          </div>
                          <span className="text-xs text-text-faint whitespace-nowrap font-mono">
                            {formatDateTime(ev.timestamp)}
                          </span>
                        </div>
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
          {tab === "mitre" && (
            <div className="space-y-3">
              {(!session.mitre_techniques || session.mitre_techniques.length === 0) ? (
                <p className="text-text-faint text-sm text-center py-8">No MITRE techniques mapped</p>
              ) : session.mitre_techniques.map((t: any, i: number) => (
                <div key={i} className="card p-4 flex items-start gap-4">
                  <div className="flex-shrink-0">
                    <span className="inline-block px-2 py-1 bg-accent/10 text-accent text-xs font-mono font-bold rounded">
                      {t.technique_id}
                    </span>
                  </div>
                  <div>
                    <p className="font-semibold text-sm text-text-primary">{t.technique_name}</p>
                    <p className="text-xs text-text-muted mt-0.5">Tactic: {t.tactic}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
