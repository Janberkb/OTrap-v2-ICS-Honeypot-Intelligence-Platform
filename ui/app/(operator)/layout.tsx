"use client";

import { useEffect, useState, createContext, useContext } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { apiPath, streamUrl } from "@/lib/api";
import { BrandMark } from "@/components/brand-mark";
import {
  LayoutDashboard, Shield, Activity, Radio,
  Settings, LogOut, Users, Database, FileText,
  WifiOff, KeyRound, X, Bell
} from "lucide-react";

// ─── Live Stream Context ────────────────────────────────────────────────────

interface LiveEvent {
  event_id:   string;
  session_id: string;
  source_ip:  string;
  event_type: string;
  severity:   string;
  protocol:   string;
  summary:    string;
  timestamp:  string;
  cpu_stop:   boolean;
}

interface StatsData {
  total_sessions:    number;
  critical_sessions: number;
  cpu_stop_count:    number;
  events_24h:        number;
}

interface StreamCtx {
  events:   LiveEvent[];
  stats:    StatsData | null;
  connected: boolean;
}

interface EventSummary {
  id: string;
  session_id?: string | null;
  source_ip: string;
  event_type: string;
  severity: string;
  protocol: string;
  raw_summary?: string | null;
  timestamp: string;
}

interface NavItem {
  href: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  exact?: boolean;
  aliases?: string[];
}

const StreamContext = createContext<StreamCtx>({ events: [], stats: null, connected: false });
export const useStream = () => useContext(StreamContext);

function mergeEvents(current: LiveEvent[], incoming: LiveEvent[]): LiveEvent[] {
  const merged = [...incoming, ...current];
  const seen = new Set<string>();
  return merged.filter((event) => {
    if (seen.has(event.event_id)) {
      return false;
    }
    seen.add(event.event_id);
    return true;
  }).slice(0, 300);
}

function eventSummaryToLiveEvent(event: EventSummary): LiveEvent {
  return {
    event_id: event.id,
    session_id: event.session_id ?? "",
    source_ip: event.source_ip,
    event_type: event.event_type,
    severity: event.severity,
    protocol: event.protocol,
    summary: event.raw_summary ?? "",
    timestamp: event.timestamp,
    cpu_stop: event.event_type.toUpperCase().includes("CPU_STOP"),
  };
}

// ─── Operator layout ────────────────────────────────────────────────────────

export default function OperatorLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router   = useRouter();

  const [user,        setUser]        = useState<any>(null);
  const [events,      setEvents]      = useState<LiveEvent[]>([]);
  const [stats,       setStats]       = useState<StatsData | null>(null);
  const [connected,   setConnected]   = useState(false);
  const [showChgPw,   setShowChgPw]   = useState(false);
  const [bellOpen,    setBellOpen]    = useState(false);
  const [seenCount,   setSeenCount]   = useState(0);
  const [chgPwForm,   setChgPwForm]   = useState({ current: "", next: "", confirm: "" });
  const [chgPwError,  setChgPwError]  = useState("");
  const [chgPwOk,     setChgPwOk]     = useState(false);
  const [chgPwLoading,setChgPwLoading]= useState(false);

  function isPathActive({ href, exact, aliases = [] }: NavItem): boolean {
    const candidates = [href, ...aliases];
    return candidates.some((candidate) => (
      pathname === candidate || (!exact && pathname.startsWith(`${candidate}/`))
    ));
  }

  // ── Load current user ──────────────────────────────────────────────────
  useEffect(() => {
    fetch(apiPath("/auth/me"), { credentials: "include" })
      .then((r) => { if (!r.ok) { router.push("/login"); return null; } return r.json(); })
      .then((d) => d && setUser(d))
      .catch(() => router.push("/login"));
  }, [router]);

  // ── Hydrate recent events so dashboard is useful after refresh ────────
  useEffect(() => {
    fetch(apiPath("/events?limit=25"), { credentials: "include" })
      .then((r) => r.ok ? r.json() : null)
      .then((d) => {
        if (!d?.items) {
          return;
        }
        const recentEvents = (d.items as EventSummary[]).map(eventSummaryToLiveEvent);
        setEvents((prev) => mergeEvents(prev, recentEvents));
      })
      .catch(() => {});
  }, []);

  // ── SSE live stream ────────────────────────────────────────────────────
  useEffect(() => {
    let es: EventSource;
    let retryTimer: ReturnType<typeof setTimeout>;
    let retryCount = 0;

    function connect() {
      es = new EventSource(streamUrl("/stream"), { withCredentials: true });

      es.addEventListener("connected", () => {
        setConnected(true);
        retryCount = 0;
      });

      es.addEventListener("attack_event", (e) => {
        const ev: LiveEvent = JSON.parse(e.data);
        setEvents((prev) => mergeEvents(prev, [ev]));
      });

      es.addEventListener("stats_update", (e) => {
        setStats(JSON.parse(e.data));
      });

      es.onerror = () => {
        setConnected(false);
        es.close();
        retryCount += 1;
        // Exponential backoff: 2s, 4s, 8s … max 30s
        const delay = Math.min(2000 * 2 ** (retryCount - 1), 30000);
        retryTimer = setTimeout(connect, delay);
      };
    }

    connect();
    return () => { es?.close(); clearTimeout(retryTimer); };
  }, []);

  async function handleChangePassword() {
    setChgPwError(""); setChgPwOk(false);
    if (chgPwForm.next !== chgPwForm.confirm) {
      setChgPwError("New passwords do not match"); return;
    }
    if (chgPwForm.next.length < 12) {
      setChgPwError("New password must be at least 12 characters"); return;
    }
    setChgPwLoading(true);
    const csrf = document.cookie.match(/csrf_token=([^;]+)/)?.[1] ?? "";
    // Step 1: reauth
    const ra = await fetch(apiPath("/auth/reauth"), {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ password: chgPwForm.current }),
    });
    if (!ra.ok) { setChgPwError("Current password is incorrect"); setChgPwLoading(false); return; }
    // Step 2: change password
    const cp = await fetch(apiPath("/auth/change-password"), {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ current_password: chgPwForm.current, new_password: chgPwForm.next }),
    });
    setChgPwLoading(false);
    if (!cp.ok) {
      const d = await cp.json();
      setChgPwError(d.detail?.message ?? d.detail?.error ?? "Failed to change password");
      return;
    }
    setChgPwOk(true);
    setChgPwForm({ current: "", next: "", confirm: "" });
    setTimeout(() => { setShowChgPw(false); setChgPwOk(false); }, 1500);
  }

  async function handleLogout() {
    const csrf = document.cookie.match(/csrf_token=([^;]+)/)?.[1] ?? "";
    await fetch(apiPath("/auth/logout"), {
      method: "POST", credentials: "include",
      headers: { "X-CSRF-Token": csrf },
    });
    router.push("/login");
  }

  const navItems: NavItem[] = [
    { href: "/dashboard",  label: "Dashboard",   icon: LayoutDashboard },
    { href: "/sessions",   label: "Sessions",    icon: Shield },
    { href: "/sensors",    label: "Sensors",     icon: Radio },
    { href: "/health",     label: "Health",      icon: Activity },
  ];

  const adminItems: NavItem[] = user?.role === "superadmin" ? [
    { href: "/admin",               label: "System",       icon: Settings, exact: true },
    { href: "/admin/users",         label: "Users",        icon: Users },
    { href: "/admin/integrations",  label: "Integrations", icon: Database, aliases: ["/admin/notifications", "/admin/siem"] },
    { href: "/admin/audit",         label: "Audit Log",    icon: FileText },
  ] : [];

  return (
    <StreamContext.Provider value={{ events, stats, connected }}>
      <div className="flex h-screen overflow-hidden bg-bg-base">

        {/* ── Sidebar ─────────────────────────────────────────────────── */}
        <aside className="w-56 flex-shrink-0 flex flex-col border-r border-bg-border bg-bg-surface">
          {/* Brand */}
          <div className="px-4 py-4 border-b border-bg-border">
            <div className="rounded-xl border border-bg-border bg-bg-base/35 px-3 py-3">
              <BrandMark variant="lockup" width={128} priority className="h-auto w-auto" />
              <p className="mt-2 text-[10px] font-medium uppercase tracking-[0.24em] text-text-faint">
                Management Console
              </p>
            </div>
            {/* Stream status */}
            <div className="flex items-center gap-1.5 mt-2">
              {connected
                ? <><div className="live-dot" /><span className="text-xs text-severity-low">Live</span></>
                : <><WifiOff className="w-3 h-3 text-severity-high" /><span className="text-xs text-severity-high">Reconnecting…</span></>
              }
            </div>
          </div>

          {/* Operator nav */}
          <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
            <p className="px-3 py-1 text-xs font-semibold text-text-faint uppercase tracking-wider">Operator</p>
            {navItems.map((item) => {
              const { href, label, icon: Icon } = item;
              return (
              <Link key={href} href={href}
                className={`nav-item ${isPathActive(item) ? "active" : ""}`}>
                <Icon className="w-4 h-4 flex-shrink-0" />
                <span>{label}</span>
              </Link>
              );
            })}

            {adminItems.length > 0 && (
              <>
                <p className="px-3 py-1 mt-4 text-xs font-semibold text-text-faint uppercase tracking-wider">Administration</p>
                {adminItems.map((item) => {
                  const { href, label, icon: Icon } = item;
                  return (
                  <Link key={href} href={href}
                    className={`nav-item ${isPathActive(item) ? "active" : ""}`}>
                    <Icon className="w-4 h-4 flex-shrink-0" />
                    <span>{label}</span>
                  </Link>
                  );
                })}
              </>
            )}
          </nav>

          {/* User footer */}
          <div className="px-2 py-3 border-t border-bg-border">
            <div className="px-3 py-2 rounded-md bg-bg-elevated">
              <p className="text-xs font-medium text-text-primary truncate">{user?.username}</p>
              <p className="text-xs text-text-faint capitalize">{user?.role}</p>
            </div>
            <button onClick={() => { setShowChgPw(true); setChgPwError(""); setChgPwOk(false); }}
              className="nav-item w-full mt-1 text-text-faint hover:text-accent">
              <KeyRound className="w-4 h-4" />
              <span>Change Password</span>
            </button>
            <button onClick={handleLogout}
              className="nav-item w-full mt-1 text-text-faint hover:text-severity-critical">
              <LogOut className="w-4 h-4" />
              <span>Log out</span>
            </button>
          </div>
        </aside>

        {/* ── Main content ────────────────────────────────────────────── */}
        <main className="flex-1 overflow-y-auto flex flex-col">
          {/* Notification bar */}
          {(() => {
            const criticalEvents = events.filter((e) => e.severity === "critical" || e.severity === "high");
            const unreadCount = Math.max(0, criticalEvents.length - seenCount);
            return (
              <div className="flex-shrink-0 flex items-center justify-end px-4 py-1.5 border-b border-bg-border bg-bg-surface sticky top-0 z-10">
                <div className="relative">
                  <button
                    onClick={() => { setBellOpen((o) => !o); setSeenCount(criticalEvents.length); }}
                    className="relative p-1.5 rounded-md text-text-faint hover:text-text-primary hover:bg-bg-elevated transition-colors"
                    title="Alerts"
                  >
                    <Bell className="w-4 h-4" />
                    {unreadCount > 0 && (
                      <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 text-[10px] font-bold bg-severity-critical text-white rounded-full flex items-center justify-center px-0.5">
                        {unreadCount > 99 ? "99+" : unreadCount}
                      </span>
                    )}
                  </button>
                  {bellOpen && (
                    <div className="absolute right-0 mt-1 w-80 bg-bg-surface border border-bg-border rounded-xl shadow-xl z-50">
                      <div className="flex items-center justify-between px-3 py-2 border-b border-bg-border">
                        <span className="text-xs font-semibold text-text-muted uppercase">Recent Alerts</span>
                        <button onClick={() => setBellOpen(false)} className="text-text-faint hover:text-text-primary">
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                      {criticalEvents.length === 0 ? (
                        <p className="text-xs text-text-faint text-center py-6">No high/critical events yet</p>
                      ) : (
                        <div className="divide-y divide-bg-border max-h-72 overflow-y-auto">
                          {criticalEvents.slice(0, 5).map((ev) => (
                            <button
                              key={ev.event_id}
                              onClick={() => { setBellOpen(false); router.push(`/sessions/${ev.session_id}`); }}
                              className="w-full text-left px-3 py-2.5 hover:bg-bg-elevated transition-colors"
                            >
                              <div className="flex items-center justify-between gap-2 mb-0.5">
                                <span className={`text-xs font-semibold ${ev.severity === "critical" ? "text-severity-critical" : "text-severity-high"}`}>
                                  {ev.severity.toUpperCase()}
                                </span>
                                <span className="text-xs text-text-faint font-mono">{ev.source_ip}</span>
                              </div>
                              <p className="text-xs text-text-muted truncate">{ev.event_type.replace(/_/g, " ")}</p>
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })()}
          <div className="flex-1">
            {children}
          </div>
        </main>
      </div>
      {/* Change Password Modal */}
      {showChgPw && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-bg-surface border border-bg-border rounded-xl p-6 w-full max-w-sm shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold text-sm text-text-primary flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-accent" />Change Password
              </h2>
              <button onClick={() => setShowChgPw(false)} className="text-text-faint hover:text-text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>
            {chgPwOk ? (
              <p className="text-sm text-severity-low text-center py-4">Password changed successfully.</p>
            ) : (
              <div className="space-y-3">
                <div>
                  <label className="text-xs text-text-muted block mb-1">Current Password</label>
                  <input type="password" className="input w-full" value={chgPwForm.current}
                    onChange={(e) => setChgPwForm({ ...chgPwForm, current: e.target.value })} />
                </div>
                <div>
                  <label className="text-xs text-text-muted block mb-1">New Password <span className="text-text-faint">(min 12 chars)</span></label>
                  <input type="password" className="input w-full" value={chgPwForm.next}
                    onChange={(e) => setChgPwForm({ ...chgPwForm, next: e.target.value })} />
                </div>
                <div>
                  <label className="text-xs text-text-muted block mb-1">Confirm New Password</label>
                  <input type="password" className="input w-full" value={chgPwForm.confirm}
                    onChange={(e) => setChgPwForm({ ...chgPwForm, confirm: e.target.value })} />
                </div>
                {chgPwError && <p className="text-xs text-severity-critical">{chgPwError}</p>}
                <div className="flex gap-2 pt-1">
                  <button onClick={handleChangePassword} disabled={chgPwLoading}
                    className="btn-primary flex-1 text-sm disabled:opacity-50">
                    {chgPwLoading ? "Saving…" : "Save"}
                  </button>
                  <button onClick={() => setShowChgPw(false)} className="btn-secondary text-sm px-4">
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </StreamContext.Provider>
  );
}
