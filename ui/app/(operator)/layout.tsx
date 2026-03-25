"use client";

import { useEffect, useState, createContext, useContext } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { apiPath, streamUrl } from "@/lib/api";
import { BrandMark } from "@/components/brand-mark";
import {
  LayoutDashboard, Shield, Activity, Radio,
  Settings, LogOut, Users, Database, FileText,
  WifiOff
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

  const [user,      setUser]      = useState<any>(null);
  const [events,    setEvents]    = useState<LiveEvent[]>([]);
  const [stats,     setStats]     = useState<StatsData | null>(null);
  const [connected, setConnected] = useState(false);

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
            <button onClick={handleLogout}
              className="nav-item w-full mt-1 text-text-faint hover:text-severity-critical">
              <LogOut className="w-4 h-4" />
              <span>Log out</span>
            </button>
          </div>
        </aside>

        {/* ── Main content ────────────────────────────────────────────── */}
        <main className="flex-1 overflow-y-auto">
          {children}
        </main>
      </div>
    </StreamContext.Provider>
  );
}
