// components/ui.tsx — Shared UI primitives

import { format, formatDistanceToNow } from "date-fns";

// ── Severity Badge ────────────────────────────────────────────────────────────

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = {
    critical: "badge-critical",
    high:     "badge-high",
    medium:   "badge-medium",
    low:      "badge-low",
    noise:    "badge-noise",
  }[severity?.toLowerCase()] ?? "badge-noise";

  return <span className={cls}>{severity}</span>;
}

// ── Signal Tier Badge ─────────────────────────────────────────────────────────

export function SignalTierBadge({ tier }: { tier: string }) {
  const styles: Record<string, string> = {
    impact:     "bg-red-900/30 text-severity-critical border border-red-800/40",
    suspicious: "bg-orange-900/30 text-severity-high border border-orange-800/40",
    recon:      "bg-yellow-900/30 text-severity-medium border border-yellow-800/40",
    noise:      "bg-gray-800/60 text-severity-noise border border-gray-700/40",
  };
  const cls = styles[tier?.toLowerCase()] ?? styles.noise;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${cls}`}>
      {tier}
    </span>
  );
}

// ── Health Status Badge ───────────────────────────────────────────────────────

export function HealthBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    healthy:   "bg-green-900/40 text-severity-low border border-green-800/40",
    degraded:  "bg-yellow-900/40 text-severity-medium border border-yellow-800/40",
    unhealthy: "bg-red-900/40 text-severity-critical border border-red-800/40",
    disabled:  "bg-gray-800/60 text-text-faint border border-gray-700/40",
    offline:   "bg-red-900/30 text-severity-critical border border-red-800/30",
  };
  const cls = styles[status?.toLowerCase()] ?? styles.disabled;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${cls}`}>
      {status}
    </span>
  );
}

// ── Time formatters ───────────────────────────────────────────────────────────

export function formatDateTime(ts: string | null | undefined): string {
  if (!ts) return "—";
  try {
    return format(new Date(ts), "MMM d, HH:mm:ss");
  } catch {
    return ts;
  }
}

export function formatTime(ts: string | null | undefined): string {
  if (!ts) return "—";
  try {
    return format(new Date(ts), "HH:mm:ss");
  } catch {
    return ts;
  }
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  if (seconds < 1)    return `${seconds.toFixed(1)}s`;
  if (seconds < 60)   return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

export function formatRelative(ts: string | null | undefined): string {
  if (!ts) return "—";
  try {
    return formatDistanceToNow(new Date(ts), { addSuffix: true });
  } catch {
    return ts;
  }
}

// ── Confirm dialog hook ───────────────────────────────────────────────────────

export function ReauthModal({
  open, onConfirm, onCancel, loading, error,
}: {
  open: boolean;
  onConfirm: (password: string) => void;
  onCancel: () => void;
  loading: boolean;
  error: string;
}) {
  if (!open) return null;

  let pw = "";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="card w-full max-w-sm p-6 shadow-2xl animate-slide-in">
        <h2 className="font-bold text-lg mb-1">Re-authentication Required</h2>
        <p className="text-sm text-text-muted mb-4">
          This action requires you to confirm your password.
        </p>
        <label>Current Password</label>
        <input
          type="password"
          className="input mb-3"
          autoFocus
          onChange={(e) => { pw = e.target.value; }}
          onKeyDown={(e) => e.key === "Enter" && onConfirm(pw)}
        />
        {error && <p className="text-xs text-severity-critical mb-3">{error}</p>}
        <div className="flex gap-2">
          <button className="btn-primary flex-1" disabled={loading} onClick={() => onConfirm(pw)}>
            {loading ? "Verifying…" : "Confirm"}
          </button>
          <button className="btn-secondary flex-1" onClick={onCancel}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

// ── Empty state ───────────────────────────────────────────────────────────────

export function EmptyState({ message = "No data" }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-text-faint gap-3">
      <svg viewBox="0 0 48 48" className="w-12 h-12 opacity-30" fill="none" stroke="currentColor" strokeWidth="1.5">
        <rect x="8" y="8" width="32" height="32" rx="4" />
        <path d="M16 24h16M16 32h8" strokeLinecap="round" />
      </svg>
      <p className="text-sm">{message}</p>
    </div>
  );
}
