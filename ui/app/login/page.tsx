"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { apiPath } from "@/lib/api";
import { BrandMark } from "@/components/brand-mark";

type View = "login" | "forgot" | "forgot_sent" | "forgot_no_smtp";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error,    setError]    = useState("");
  const [loading,  setLoading]  = useState(false);
  const [csrf,     setCsrf]     = useState("");
  const [view,     setView]     = useState<View>("login");
  const [fgUser,   setFgUser]   = useState("");
  const [fgLoading,setFgLoading]= useState(false);

  // Fetch CSRF token on mount
  useEffect(() => {
    fetch(apiPath("/auth/csrf-token"), { credentials: "include" })
      .then((r) => r.json())
      .then((d) => setCsrf(d.csrf_token ?? ""))
      .catch(() => {});
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!csrf) { setError("CSRF token missing — reload the page"); return; }
    setLoading(true);
    setError("");

    try {
      const res = await fetch(apiPath("/auth/login"), {
        method:      "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token":  csrf,
        },
        body: JSON.stringify({ username, password }),
      });

      if (res.status === 429) { setError("Too many attempts. Try again in 60 seconds."); return; }
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        setError(d?.detail?.message ?? "Invalid username or password");
        return;
      }

      const user = await res.json();
      router.push(user.role === "superadmin" ? "/admin" : "/dashboard");
    } catch {
      setError("Network error — check your connection");
    } finally {
      setLoading(false);
    }
  }

  async function handleForgot(e: React.FormEvent) {
    e.preventDefault();
    setFgLoading(true);
    try {
      const res = await fetch(apiPath("/auth/forgot-password"), {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ username: fgUser }),
      });
      const d = await res.json().catch(() => ({}));
      if (d?.smtp_required) { setView("forgot_no_smtp"); }
      else { setView("forgot_sent"); }
    } catch {
      setView("forgot_sent"); // Don't reveal errors
    } finally {
      setFgLoading(false);
    }
  }

  return (
    <div className="relative min-h-screen overflow-hidden px-4">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,_rgb(255_255_255_/_0.03),_transparent_42%)]" />
      <div className="relative flex min-h-screen items-center justify-center py-10">
        <div className="w-full max-w-md">
          {/* Logo / Header */}
          <div className="text-center mb-8">
            <div className="mx-auto inline-flex items-center justify-center rounded-[26px] border border-accent/12 bg-bg-surface/72 px-4 py-3 shadow-[0_18px_40px_rgb(0_0_0_/_0.28)]">
              <BrandMark variant="lockup" width={286} priority className="h-auto w-auto" />
            </div>
            <p className="text-[11px] font-medium uppercase tracking-[0.28em] text-text-faint mt-4">Management Console</p>
            <p className="text-sm text-text-muted mt-2">Industrial deception operations for OT and ICS environments</p>
          </div>

          {/* Login card */}
          <div className="card p-7">
            {/* ── Login form ── */}
            {view === "login" && (
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label htmlFor="username">Username</label>
                  <input
                    id="username"
                    type="text"
                    className="input"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoComplete="username"
                    autoFocus
                    required
                  />
                </div>
                <div>
                  <label htmlFor="password">Password</label>
                  <input
                    id="password"
                    type="password"
                    className="input"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    required
                  />
                </div>
                {error && (
                  <div className="rounded-md bg-red-900/30 border border-red-800/40 px-3 py-2 text-sm text-severity-critical">
                    {error}
                  </div>
                )}
                <button type="submit" className="btn-primary w-full" disabled={loading || !csrf}>
                  {loading ? (
                    <span className="flex items-center justify-center gap-2">
                      <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                      </svg>
                      Logging in…
                    </span>
                  ) : "Log in"}
                </button>
                <div className="text-center">
                  <button type="button" onClick={() => { setView("forgot"); setError(""); }}
                    className="text-xs text-text-faint hover:text-accent transition-colors">
                    Forgot your password?
                  </button>
                </div>
              </form>
            )}

            {/* ── Forgot password form ── */}
            {view === "forgot" && (
              <form onSubmit={handleForgot} className="space-y-4">
                <div>
                  <h2 className="font-semibold text-sm text-text-primary mb-1">Reset Password</h2>
                  <p className="text-xs text-text-muted">Enter your username and we&apos;ll send a reset link to your registered email address.</p>
                </div>
                <div>
                  <label htmlFor="fg-username">Username</label>
                  <input id="fg-username" type="text" className="input" autoFocus required
                    value={fgUser} onChange={(e) => setFgUser(e.target.value)} />
                </div>
                <button type="submit" className="btn-primary w-full" disabled={fgLoading || !csrf}>
                  {fgLoading ? "Sending…" : "Send Reset Link"}
                </button>
                <div className="text-center">
                  <button type="button" onClick={() => setView("login")}
                    className="text-xs text-text-faint hover:text-accent transition-colors">
                    Back to login
                  </button>
                </div>
              </form>
            )}

            {/* ── Sent confirmation ── */}
            {view === "forgot_sent" && (
              <div className="space-y-4 text-center">
                <p className="text-sm text-text-primary">If an account with that username exists, a reset link has been sent to the registered email address.</p>
                <p className="text-xs text-text-muted">The link expires in 1 hour.</p>
                <button onClick={() => setView("login")} className="btn-secondary w-full text-sm">Back to login</button>
              </div>
            )}

            {/* ── No SMTP configured ── */}
            {view === "forgot_no_smtp" && (
              <div className="space-y-4 text-center">
                <p className="text-sm text-text-primary">Email-based password reset is not configured.</p>
                <p className="text-xs text-text-muted">Please contact your system administrator to reset your password.</p>
                <button onClick={() => setView("login")} className="btn-secondary w-full text-sm">Back to login</button>
              </div>
            )}
          </div>

          <p className="text-center text-xs text-text-faint mt-6">
            OTrap v2.0 · Enterprise ICS Deception Platform
          </p>
        </div>
      </div>
    </div>
  );
}
