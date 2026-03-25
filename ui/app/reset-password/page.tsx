"use client";

import { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { apiPath } from "@/lib/api";
import { BrandMark } from "@/components/brand-mark";

function ResetPasswordForm() {
  const router      = useRouter();
  const params      = useSearchParams();
  const token       = params.get("token") ?? "";

  const [newPw,     setNewPw]     = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [error,     setError]     = useState("");
  const [success,   setSuccess]   = useState(false);
  const [loading,   setLoading]   = useState(false);
  const [csrf,      setCsrf]      = useState("");

  useEffect(() => {
    fetch(apiPath("/auth/csrf-token"), { credentials: "include" })
      .then((r) => r.json())
      .then((d) => setCsrf(d.csrf_token ?? ""))
      .catch(() => {});
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (newPw !== confirmPw) { setError("Passwords do not match"); return; }
    if (newPw.length < 12)   { setError("Password must be at least 12 characters"); return; }
    if (!token)               { setError("Invalid reset link"); return; }

    setLoading(true);
    try {
      const res = await fetch(apiPath("/auth/reset-password"), {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ token, new_password: newPw }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        setError(d?.detail?.message ?? "Invalid or expired reset link");
        return;
      }
      setSuccess(true);
      setTimeout(() => router.push("/login"), 2500);
    } catch {
      setError("Network error — check your connection");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="relative min-h-screen overflow-hidden px-4">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,_rgb(255_255_255_/_0.03),_transparent_42%)]" />
      <div className="relative flex min-h-screen items-center justify-center py-10">
        <div className="w-full max-w-md">
          <div className="text-center mb-8">
            <div className="mx-auto inline-flex items-center justify-center rounded-[26px] border border-accent/12 bg-bg-surface/72 px-4 py-3 shadow-[0_18px_40px_rgb(0_0_0_/_0.28)]">
              <BrandMark variant="lockup" width={286} priority className="h-auto w-auto" />
            </div>
            <p className="text-[11px] font-medium uppercase tracking-[0.28em] text-text-faint mt-4">Management Console</p>
          </div>

          <div className="card p-7">
            {success ? (
              <div className="text-center space-y-3">
                <p className="text-sm text-severity-low font-medium">Password reset successful.</p>
                <p className="text-xs text-text-muted">Redirecting to login…</p>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <h2 className="font-semibold text-sm text-text-primary mb-1">Set New Password</h2>
                  <p className="text-xs text-text-muted">Choose a strong password of at least 12 characters.</p>
                </div>
                <div>
                  <label htmlFor="new-pw">New Password</label>
                  <input id="new-pw" type="password" className="input" autoFocus required
                    value={newPw} onChange={(e) => setNewPw(e.target.value)} />
                </div>
                <div>
                  <label htmlFor="confirm-pw">Confirm Password</label>
                  <input id="confirm-pw" type="password" className="input" required
                    value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} />
                </div>
                {error && (
                  <div className="rounded-md bg-red-900/30 border border-red-800/40 px-3 py-2 text-sm text-severity-critical">
                    {error}
                  </div>
                )}
                <button type="submit" className="btn-primary w-full" disabled={loading || !csrf || !token}>
                  {loading ? "Saving…" : "Reset Password"}
                </button>
              </form>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense>
      <ResetPasswordForm />
    </Suspense>
  );
}
