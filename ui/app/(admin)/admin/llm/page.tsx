"use client";

import { useEffect, useState } from "react";
import { Brain, CheckCircle, XCircle, Loader, AlertTriangle } from "lucide-react";
import { apiPath } from "@/lib/api";

function getCsrf() {
  return document.cookie.match(/csrf_token=([^;]+)/)?.[1] ?? "";
}

export default function LLMConfigPage() {
  const [config,   setConfig]   = useState<any>(null);
  const [loading,  setLoading]  = useState(true);
  const [saving,   setSaving]   = useState(false);
  const [saved,    setSaved]    = useState(false);
  const [error,    setError]    = useState("");

  // Form state
  const [enabled,      setEnabled]      = useState(false);
  const [backend,      setBackend]      = useState("ollama");
  const [baseUrl,      setBaseUrl]      = useState("");
  const [defaultModel, setDefaultModel] = useState("");

  // Test connection state
  const [testing,      setTesting]      = useState(false);
  const [testResult,   setTestResult]   = useState<{ ok: boolean; models: string[]; detail?: string } | null>(null);

  useEffect(() => {
    fetch(apiPath("/admin/llm-config"), { credentials: "include" })
      .then((r) => r.ok ? r.json() : null)
      .then((d) => {
        if (!d) return;
        setConfig(d);
        setEnabled(d.llm_enabled ?? false);
        setBackend(d.llm_backend ?? "ollama");
        setBaseUrl(d.llm_base_url ?? "");
        setDefaultModel(d.llm_default_model ?? "");
      })
      .finally(() => setLoading(false));
  }, []);

  async function save() {
    setSaving(true);
    setError("");
    setSaved(false);
    const r = await fetch(apiPath("/admin/llm-config"), {
      method: "PATCH",
      credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCsrf() },
      body: JSON.stringify({
        llm_enabled:       enabled,
        llm_backend:       backend,
        llm_base_url:      baseUrl.trim(),
        llm_default_model: defaultModel.trim(),
      }),
    });
    if (r.ok) {
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
      // Invalidate layout badge cache
      localStorage.removeItem("llm_enabled_cache");
    } else {
      const d = await r.json().catch(() => ({}));
      setError(d?.detail || d?.error || "Save failed");
    }
    setSaving(false);
  }

  async function testConnection() {
    const url = baseUrl.trim();
    if (!url) return;
    setTesting(true);
    setTestResult(null);
    const r = await fetch(apiPath("/admin/llm-config/test"), {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ base_url: url, backend }),
    });
    const d = await r.json().catch(() => ({ ok: false, detail: "Invalid response" }));
    setTestResult(d);
    // Auto-fill model if empty and we got models back
    if (d.ok && d.models?.length > 0 && !defaultModel) {
      setDefaultModel(d.models[0]);
    }
    setTesting(false);
  }

  const placeholderUrl = backend === "lmstudio"
    ? "http://localhost:1234"
    : "http://localhost:11434";

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center py-24 text-text-faint text-sm">
        Loading LLM configuration…
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 animate-fade-in max-w-2xl">
      <div className="flex items-center gap-3">
        <Brain className="w-6 h-6 text-accent" />
        <div>
          <h1 className="text-xl font-bold">Local LLM Configuration</h1>
          <p className="text-sm text-text-muted mt-0.5">
            Connect OTrap to a local Ollama or LM Studio instance for AI-powered session and attacker analysis.
          </p>
        </div>
      </div>

      <div className="card p-5 space-y-5">
        {/* Enable toggle */}
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-text-primary">Enable AI Analysis</p>
            <p className="text-xs text-text-muted mt-0.5">
              When enabled, analysts can trigger LLM analysis from session and attacker pages.
            </p>
          </div>
          <button
            onClick={() => setEnabled((v) => !v)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              enabled ? "bg-accent" : "bg-bg-border"
            }`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
              enabled ? "translate-x-6" : "translate-x-1"
            }`} />
          </button>
        </div>

        <hr className="border-bg-border" />

        {/* Backend */}
        <div>
          <label className="text-xs text-text-muted block mb-1.5 font-medium uppercase tracking-wide">
            Backend
          </label>
          <div className="flex gap-2">
            {(["ollama", "lmstudio"] as const).map((b) => (
              <button
                key={b}
                onClick={() => { setBackend(b); setBaseUrl(""); setTestResult(null); }}
                className={`px-4 py-2 rounded-lg border text-sm font-medium transition-colors ${
                  backend === b
                    ? "border-accent bg-accent/10 text-accent"
                    : "border-bg-border text-text-muted hover:border-accent/50"
                }`}
              >
                {b === "ollama" ? "Ollama" : "LM Studio"}
              </button>
            ))}
          </div>
          <p className="text-xs text-text-faint mt-1.5">
            {backend === "ollama"
              ? "Ollama runs models locally. Default port 11434."
              : "LM Studio exposes an OpenAI-compatible server. Default port 1234."}
          </p>
        </div>

        {/* Base URL + test */}
        <div>
          <label className="text-xs text-text-muted block mb-1.5 font-medium uppercase tracking-wide">
            Base URL
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              className="input flex-1 text-sm"
              placeholder={placeholderUrl}
              value={baseUrl}
              onChange={(e) => { setBaseUrl(e.target.value); setTestResult(null); }}
            />
            <button
              onClick={testConnection}
              disabled={testing || !baseUrl.trim()}
              className="btn-secondary text-xs px-3 py-1.5 whitespace-nowrap flex items-center gap-1.5 disabled:opacity-50"
            >
              {testing ? <Loader className="w-3.5 h-3.5 animate-spin" /> : null}
              Test Connection
            </button>
          </div>

          {/* Test result */}
          {testResult && (
            <div className={`mt-2 rounded-lg border px-3 py-2.5 text-sm flex items-start gap-2 ${
              testResult.ok
                ? "border-severity-low/30 bg-severity-low/10"
                : "border-severity-critical/30 bg-severity-critical/10"
            }`}>
              {testResult.ok
                ? <CheckCircle className="w-4 h-4 text-severity-low flex-shrink-0 mt-0.5" />
                : <XCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />}
              <div>
                {testResult.ok ? (
                  <>
                    <p className="font-medium text-severity-low">Connection successful</p>
                    {testResult.models.length > 0 ? (
                      <p className="text-xs text-text-muted mt-0.5">
                        Available models: {testResult.models.join(", ")}
                      </p>
                    ) : (
                      <p className="text-xs text-text-muted mt-0.5">No models loaded yet.</p>
                    )}
                  </>
                ) : (
                  <>
                    <p className="font-medium text-severity-critical">Connection failed</p>
                    <p className="text-xs text-text-muted mt-0.5">{testResult.detail}</p>
                  </>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Default model */}
        <div>
          <label className="text-xs text-text-muted block mb-1.5 font-medium uppercase tracking-wide">
            Default Model
          </label>
          <input
            type="text"
            className="input w-full text-sm"
            placeholder="e.g. llama3.2, mistral, phi4"
            value={defaultModel}
            onChange={(e) => setDefaultModel(e.target.value)}
          />
          <p className="text-xs text-text-faint mt-1">
            Analysts can override this per analysis. Leave blank to require manual selection.
          </p>
        </div>

        {/* Env defaults hint */}
        {config?.env_defaults && (
          <div className="rounded-lg bg-bg-elevated border border-bg-border px-3 py-2.5 text-xs text-text-faint space-y-1">
            <p className="font-medium text-text-muted flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" />
              Environment variable defaults (read-only)
            </p>
            <p>LLM_ENABLED={String(config.env_defaults.llm_enabled)}, LLM_BACKEND={config.env_defaults.llm_backend}</p>
            <p>
              {config.env_defaults.llm_backend === "lmstudio"
                ? `LM_STUDIO_BASE_URL=${config.env_defaults.lm_studio_base_url}`
                : `OLLAMA_BASE_URL=${config.env_defaults.ollama_base_url}`}
            </p>
            <p>Values configured here override .env defaults and take effect immediately.</p>
          </div>
        )}

        {/* Save */}
        {error && (
          <p className="text-xs text-severity-critical">{error}</p>
        )}
        <div className="flex items-center gap-3 pt-1">
          <button
            onClick={save}
            disabled={saving}
            className="btn-primary px-6 py-2 text-sm disabled:opacity-50"
          >
            {saving ? "Saving…" : saved ? "Saved ✓" : "Save Configuration"}
          </button>
          {saved && (
            <span className="text-xs text-severity-low flex items-center gap-1">
              <CheckCircle className="w-3.5 h-3.5" />
              Configuration applied — no restart required
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
