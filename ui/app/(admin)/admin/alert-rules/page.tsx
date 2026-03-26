"use client";

import { useEffect, useState } from "react";
import { Plus, Pencil, Trash2, Zap, X, ChevronDown, ChevronUp } from "lucide-react";
import { apiPath } from "@/lib/api";

const FIELDS = ["severity", "protocol", "event_type", "source_ip", "sensor_id"] as const;
const OPERATORS_BY_FIELD: Record<string, string[]> = {
  severity:   ["gte", "lte", "eq", "neq"],
  protocol:   ["eq", "neq", "in", "not_in"],
  event_type: ["eq", "neq", "in", "not_in", "contains"],
  source_ip:  ["eq", "neq", "in", "not_in", "contains"],
  sensor_id:  ["eq", "neq"],
};
const OPERATOR_LABEL: Record<string, string> = {
  eq:      "equals",
  neq:     "not equals",
  gte:     "≥ (at least)",
  lte:     "≤ (at most)",
  in:      "is one of",
  not_in:  "is not one of",
  contains:"contains",
};
const SEVERITY_VALUES = ["noise", "low", "medium", "high", "critical"];
const TRIAGE_OPTIONS = [
  { value: "", label: "— none —" },
  { value: "investigating",  label: "investigating" },
  { value: "reviewed",       label: "reviewed" },
  { value: "false_positive", label: "false positive" },
  { value: "escalated",      label: "escalated" },
];

type Condition = { field: string; operator: string; value: string };
type AlertRule = {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  conditions: Condition[];
  notify_smtp: boolean;
  notify_siem: boolean;
  auto_triage: string | null;
  window_seconds: number | null;
  threshold: number | null;
  created_at: string;
  updated_at: string;
};

const EMPTY_RULE = {
  name: "",
  description: "",
  enabled: true,
  conditions: [] as Condition[],
  notify_smtp: false,
  notify_siem: false,
  auto_triage: "",
  window_seconds: "" as string,
  threshold: "" as string,
};

function getCSRF(): string {
  return document.cookie.match(/csrf_token=([^;]+)/)?.[1] ?? "";
}

function SeverityBadge({ v }: { v: string }) {
  const cls: Record<string, string> = {
    noise: "badge-noise", low: "badge-low", medium: "badge-warning",
    high: "badge-high", critical: "badge-critical",
  };
  return <span className={cls[v] ?? "badge-noise"}>{v}</span>;
}

export default function AlertRulesPage() {
  const [rules,     setRules]     = useState<AlertRule[]>([]);
  const [loading,   setLoading]   = useState(true);
  const [modal,     setModal]     = useState<"create" | "edit" | null>(null);
  const [editTarget,setEditTarget]= useState<AlertRule | null>(null);
  const [form,      setForm]      = useState({ ...EMPTY_RULE });
  const [saving,    setSaving]    = useState(false);
  const [error,     setError]     = useState("");
  const [expanded,  setExpanded]  = useState<Set<string>>(new Set());

  async function load() {
    setLoading(true);
    const r = await fetch(apiPath("/admin/alert-rules"), { credentials: "include" });
    if (r.ok) setRules((await r.json()).items ?? []);
    setLoading(false);
  }

  useEffect(() => { void load(); }, []);

  function openCreate() {
    setForm({ ...EMPTY_RULE });
    setEditTarget(null);
    setError("");
    setModal("create");
  }

  function openEdit(rule: AlertRule) {
    setForm({
      name:           rule.name,
      description:    rule.description ?? "",
      enabled:        rule.enabled,
      conditions:     rule.conditions.map((c) => ({ ...c, value: Array.isArray(c.value) ? c.value.join(", ") : String(c.value) })),
      notify_smtp:    rule.notify_smtp,
      notify_siem:    rule.notify_siem,
      auto_triage:    rule.auto_triage ?? "",
      window_seconds: rule.window_seconds != null ? String(rule.window_seconds) : "",
      threshold:      rule.threshold      != null ? String(rule.threshold)      : "",
    });
    setEditTarget(rule);
    setError("");
    setModal("edit");
  }

  function closeModal() { setModal(null); setEditTarget(null); setError(""); }

  function addCondition() {
    setForm((f) => ({
      ...f,
      conditions: [...f.conditions, { field: "severity", operator: "gte", value: "high" }],
    }));
  }

  function removeCondition(idx: number) {
    setForm((f) => ({ ...f, conditions: f.conditions.filter((_, i) => i !== idx) }));
  }

  function updateCondition(idx: number, key: keyof Condition, val: string) {
    setForm((f) => {
      const conditions = [...f.conditions];
      const cond = { ...conditions[idx], [key]: val };
      // Reset operator when field changes
      if (key === "field") {
        const ops = OPERATORS_BY_FIELD[val] ?? ["eq"];
        cond.operator = ops[0];
        cond.value = val === "severity" ? "high" : "";
      }
      conditions[idx] = cond;
      return { ...f, conditions };
    });
  }

  async function save() {
    setSaving(true);
    setError("");

    const winSec   = form.window_seconds !== "" ? parseInt(form.window_seconds, 10) : null;
    const thresh   = form.threshold      !== "" ? parseInt(form.threshold,      10) : null;
    const body = {
      name:           form.name.trim(),
      description:    form.description.trim() || null,
      enabled:        form.enabled,
      conditions:     form.conditions.map((c) => ({
        field:    c.field,
        operator: c.operator,
        // Convert comma-separated to array for in/not_in operators
        value: c.operator === "in" || c.operator === "not_in"
          ? c.value.split(",").map((s) => s.trim()).filter(Boolean)
          : c.value,
      })),
      notify_smtp:    form.notify_smtp,
      notify_siem:    form.notify_siem,
      auto_triage:    form.auto_triage || null,
      window_seconds: winSec,
      threshold:      thresh,
    };

    const url   = modal === "edit" && editTarget ? apiPath(`/admin/alert-rules/${editTarget.id}`) : apiPath("/admin/alert-rules");
    const method = modal === "edit" ? "PATCH" : "POST";

    const r = await fetch(url, {
      method, credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify(body),
    });
    setSaving(false);
    if (r.ok) {
      closeModal();
      void load();
    } else {
      const d = await r.json().catch(() => ({}));
      setError(typeof d.detail === "string" ? d.detail : "Save failed");
    }
  }

  async function deleteRule(rule: AlertRule) {
    if (!confirm(`Delete rule "${rule.name}"?`)) return;
    await fetch(apiPath(`/admin/alert-rules/${rule.id}`), {
      method: "DELETE", credentials: "include",
      headers: { "X-CSRF-Token": getCSRF() },
    });
    void load();
  }

  async function toggleEnabled(rule: AlertRule) {
    const body = {
      name: rule.name, description: rule.description, enabled: !rule.enabled,
      conditions: rule.conditions, notify_smtp: rule.notify_smtp,
      notify_siem: rule.notify_siem, auto_triage: rule.auto_triage,
      window_seconds: rule.window_seconds, threshold: rule.threshold,
    };
    await fetch(apiPath(`/admin/alert-rules/${rule.id}`), {
      method: "PATCH", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify(body),
    });
    void load();
  }

  function toggleExpand(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text-primary flex items-center gap-2">
            <Zap className="w-5 h-5 text-accent" />Alert Rules
          </h1>
          <p className="text-sm text-text-muted mt-0.5">
            Define conditions that trigger notifications independently of global severity thresholds
          </p>
        </div>
        <button onClick={openCreate} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />New Rule
        </button>
      </div>

      {loading ? (
        <p className="text-sm text-text-faint">Loading…</p>
      ) : rules.length === 0 ? (
        <div className="card p-8 text-center space-y-2">
          <Zap className="w-8 h-8 text-text-faint mx-auto" />
          <p className="text-sm text-text-muted">No alert rules yet.</p>
          <p className="text-xs text-text-faint">
            Rules let you force SMTP/SIEM notifications or auto-triage sessions based on specific conditions.
          </p>
          <button onClick={openCreate} className="btn-primary text-xs mt-2">Create first rule</button>
        </div>
      ) : (
        <div className="space-y-2">
          {rules.map((rule) => {
            const isExpanded = expanded.has(rule.id);
            return (
              <div key={rule.id} className={`card overflow-hidden transition-opacity ${rule.enabled ? "" : "opacity-60"}`}>
                <div className="px-4 py-3 flex items-center gap-3">
                  {/* Enable toggle */}
                  <button
                    onClick={() => void toggleEnabled(rule)}
                    className={`w-9 h-5 rounded-full flex-shrink-0 transition-colors relative ${rule.enabled ? "bg-accent" : "bg-bg-border"}`}
                    title={rule.enabled ? "Disable rule" : "Enable rule"}
                  >
                    <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${rule.enabled ? "left-4" : "left-0.5"}`} />
                  </button>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-sm text-text-primary">{rule.name}</span>
                      {rule.notify_smtp && <span className="badge-noise text-[10px]">SMTP</span>}
                      {rule.notify_siem && <span className="badge-noise text-[10px]">SIEM</span>}
                      {rule.auto_triage && (
                        <span className="badge-warning text-[10px]">auto→{rule.auto_triage.replace("_", " ")}</span>
                      )}
                      {rule.window_seconds && rule.threshold && (
                        <span className="badge-noise text-[10px]" title={`Fires after ${rule.threshold} matches within ${rule.window_seconds}s`}>
                          ⏱ {rule.threshold}× / {rule.window_seconds}s
                        </span>
                      )}
                      {rule.conditions.length === 0 && (
                        <span className="text-[10px] text-severity-high">⚠ catch-all</span>
                      )}
                    </div>
                    {rule.description && (
                      <p className="text-xs text-text-faint truncate mt-0.5">{rule.description}</p>
                    )}
                  </div>

                  <div className="flex items-center gap-1 flex-shrink-0">
                    <button onClick={() => toggleExpand(rule.id)} className="p-1 text-text-faint hover:text-text-primary transition-colors" title="Show conditions">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                    <button onClick={() => openEdit(rule)} className="p-1 text-text-faint hover:text-accent transition-colors">
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                    <button onClick={() => void deleteRule(rule)} className="p-1 text-text-faint hover:text-severity-critical transition-colors">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {isExpanded && (
                  <div className="border-t border-bg-border px-4 py-3 bg-bg-base/40 space-y-2">
                    {rule.conditions.length === 0 ? (
                      <p className="text-xs text-severity-high">No conditions — this rule matches every event.</p>
                    ) : (
                      <div className="space-y-1.5">
                        <p className="text-[10px] font-semibold text-text-faint uppercase tracking-wider">Conditions (ALL must match)</p>
                        {rule.conditions.map((c, i) => (
                          <div key={i} className="flex items-center gap-2 text-xs font-mono">
                            <span className="text-accent">{c.field}</span>
                            <span className="text-text-faint">{OPERATOR_LABEL[c.operator] ?? c.operator}</span>
                            <span className="text-text-primary">
                              {Array.isArray(c.value) ? c.value.join(", ") : String(c.value)}
                            </span>
                            {c.field === "severity" && !Array.isArray(c.value) && (
                              <SeverityBadge v={String(c.value)} />
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                    {rule.window_seconds && rule.threshold && (
                      <div className="mt-1 px-3 py-2 rounded-md bg-bg-elevated border border-bg-border text-xs text-text-muted">
                        <span className="text-text-faint">Correlation: </span>
                        fires after <strong className="text-accent">{rule.threshold} matching events</strong> within a <strong className="text-accent">{rule.window_seconds}s</strong> window per source IP
                      </div>
                    )}
                    <div className="flex gap-4 pt-1 text-xs text-text-faint">
                      <span>Created {new Date(rule.created_at).toLocaleDateString()}</span>
                      {rule.updated_at !== rule.created_at && (
                        <span>Updated {new Date(rule.updated_at).toLocaleDateString()}</span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Create / Edit modal */}
      {modal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 overflow-y-auto">
          <div className="card w-full max-w-xl my-4 p-6 space-y-5 animate-slide-in">
            <div className="flex items-center justify-between">
              <h2 className="font-semibold text-text-primary flex items-center gap-2">
                <Zap className="w-4 h-4 text-accent" />
                {modal === "create" ? "New Alert Rule" : "Edit Alert Rule"}
              </h2>
              <button onClick={closeModal} className="text-text-faint hover:text-text-primary p-1">
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Basic info */}
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-text-muted mb-1">Rule Name <span className="text-severity-critical">*</span></label>
                <input className="input w-full text-sm" placeholder="e.g. Alert on any S7 CPU Stop"
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
              </div>
              <div>
                <label className="block text-xs text-text-muted mb-1">Description</label>
                <input className="input w-full text-sm" placeholder="Optional description"
                  value={form.description}
                  onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} />
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" id="rule_enabled" className="w-4 h-4 accent-accent"
                  checked={form.enabled}
                  onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))} />
                <label htmlFor="rule_enabled" className="text-xs text-text-muted cursor-pointer">Rule enabled</label>
              </div>
            </div>

            {/* Conditions */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-xs font-semibold text-text-faint uppercase tracking-wider">
                  Conditions <span className="normal-case font-normal">(ALL must match)</span>
                </p>
                <button onClick={addCondition} className="text-xs text-accent hover:underline flex items-center gap-1">
                  <Plus className="w-3 h-3" />Add condition
                </button>
              </div>

              {form.conditions.length === 0 && (
                <p className="text-xs text-severity-high bg-severity-high/10 border border-severity-high/20 rounded px-3 py-2">
                  No conditions — this rule will match every incoming event (catch-all).
                </p>
              )}

              {form.conditions.map((cond, idx) => (
                <div key={idx} className="flex items-center gap-2 bg-bg-elevated rounded-lg p-2">
                  {/* Field */}
                  <select className="select text-xs py-1 h-7"
                    value={cond.field}
                    onChange={(e) => updateCondition(idx, "field", e.target.value)}>
                    {FIELDS.map((f) => <option key={f} value={f}>{f}</option>)}
                  </select>

                  {/* Operator */}
                  <select className="select text-xs py-1 h-7"
                    value={cond.operator}
                    onChange={(e) => updateCondition(idx, "operator", e.target.value)}>
                    {(OPERATORS_BY_FIELD[cond.field] ?? ["eq"]).map((op) => (
                      <option key={op} value={op}>{OPERATOR_LABEL[op] ?? op}</option>
                    ))}
                  </select>

                  {/* Value */}
                  {cond.field === "severity" ? (
                    <select className="select text-xs py-1 h-7 flex-1"
                      value={cond.value}
                      onChange={(e) => updateCondition(idx, "value", e.target.value)}>
                      {SEVERITY_VALUES.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  ) : (
                    <input className="input text-xs flex-1 py-1 h-7"
                      placeholder={cond.operator === "in" || cond.operator === "not_in" ? "val1, val2, …" : "value"}
                      value={cond.value}
                      onChange={(e) => updateCondition(idx, "value", e.target.value)} />
                  )}

                  <button onClick={() => removeCondition(idx)} className="text-text-faint hover:text-severity-critical flex-shrink-0 p-0.5">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>

            {/* Correlation window */}
            <div className="space-y-2">
              <p className="text-xs font-semibold text-text-faint uppercase tracking-wider">Correlation Window <span className="normal-case font-normal text-text-faint">(optional)</span></p>
              <div className="bg-bg-elevated rounded-lg p-3 space-y-2">
                <p className="text-xs text-text-faint">
                  Leave blank to fire on every matching event. Set both fields to fire only after <em>N</em> matches within a time window (e.g. 10 S7_READ_VAR in 60 s → RECON alert).
                </p>
                <div className="flex items-center gap-3">
                  <label className="text-xs text-text-muted flex-shrink-0">Fire after</label>
                  <input
                    type="number" min={2} max={10000}
                    className="input text-xs w-24 py-1 h-7"
                    placeholder="e.g. 10"
                    value={form.threshold}
                    onChange={(e) => setForm((f) => ({ ...f, threshold: e.target.value }))}
                  />
                  <label className="text-xs text-text-muted flex-shrink-0">matches within</label>
                  <input
                    type="number" min={10} max={86400}
                    className="input text-xs w-24 py-1 h-7"
                    placeholder="e.g. 60"
                    value={form.window_seconds}
                    onChange={(e) => setForm((f) => ({ ...f, window_seconds: e.target.value }))}
                  />
                  <span className="text-xs text-text-faint">seconds</span>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className="space-y-2">
              <p className="text-xs font-semibold text-text-faint uppercase tracking-wider">Actions (when rule matches)</p>
              <div className="space-y-2 bg-bg-elevated rounded-lg p-3">
                <div className="flex items-center gap-2">
                  <input type="checkbox" id="act_smtp" className="w-4 h-4 accent-accent"
                    checked={form.notify_smtp}
                    onChange={(e) => setForm((f) => ({ ...f, notify_smtp: e.target.checked }))} />
                  <label htmlFor="act_smtp" className="text-xs text-text-muted cursor-pointer">
                    Force SMTP alert <span className="text-text-faint">(bypasses severity threshold and cooldown)</span>
                  </label>
                </div>
                <div className="flex items-center gap-2">
                  <input type="checkbox" id="act_siem" className="w-4 h-4 accent-accent"
                    checked={form.notify_siem}
                    onChange={(e) => setForm((f) => ({ ...f, notify_siem: e.target.checked }))} />
                  <label htmlFor="act_siem" className="text-xs text-text-muted cursor-pointer">
                    Force SIEM forward <span className="text-text-faint">(bypasses severity threshold and throttle)</span>
                  </label>
                </div>
                <div className="flex items-center gap-2 pt-1">
                  <label className="text-xs text-text-muted flex-shrink-0">Auto-triage to:</label>
                  <select className="select text-xs py-1 h-7"
                    value={form.auto_triage}
                    onChange={(e) => setForm((f) => ({ ...f, auto_triage: e.target.value }))}>
                    {TRIAGE_OPTIONS.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                </div>
              </div>
            </div>

            {error && <p className="text-xs text-severity-critical">{error}</p>}

            <div className="flex items-center justify-end gap-3 pt-1">
              <button onClick={closeModal} className="btn-secondary text-sm">Cancel</button>
              <button onClick={() => void save()} disabled={saving || !form.name.trim()} className="btn-primary text-sm disabled:opacity-60">
                {saving ? "Saving…" : modal === "create" ? "Create Rule" : "Save Changes"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
