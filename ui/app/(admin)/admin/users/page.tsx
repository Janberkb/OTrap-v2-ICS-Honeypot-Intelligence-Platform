"use client";

import { useEffect, useState } from "react";
import { Plus, Pencil, Trash2, Shield, User } from "lucide-react";
import { formatDateTime, ReauthModal } from "@/components/ui";
import { apiPath } from "@/lib/api";
const getCSRF = () => document.cookie.match(/csrf_token=([^;]+)/)?.[1] ?? "";

interface OtrapUser {
  id: string; username: string; email: string;
  role: string; is_active: boolean; created_at: string; last_login_at: string;
}

export default function AdminUsersPage() {
  const [users,         setUsers]         = useState<OtrapUser[]>([]);
  const [loading,       setLoading]       = useState(true);
  const [showForm,      setShowForm]      = useState(false);
  const [editTarget,    setEditTarget]    = useState<OtrapUser | null>(null);
  const [deleteTarget,  setDeleteTarget]  = useState<OtrapUser | null>(null);
  const [reauthOpen,    setReauthOpen]    = useState(false);
  const [reauthLoading, setReauthLoading] = useState(false);
  const [reauthError,   setReauthError]   = useState("");
  const [form,          setForm]          = useState({ username: "", email: "", password: "", role: "user" });
  const [formError,     setFormError]     = useState("");
  const [editForm,      setEditForm]      = useState({ email: "", role: "user", new_password: "" });
  const [editError,     setEditError]     = useState("");

  async function load() {
    setLoading(true);
    const r = await fetch(apiPath("/admin/users"), { credentials: "include" });
    setUsers((await r.json()).items ?? []);
    setLoading(false);
  }

  useEffect(() => { load(); }, []);

  async function createUser() {
    setFormError("");
    const r = await fetch(apiPath("/admin/users"), {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify(form),
    });
    if (!r.ok) {
      const d = await r.json();
      setFormError(d.detail?.error ?? "Failed to create user");
      return;
    }
    setShowForm(false);
    setForm({ username: "", email: "", password: "", role: "user" });
    load();
  }

  function startEdit(u: OtrapUser) {
    setEditTarget(u);
    setEditForm({ email: u.email, role: u.role, new_password: "" });
    setEditError("");
  }

  async function saveEdit() {
    if (!editTarget) return;
    setEditError("");
    const body: Record<string, string> = { email: editForm.email, role: editForm.role };
    if (editForm.new_password) body.new_password = editForm.new_password;
    const r = await fetch(apiPath(`/admin/users/${editTarget.id}`), {
      method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const d = await r.json();
      setEditError(d.detail?.message ?? d.detail?.error ?? "Failed to update user");
      return;
    }
    setEditTarget(null);
    load();
  }

  async function toggleActive(u: OtrapUser) {
    await fetch(apiPath(`/admin/users/${u.id}`), {
      method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify({ is_active: !u.is_active }),
    });
    load();
  }

  function startDelete(u: OtrapUser) {
    setDeleteTarget(u);
    setReauthOpen(true);
  }

  async function doReauth(password: string) {
    setReauthLoading(true); setReauthError("");
    const r = await fetch(apiPath("/auth/reauth"), {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify({ password }),
    });
    if (!r.ok) { setReauthError("Incorrect password"); setReauthLoading(false); return; }
    setReauthOpen(false); setReauthLoading(false);
    if (deleteTarget) {
      await fetch(apiPath(`/admin/users/${deleteTarget.id}`), {
        method: "DELETE", credentials: "include",
        headers: { "X-CSRF-Token": getCSRF() },
      });
      setDeleteTarget(null);
      load();
    }
  }

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">User Management</h1>
          <p className="text-sm text-text-muted mt-0.5">{users.length} users</p>
        </div>
        <button className="btn-primary flex items-center gap-2" onClick={() => setShowForm(true)}>
          <Plus className="w-4 h-4" />New User
        </button>
      </div>

      {/* Create form */}
      {showForm && (
        <div className="card p-5 animate-slide-in">
          <h2 className="font-semibold text-sm mb-4">Create New User</h2>
          <div className="grid grid-cols-2 gap-3 mb-3">
            <div><label>Username</label>
              <input className="input" value={form.username} onChange={(e) => setForm({...form, username: e.target.value})} /></div>
            <div><label>Email</label>
              <input className="input" type="email" value={form.email} onChange={(e) => setForm({...form, email: e.target.value})} /></div>
            <div><label>Password (min 12 chars)</label>
              <input className="input" type="password" value={form.password} onChange={(e) => setForm({...form, password: e.target.value})} /></div>
            <div><label>Role</label>
              <select className="select" value={form.role} onChange={(e) => setForm({...form, role: e.target.value})}>
                <option value="user">User (Operator)</option>
                <option value="superadmin">Superadmin</option>
              </select>
            </div>
          </div>
          {formError && <p className="text-xs text-severity-critical mb-3">{formError}</p>}
          <div className="flex gap-2">
            <button className="btn-primary" onClick={createUser}>Create</button>
            <button className="btn-secondary" onClick={() => { setShowForm(false); setFormError(""); }}>Cancel</button>
          </div>
        </div>
      )}

      {/* Users table */}
      <div className="card overflow-hidden">
        <table className="data-table">
          <thead>
            <tr><th>User</th><th>Role</th><th>Status</th><th>Last Login</th><th>Created</th><th></th></tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="text-center text-text-faint py-12">Loading…</td></tr>
            ) : users.map((u) => (
              <>
                <tr key={u.id}>
                  <td>
                    <div>
                      <p className="font-semibold text-sm">{u.username}</p>
                      <p className="text-xs text-text-muted">{u.email}</p>
                    </div>
                  </td>
                  <td>
                    <div className="flex items-center gap-1.5">
                      {u.role === "superadmin"
                        ? <><Shield className="w-3.5 h-3.5 text-accent" /><span className="text-xs text-accent font-semibold">Superadmin</span></>
                        : <><User className="w-3.5 h-3.5 text-text-muted" /><span className="text-xs text-text-muted">Operator</span></>}
                    </div>
                  </td>
                  <td>
                    <button onClick={() => toggleActive(u)}
                      className={`text-xs font-medium px-2 py-0.5 rounded transition-colors ${
                        u.is_active
                          ? "bg-green-900/30 text-severity-low hover:bg-red-900/30 hover:text-severity-critical"
                          : "bg-red-900/30 text-severity-critical hover:bg-green-900/30 hover:text-severity-low"
                      }`}>
                      {u.is_active ? "Active" : "Disabled"}
                    </button>
                  </td>
                  <td className="text-xs text-text-muted">{formatDateTime(u.last_login_at)}</td>
                  <td className="text-xs text-text-muted">{formatDateTime(u.created_at)}</td>
                  <td>
                    <div className="flex items-center gap-1">
                      <button onClick={() => startEdit(u)}
                        className="text-text-faint hover:text-accent transition-colors p-1">
                        <Pencil className="w-4 h-4" />
                      </button>
                      <button onClick={() => startDelete(u)}
                        className="text-text-faint hover:text-severity-critical transition-colors p-1">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
                {editTarget?.id === u.id && (
                  <tr key={`${u.id}-edit`} className="bg-bg-elevated">
                    <td colSpan={6} className="px-4 py-3">
                      <div className="flex items-end gap-3 flex-wrap">
                        <div>
                          <label className="text-xs text-text-muted block mb-1">Email</label>
                          <input
                            className="input text-sm w-56"
                            type="email"
                            value={editForm.email}
                            onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
                          />
                        </div>
                        <div>
                          <label className="text-xs text-text-muted block mb-1">Role</label>
                          <select
                            className="select text-sm"
                            value={editForm.role}
                            onChange={(e) => setEditForm({ ...editForm, role: e.target.value })}
                          >
                            <option value="user">Operator</option>
                            <option value="superadmin">Superadmin</option>
                          </select>
                        </div>
                        <div className="flex gap-2">
                          <button onClick={saveEdit} className="btn-primary text-xs px-3 py-1.5">Save</button>
                          <button onClick={() => setEditTarget(null)} className="btn-secondary text-xs px-3 py-1.5">Cancel</button>
                        </div>
                        {editError && <p className="text-xs text-severity-critical">{editError}</p>}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>

      <ReauthModal
        open={reauthOpen}
        onConfirm={doReauth}
        onCancel={() => { setReauthOpen(false); setDeleteTarget(null); }}
        loading={reauthLoading}
        error={reauthError}
      />
    </div>
  );
}
