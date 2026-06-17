import React, { useState, useEffect, useCallback } from 'react'
import {
  Users, Plus, Edit2, Trash2, CreditCard, RefreshCw,
  Search, ChevronUp, ChevronDown, X, Save, AlertTriangle,
  UserCheck, Crown, Webhook, CheckCircle, XCircle, Loader, ShieldCheck, ExternalLink
} from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

function WebhooksSection() {
  const toast = useToast()
  const [webhooks, setWebhooks] = useState([])
  const [showAdd, setShowAdd] = useState(false)
  const [testingId, setTestingId] = useState(null)
  const [form, setForm] = useState({ name: '', url: '', events: ['simulation_complete'], secret: '' })

  const fetchWebhooks = async () => {
    try {
      const r = await api.get('/api/webhooks')
      setWebhooks(r.data.webhooks || [])
    } catch {}
  }

  useEffect(() => { fetchWebhooks() }, [])

  const handleAdd = async () => {
    if (!form.name.trim() || !form.url.trim()) { toast('Preencha nome e URL', 'warning'); return }
    try {
      await api.post('/api/webhooks', { name: form.name, url: form.url, events: form.events, secret: form.secret || undefined })
      setShowAdd(false)
      setForm({ name: '', url: '', events: ['simulation_complete'], secret: '' })
      fetchWebhooks()
      toast('Webhook criado!', 'success')
    } catch (err) {
      toast('Erro: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  const handleDelete = async (id) => {
    try {
      await api.delete(`/api/webhooks/${id}`)
      fetchWebhooks()
      toast('Webhook removido', 'success')
    } catch (err) {
      toast('Erro: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  const handleTest = async (id) => {
    setTestingId(id)
    try {
      const r = await api.post(`/api/webhooks/${id}/test`)
      toast(`Webhook respondeu: HTTP ${r.data?.status ?? 'OK'}`, 'success')
    } catch (err) {
      toast('Falha: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setTestingId(null)
    }
  }

  const toggleEvent = (ev) => {
    setForm(f => ({
      ...f,
      events: f.events.includes(ev) ? f.events.filter(e => e !== ev) : [...f.events, ev]
    }))
  }

  return (
    <div className="bg-dark-800 border border-dark-600 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Webhook className="w-5 h-5 text-cyan-400" />
          <h2 className="text-xl font-bold text-gray-100">Integrações — Webhooks</h2>
        </div>
        <button onClick={() => setShowAdd(true)} className="flex items-center gap-2 text-sm px-3 py-1.5 bg-cyan-700 hover:bg-cyan-600 text-white rounded transition">
          <Plus className="w-4 h-4" /> Adicionar Webhook
        </button>
      </div>
      <p className="text-gray-400 text-sm mb-4">Receba notificações automáticas quando simulações completarem ou vulnerabilidades críticas forem encontradas.</p>

      {webhooks.length === 0 ? (
        <div className="text-center py-10 border border-dashed border-dark-600 rounded-lg">
          <Webhook className="w-8 h-8 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-500 text-sm">Nenhum webhook configurado ainda.</p>
          <p className="text-gray-600 text-xs mt-1">Compatível com Slack, Discord, Teams e qualquer endpoint HTTP.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {webhooks.map(hook => (
            <div key={hook.id} className="flex items-center justify-between p-4 bg-dark-700 border border-dark-600 rounded-lg">
              <div>
                <p className="font-semibold text-gray-100">{hook.name}</p>
                <p className="text-xs text-gray-400 font-mono mt-0.5">{hook.url}</p>
                <div className="flex gap-1 mt-1">
                  {(hook.events || []).map(ev => (
                    <span key={ev} className="text-[10px] px-1.5 py-0.5 rounded bg-dark-600 text-cyan-400 border border-dark-500">{ev}</span>
                  ))}
                  {hook.has_secret && <span className="text-[10px] px-1.5 py-0.5 rounded bg-dark-600 text-yellow-400 border border-dark-500">HMAC ✓</span>}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleTest(hook.id)}
                  disabled={testingId === hook.id}
                  className="text-xs px-2 py-1 rounded bg-dark-600 hover:bg-dark-500 text-cyan-400 border border-dark-500 transition flex items-center gap-1 disabled:opacity-50"
                >
                  {testingId === hook.id ? <Loader className="w-3 h-3 animate-spin" /> : <CheckCircle className="w-3 h-3" />}
                  Testar
                </button>
                <button onClick={() => handleDelete(hook.id)} className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-red-900/20 rounded transition">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {showAdd && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 border border-dark-600 rounded-xl w-full max-w-md">
            <div className="flex items-center justify-between px-6 py-4 border-b border-dark-700">
              <h3 className="text-lg font-bold text-gray-100">Adicionar Webhook</h3>
              <button onClick={() => setShowAdd(false)} className="text-gray-500 hover:text-gray-300 transition"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Nome</label>
                <input type="text" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="ex: Slack #alerts" className="input-dark w-full" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">URL do Webhook</label>
                <input type="text" value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))} placeholder="https://hooks.slack.com/..." className="input-dark w-full" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Eventos</label>
                <div className="space-y-2">
                  {[
                    { v: 'simulation_complete', l: 'Simulação Completa' },
                    { v: 'vuln_critical_found', l: 'Vulnerabilidade Crítica Encontrada' },
                  ].map(({ v, l }) => (
                    <label key={v} className="flex items-center gap-2 cursor-pointer text-sm text-gray-300">
                      <input type="checkbox" checked={form.events.includes(v)} onChange={() => toggleEvent(v)} className="rounded" />
                      {l}
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Secret HMAC <span className="text-gray-500 font-normal">(opcional)</span></label>
                <input type="text" value={form.secret} onChange={e => setForm(f => ({ ...f, secret: e.target.value }))} placeholder="senha para assinar os payloads" className="input-dark w-full" />
              </div>
            </div>
            <div className="flex justify-end gap-2 px-6 pb-6">
              <button onClick={() => setShowAdd(false)} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded transition">Cancelar</button>
              <button onClick={handleAdd} className="px-4 py-2 bg-cyan-700 hover:bg-cyan-600 text-white rounded transition">Criar Webhook</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Spinner() {
  return <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
}

function Modal({ title, onClose, children }) {
  return (
    <div
      className="fixed inset-0 bg-black/75 flex items-center justify-center z-50 p-4"
      onClick={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="bg-dark-800 border border-dark-600 rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-dark-700">
          <h3 className="text-lg font-bold text-gray-100">{title}</h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition p-1">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-6">{children}</div>
      </div>
    </div>
  )
}

function AdminStatCard({ title, value, icon: Icon, colorClass }) {
  return (
    <div className={`rounded-lg border p-5 ${colorClass}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm opacity-70 mb-1">{title}</p>
          <p className="text-3xl font-bold">{value}</p>
        </div>
        <Icon className="w-10 h-10 opacity-30" />
      </div>
    </div>
  )
}

function SortTh({ label, field, sortField, sortDir, onSort }) {
  const active = sortField === field
  return (
    <th
      className="px-4 py-3 text-xs font-semibold text-gray-400 cursor-pointer hover:text-gray-200 transition select-none whitespace-nowrap text-left"
      onClick={() => onSort(field)}
    >
      {label}{' '}
      {active && (sortDir === 'asc'
        ? <ChevronUp className="w-3 h-3 inline" />
        : <ChevronDown className="w-3 h-3 inline" />
      )}
    </th>
  )
}

function CreateUserModal({ onClose, onSuccess }) {
  const toast = useToast()
  const [form, setForm] = useState({ username: '', email: '', password: '', is_admin: false, credits: 0 })
  const [saving, setSaving] = useState(false)

  const submit = async e => {
    e.preventDefault()
    setSaving(true)
    try {
      await api.post('/api/admin/users', form)
      toast('Usuário criado com sucesso', 'success')
      onSuccess()
    } catch (err) {
      toast(err.response?.data?.detail || 'Erro ao criar usuário', 'error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal title="Novo Usuário" onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Usuário</label>
          <input required className="input-dark w-full" value={form.username}
            onChange={e => setForm({ ...form, username: e.target.value })} placeholder="nome_usuario" />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">E-mail</label>
          <input required type="email" className="input-dark w-full" value={form.email}
            onChange={e => setForm({ ...form, email: e.target.value })} placeholder="user@exemplo.com" />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Senha</label>
          <input required type="password" className="input-dark w-full" value={form.password}
            onChange={e => setForm({ ...form, password: e.target.value })} placeholder="••••••••" />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Créditos iniciais</label>
          <input type="number" min="0" className="input-dark w-full" value={form.credits}
            onChange={e => setForm({ ...form, credits: parseInt(e.target.value) || 0 })} />
        </div>
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input type="checkbox" className="w-4 h-4 accent-red-600" checked={form.is_admin}
            onChange={e => setForm({ ...form, is_admin: e.target.checked })} />
          <span className="text-sm text-gray-300">Administrador</span>
        </label>
        <div className="flex gap-3 pt-2">
          <button type="button" onClick={onClose} className="flex-1 btn-outline-red">Cancelar</button>
          <button type="submit" disabled={saving}
            className="flex-1 btn-blue flex items-center justify-center gap-2 disabled:opacity-60">
            {saving ? <Spinner /> : <Plus className="w-4 h-4" />}
            Criar Usuário
          </button>
        </div>
      </form>
    </Modal>
  )
}

function EditUserModal({ user, onClose, onSuccess }) {
  const toast = useToast()
  const [form, setForm] = useState({
    username: user.username,
    email: user.email,
    password: '',
    is_admin: user.is_admin,
    status: user.status || 'active',
  })
  const [saving, setSaving] = useState(false)

  const submit = async e => {
    e.preventDefault()
    setSaving(true)
    const payload = { ...form }
    if (!payload.password) delete payload.password
    try {
      await api.put(`/api/admin/users/${user.id}`, payload)
      toast('Usuário atualizado com sucesso', 'success')
      onSuccess()
    } catch (err) {
      toast(err.response?.data?.detail || 'Erro ao atualizar', 'error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal title={`Editar: ${user.username}`} onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Usuário</label>
          <input required className="input-dark w-full" value={form.username}
            onChange={e => setForm({ ...form, username: e.target.value })} />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">E-mail</label>
          <input required type="email" className="input-dark w-full" value={form.email}
            onChange={e => setForm({ ...form, email: e.target.value })} />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">
            Nova Senha <span className="text-gray-600">(vazio = manter atual)</span>
          </label>
          <input type="password" className="input-dark w-full" value={form.password}
            onChange={e => setForm({ ...form, password: e.target.value })} placeholder="••••••••" />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Status</label>
          <select className="select-dark w-full" value={form.status}
            onChange={e => setForm({ ...form, status: e.target.value })}>
            <option value="active">Ativo</option>
            <option value="suspended">Suspenso</option>
          </select>
        </div>
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input type="checkbox" className="w-4 h-4 accent-red-600" checked={form.is_admin}
            onChange={e => setForm({ ...form, is_admin: e.target.checked })} />
          <span className="text-sm text-gray-300">Administrador</span>
        </label>
        <div className="flex gap-3 pt-2">
          <button type="button" onClick={onClose} className="flex-1 btn-outline-red">Cancelar</button>
          <button type="submit" disabled={saving}
            className="flex-1 btn-blue flex items-center justify-center gap-2 disabled:opacity-60">
            {saving ? <Spinner /> : <Save className="w-4 h-4" />}
            Salvar
          </button>
        </div>
      </form>
    </Modal>
  )
}

function CreditsUserModal({ user, onClose, onSuccess }) {
  const toast = useToast()
  const [action, setAction] = useState('add')
  const [amount, setAmount] = useState(100)
  const [saving, setSaving] = useState(false)

  const submit = async (act, amt) => {
    setSaving(true)
    try {
      const res = await api.post(`/api/admin/users/${user.id}/credits`, {
        action: act,
        amount: parseInt(amt) || 0,
      })
      toast(`Créditos atualizados: ${res.data?.credits ?? '?'} total`, 'success')
      onSuccess()
    } catch (err) {
      toast(err.response?.data?.detail || 'Erro ao atualizar créditos', 'error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal title={`Créditos: ${user.username}`} onClose={onClose}>
      <div className="space-y-5">
        <div className="text-center py-5 bg-dark-700 rounded-lg">
          <p className="text-xs text-gray-400 mb-1">Saldo Atual</p>
          <p className="text-5xl font-bold text-yellow-400">{user.credits ?? 0}</p>
          <p className="text-xs text-gray-500 mt-1">créditos</p>
        </div>

        <div>
          <label className="block text-xs text-gray-400 mb-2">Operação</label>
          <div className="flex gap-2">
            {[{ v: 'add', label: '+ Adicionar' }, { v: 'remove', label: '− Remover' }].map(opt => (
              <button key={opt.v} type="button" onClick={() => setAction(opt.v)}
                className={`flex-1 py-2 rounded-lg text-sm font-medium transition border ${
                  action === opt.v
                    ? 'bg-red-600 border-red-600 text-white'
                    : 'bg-dark-700 border-dark-600 text-gray-400 hover:border-red-600/60'
                }`}>
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-xs text-gray-400 mb-1">Quantidade</label>
          <input type="number" min="1" className="input-dark w-full" value={amount}
            onChange={e => setAmount(e.target.value)} />
        </div>

        <div className="flex gap-2">
          <button type="button" onClick={() => submit('set', 0)} disabled={saving}
            className="px-4 py-2 text-xs text-red-400 border border-red-700/50 hover:bg-red-900/20 rounded-lg transition disabled:opacity-50">
            Zerar
          </button>
          <button type="button" onClick={onClose} className="flex-1 btn-outline-red">Cancelar</button>
          <button type="button" onClick={() => submit(action, amount)} disabled={saving}
            className="flex-1 btn-blue flex items-center justify-center gap-2 disabled:opacity-60">
            {saving ? <Spinner /> : <CreditCard className="w-4 h-4" />}
            Confirmar
          </button>
        </div>
      </div>
    </Modal>
  )
}

function DeleteUserModal({ user, onClose, onSuccess }) {
  const toast = useToast()
  const [deleting, setDeleting] = useState(false)

  const confirm = async () => {
    setDeleting(true)
    try {
      await api.delete(`/api/admin/users/${user.id}`)
      toast(`Usuário "${user.username}" deletado`, 'success')
      onSuccess()
    } catch (err) {
      toast(err.response?.data?.detail || 'Erro ao deletar', 'error')
      setDeleting(false)
    }
  }

  return (
    <Modal title="Confirmar Exclusão" onClose={onClose}>
      <div className="space-y-5">
        <div className="flex items-start gap-3 p-4 bg-red-900/20 border border-red-700/40 rounded-lg">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-gray-200">
              Deletar <strong className="text-red-400">{user.username}</strong>?
            </p>
            <p className="text-xs text-gray-400 mt-1">
              Irreversível — todos os dados do usuário serão removidos.
            </p>
          </div>
        </div>
        <div className="flex gap-3">
          <button onClick={onClose} className="flex-1 btn-outline-red">Cancelar</button>
          <button onClick={confirm} disabled={deleting}
            className="flex-1 bg-red-700 hover:bg-red-600 disabled:opacity-60 text-white py-2 rounded-lg font-medium transition text-sm flex items-center justify-center gap-2">
            {deleting ? <Spinner /> : <Trash2 className="w-4 h-4" />}
            Deletar
          </button>
        </div>
      </div>
    </Modal>
  )
}

function SSOConfigSection() {
  const toast = useToast()
  const [ssoProvider, setSsoProvider] = useState('azure')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [extraConfig, setExtraConfig] = useState({})
  const [saving, setSaving] = useState(false)

  const handleSave = async () => {
    if (!clientId.trim() || !clientSecret.trim()) {
      toast('Preencha Client ID e Client Secret', 'warning')
      return
    }
    setSaving(true)
    try {
      await api.post('/api/auth/sso/configure', {
        provider: ssoProvider,
        client_id: clientId,
        client_secret: clientSecret,
        extra_config: extraConfig,
      })
      toast('Configuração SSO salva com sucesso!', 'success')
    } catch (err) {
      toast('Erro ao salvar: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setSaving(false)
    }
  }

  const handleTestSSO = async () => {
    try {
      const res = await api.get('/api/auth/sso/authorize', {
        params: { provider: ssoProvider, redirect_uri: window.location.origin + '/sso-callback' }
      })
      const url = res.data?.authorization_url || res.data?.url
      if (url) window.open(url, '_blank')
      else toast('URL de autorização não retornada pelo servidor', 'error')
    } catch (err) {
      toast('Erro ao iniciar SSO: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  return (
    <div className="bg-dark-800 border border-dark-600 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-indigo-400" />
          <h2 className="text-xl font-bold text-gray-100">Configuração SSO</h2>
        </div>
        <button
          onClick={handleTestSSO}
          className="flex items-center gap-2 text-sm px-3 py-1.5 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-gray-300 rounded transition"
        >
          <ExternalLink className="w-3.5 h-3.5" /> Testar SSO
        </button>
      </div>
      <p className="text-gray-400 text-sm mb-5">Configure o provedor de identidade para login SSO (Single Sign-On) da plataforma.</p>

      <div className="space-y-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Provedor</label>
          <select
            className="select-dark w-full"
            value={ssoProvider}
            onChange={e => { setSsoProvider(e.target.value); setExtraConfig({}) }}
          >
            <option value="azure">Microsoft Azure AD</option>
            <option value="google">Google Workspace</option>
            <option value="okta">Okta</option>
            <option value="generic">Generic OIDC</option>
          </select>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs text-gray-400 mb-1">Client ID</label>
            <input
              type="text"
              className="input-dark w-full font-mono text-sm"
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              value={clientId}
              onChange={e => setClientId(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Client Secret</label>
            <input
              type="password"
              className="input-dark w-full font-mono text-sm"
              placeholder="••••••••••••••••"
              value={clientSecret}
              onChange={e => setClientSecret(e.target.value)}
            />
          </div>
        </div>

        {ssoProvider === 'azure' && (
          <div>
            <label className="block text-xs text-gray-400 mb-1">Tenant ID</label>
            <input
              type="text"
              className="input-dark w-full font-mono text-sm"
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              value={extraConfig.tenant_id || ''}
              onChange={e => setExtraConfig(ec => ({ ...ec, tenant_id: e.target.value }))}
            />
          </div>
        )}

        {ssoProvider === 'okta' && (
          <div>
            <label className="block text-xs text-gray-400 mb-1">Okta Domain</label>
            <input
              type="text"
              className="input-dark w-full font-mono text-sm"
              placeholder="sua-empresa.okta.com"
              value={extraConfig.domain || ''}
              onChange={e => setExtraConfig(ec => ({ ...ec, domain: e.target.value }))}
            />
          </div>
        )}

        {ssoProvider === 'generic' && (
          <div>
            <label className="block text-xs text-gray-400 mb-1">Issuer URL</label>
            <input
              type="text"
              className="input-dark w-full font-mono text-sm"
              placeholder="https://sso.suaempresa.com"
              value={extraConfig.issuer_url || ''}
              onChange={e => setExtraConfig(ec => ({ ...ec, issuer_url: e.target.value }))}
            />
          </div>
        )}

        <div className="pt-2">
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 px-5 py-2.5 bg-indigo-700 hover:bg-indigo-600 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition"
          >
            {saving ? <Loader className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            Salvar Configuração SSO
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Admin() {
  const toast = useToast()
  const [users, setUsers] = useState([])
  const [stats, setStats] = useState({ total_users: 0, active_users: 0, total_credits: 0, new_this_month: 0 })
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [sortField, setSortField] = useState('created_at')
  const [sortDir, setSortDir] = useState('desc')

  const [showCreate, setShowCreate] = useState(false)
  const [editUser, setEditUser] = useState(null)
  const [creditsUser, setCreditsUser] = useState(null)
  const [deleteUser, setDeleteUser] = useState(null)

  const fetchData = useCallback(async () => {
    try {
      const [ur, sr] = await Promise.all([
        api.get('/api/admin/users'),
        api.get('/api/admin/stats'),
      ])
      setUsers(ur.data.users || [])
      setStats(sr.data)
    } catch {
      toast('Sem permissão ou erro ao carregar dados do admin', 'error')
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => { fetchData() }, [fetchData])

  const handleSort = field => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('asc') }
  }

  const filtered = users
    .filter(u =>
      (u.username ?? '').toLowerCase().includes(search.toLowerCase()) ||
      (u.email ?? '').toLowerCase().includes(search.toLowerCase())
    )
    .sort((a, b) => {
      let av = a[sortField] ?? '', bv = b[sortField] ?? ''
      if (typeof av === 'string') { av = av.toLowerCase(); bv = bv.toLowerCase() }
      if (av < bv) return sortDir === 'asc' ? -1 : 1
      if (av > bv) return sortDir === 'asc' ? 1 : -1
      return 0
    })

  if (loading) return (
    <div className="flex items-center justify-center py-24">
      <div className="w-8 h-8 border-2 border-red-600 border-t-transparent rounded-full animate-spin" />
    </div>
  )

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100">
            Painel <span className="text-red-600">Administrativo</span>
          </h1>
          <p className="text-gray-400 mt-1">Gerencie usuários, créditos e permissões</p>
        </div>
        <button onClick={() => setShowCreate(true)} className="btn-blue flex items-center gap-2">
          <Plus className="w-4 h-4" /> Novo Usuário
        </button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <AdminStatCard title="Total de Usuários" value={stats.total_users} icon={Users}
          colorClass="bg-blue-900/20 border-blue-700/40 text-blue-300" />
        <AdminStatCard title="Usuários Ativos" value={stats.active_users} icon={UserCheck}
          colorClass="bg-green-900/20 border-green-700/40 text-green-300" />
        <AdminStatCard title="Total de Créditos" value={stats.total_credits} icon={CreditCard}
          colorClass="bg-yellow-900/20 border-yellow-700/40 text-yellow-300" />
        <AdminStatCard title="Novos este Mês" value={stats.new_this_month} icon={Crown}
          colorClass="bg-purple-900/20 border-purple-700/40 text-purple-300" />
      </div>

      <div className="card-dark overflow-hidden">
        <div className="flex items-center gap-4 p-4 border-b border-dark-700">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              className="input-dark w-full pl-9"
              placeholder="Buscar por usuário ou e-mail..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <button onClick={fetchData} title="Atualizar"
            className="p-2 text-gray-400 hover:text-gray-100 hover:bg-dark-700 rounded-lg transition">
            <RefreshCw className="w-4 h-4" />
          </button>
          <span className="text-sm text-gray-500 hidden sm:block">{filtered.length} usuário(s)</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-dark-700">
                <SortTh label="Usuário" field="username" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                <SortTh label="E-mail" field="email" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                <SortTh label="Créditos" field="credits" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                <SortTh label="Papel" field="is_admin" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                <SortTh label="Status" field="status" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                <SortTh label="Criado em" field="created_at" sortField={sortField} sortDir={sortDir} onSort={handleSort} />
                <th className="px-4 py-3 text-xs font-semibold text-gray-400 text-right">Ações</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(user => (
                <tr key={user.id} className="border-b border-dark-700/40 hover:bg-dark-700/25 transition">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {user.is_admin && <Crown className="w-3.5 h-3.5 text-yellow-400 flex-shrink-0" />}
                      <span className="text-sm font-medium text-gray-200">{user.username}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-400 max-w-[180px] truncate">{user.email}</td>
                  <td className="px-4 py-3">
                    <span className="text-sm font-mono font-bold text-yellow-400">{user.credits ?? 0}</span>
                  </td>
                  <td className="px-4 py-3">
                    {user.is_admin
                      ? <span className="px-2 py-0.5 rounded text-xs bg-red-900/40 text-red-400 border border-red-700/40 font-medium">Admin</span>
                      : <span className="px-2 py-0.5 rounded text-xs bg-dark-700 text-gray-500 border border-dark-600">Usuário</span>
                    }
                  </td>
                  <td className="px-4 py-3">
                    <span className={`flex items-center gap-1.5 text-xs ${user.status === 'active' ? 'text-green-400' : 'text-red-400'}`}>
                      <span className={`w-1.5 h-1.5 rounded-full inline-block ${user.status === 'active' ? 'bg-green-400' : 'bg-red-400'}`} />
                      {user.status === 'active' ? 'Ativo' : 'Suspenso'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">
                    {user.created_at ? new Date(user.created_at).toLocaleDateString('pt-BR') : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <button onClick={() => setCreditsUser(user)} title="Gerenciar Créditos"
                        className="p-1.5 text-gray-400 hover:text-yellow-400 hover:bg-yellow-900/20 rounded transition">
                        <CreditCard className="w-4 h-4" />
                      </button>
                      <button onClick={() => setEditUser(user)} title="Editar Usuário"
                        className="p-1.5 text-gray-400 hover:text-blue-400 hover:bg-blue-900/20 rounded transition">
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button onClick={() => setDeleteUser(user)} title="Deletar Usuário"
                        className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-red-900/20 rounded transition">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-16 text-center text-gray-500 text-sm">
                    {search
                      ? 'Nenhum usuário encontrado para esta busca.'
                      : 'Nenhum usuário cadastrado ainda.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onSuccess={() => { setShowCreate(false); fetchData() }}
        />
      )}
      {editUser && (
        <EditUserModal
          user={editUser}
          onClose={() => setEditUser(null)}
          onSuccess={() => { setEditUser(null); fetchData() }}
        />
      )}
      {creditsUser && (
        <CreditsUserModal
          user={creditsUser}
          onClose={() => setCreditsUser(null)}
          onSuccess={() => { setCreditsUser(null); fetchData() }}
        />
      )}
      {deleteUser && (
        <DeleteUserModal
          user={deleteUser}
          onClose={() => setDeleteUser(null)}
          onSuccess={() => { setDeleteUser(null); fetchData() }}
        />
      )}

      <WebhooksSection />

      <SSOConfigSection />
    </div>
  )
}
