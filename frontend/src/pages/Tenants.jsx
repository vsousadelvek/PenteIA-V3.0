import React, { useState, useEffect, useCallback } from 'react'
import {
  Building2, Users, Plus, Settings, Crown, Globe, Shield, X,
  RefreshCw, AlertTriangle, CheckCircle, Loader, ChevronRight,
  TrendingUp, UserPlus, Zap
} from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

// ── helpers ──────────────────────────────────────────────────────────────────

function slugify(str) {
  return str
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .slice(0, 48)
}

function fmtDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('pt-BR')
}

// ── role badge ────────────────────────────────────────────────────────────────

const ROLE_STYLES = {
  admin:    'bg-red-900/40 text-red-400 border-red-700/50',
  redteam:  'bg-orange-900/40 text-orange-400 border-orange-700/50',
  soc:      'bg-blue-900/40 text-blue-400 border-blue-700/50',
  ciso:     'bg-purple-900/40 text-purple-400 border-purple-700/50',
  readonly: 'bg-dark-700 text-gray-400 border-dark-600',
}

const ROLE_LABEL = {
  admin:    'Admin',
  redteam:  'Red Team',
  soc:      'SOC',
  ciso:     'CISO',
  readonly: 'Somente Leitura',
}

function RoleBadge({ role }) {
  const cls = ROLE_STYLES[role] || ROLE_STYLES.readonly
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium border ${cls}`}>
      {ROLE_LABEL[role] || role}
    </span>
  )
}

// ── plan config ───────────────────────────────────────────────────────────────

const PLANS = {
  starter:      { label: 'Starter',      maxUsers: 5,   sims: 20,  color: 'text-gray-400',   badge: 'bg-dark-700 text-gray-400 border-dark-600' },
  professional: { label: 'Professional', maxUsers: 20,  sims: 100, color: 'text-blue-400',   badge: 'bg-blue-900/30 text-blue-400 border-blue-700/50' },
  enterprise:   { label: 'Enterprise',   maxUsers: null, sims: null, color: 'text-purple-400', badge: 'bg-purple-900/30 text-purple-400 border-purple-700/50' },
  mssp:         { label: 'MSSP',         maxUsers: null, sims: null, color: 'text-red-400',   badge: 'bg-red-900/30 text-red-400 border-red-700/50' },
}

function PlanBadge({ plan }) {
  const cfg = PLANS[plan] || PLANS.starter
  return (
    <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${cfg.badge}`}>
      {cfg.label}
    </span>
  )
}

// ── spinner ───────────────────────────────────────────────────────────────────

function Spinner({ size = 4 }) {
  return (
    <div className={`w-${size} h-${size} border-2 border-white/30 border-t-white rounded-full animate-spin`} />
  )
}

// ── modal wrapper ─────────────────────────────────────────────────────────────

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

// ── usage bar ─────────────────────────────────────────────────────────────────

function UsageBar({ value, max, label, colorClass = 'bg-red-600' }) {
  const pct = max ? Math.min(100, Math.round((value / max) * 100)) : 0
  const unlimited = max === null || max === undefined
  return (
    <div>
      <div className="flex items-center justify-between text-xs text-gray-400 mb-1.5">
        <span>{label}</span>
        {unlimited
          ? <span className="text-green-400 font-medium">Ilimitado</span>
          : <span><strong className="text-gray-200">{value}</strong> / {max}</span>
        }
      </div>
      {!unlimited && (
        <div className="h-2 bg-dark-700 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${pct >= 90 ? 'bg-red-500' : pct >= 70 ? 'bg-yellow-500' : colorClass}`}
            style={{ width: `${pct}%` }}
          />
        </div>
      )}
    </div>
  )
}

// ── invite modal ──────────────────────────────────────────────────────────────

function InviteModal({ onClose, onSuccess }) {
  const toast = useToast()
  const [form, setForm] = useState({ email: '', role: 'readonly' })
  const [loading, setLoading] = useState(false)

  const submit = async e => {
    e.preventDefault()
    if (!form.email.trim()) { toast('Informe um e-mail', 'warning'); return }
    setLoading(true)
    try {
      const r = await api.post('/api/org/invite', form)
      toast(`Convite enviado para ${r.data?.email ?? form.email}`, 'success')
      onSuccess()
    } catch (err) {
      toast(err.response?.data?.detail || 'Erro ao enviar convite', 'error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal title="Convidar Membro" onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">E-mail do convidado</label>
          <input
            required
            type="email"
            className="input-dark w-full"
            placeholder="usuario@empresa.com"
            value={form.email}
            onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Papel / Função</label>
          <select
            className="select-dark w-full"
            value={form.role}
            onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
          >
            <option value="admin">Admin</option>
            <option value="redteam">Red Team</option>
            <option value="soc">SOC</option>
            <option value="ciso">CISO</option>
            <option value="readonly">Somente Leitura</option>
          </select>
        </div>
        <div className="p-3 bg-dark-700 rounded-lg border border-dark-600">
          <p className="text-xs text-gray-400">
            O usuário receberá um link de convite por e-mail para entrar na organização.
          </p>
        </div>
        <div className="flex gap-3 pt-1">
          <button type="button" onClick={onClose}
            className="flex-1 px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded-lg transition text-sm">
            Cancelar
          </button>
          <button type="submit" disabled={loading}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 disabled:opacity-60 text-white rounded-lg transition text-sm font-medium">
            {loading ? <Spinner size={4} /> : <UserPlus className="w-4 h-4" />}
            Enviar Convite
          </button>
        </div>
      </form>
    </Modal>
  )
}

// ── create org panel ──────────────────────────────────────────────────────────

function CreateOrgPanel({ onCreated }) {
  const toast = useToast()
  const [form, setForm] = useState({ name: '', slug: '', plan: 'starter' })
  const [loading, setLoading] = useState(false)
  const [slugManual, setSlugManual] = useState(false)

  const handleNameChange = e => {
    const name = e.target.value
    setForm(f => ({
      ...f,
      name,
      slug: slugManual ? f.slug : slugify(name),
    }))
  }

  const handleSlugChange = e => {
    setSlugManual(true)
    setForm(f => ({ ...f, slug: slugify(e.target.value) }))
  }

  const submit = async e => {
    e.preventDefault()
    if (!form.name.trim()) { toast('Nome da organização é obrigatório', 'warning'); return }
    if (!form.slug.trim()) { toast('Slug é obrigatório', 'warning'); return }
    setLoading(true)
    try {
      await api.post('/api/org', form)
      toast('Organização criada com sucesso!', 'success')
      onCreated()
    } catch (err) {
      toast(err.response?.data?.detail || 'Erro ao criar organização', 'error')
    } finally {
      setLoading(false)
    }
  }

  const planOptions = [
    { value: 'starter',      label: 'Starter',      desc: '5 usuários · 20 simulações/mês' },
    { value: 'professional', label: 'Professional',  desc: '20 usuários · 100 simulações/mês' },
    { value: 'enterprise',   label: 'Enterprise',    desc: 'Usuários ilimitados · Simulações ilimitadas' },
    { value: 'mssp',         label: 'MSSP',          desc: 'Multi-tenant · Clientes ilimitados' },
  ]

  return (
    <div className="max-w-xl mx-auto">
      <div className="bg-dark-800 border border-dark-600 rounded-xl p-8">
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-red-900/30 border border-red-700/50 rounded-2xl flex items-center justify-center mx-auto mb-4">
            <Building2 className="w-8 h-8 text-red-400" />
          </div>
          <h2 className="text-2xl font-bold text-gray-100 mb-1">Criar Organização</h2>
          <p className="text-gray-400 text-sm">Configure sua organização para começar a usar o PenteIA como MSSP.</p>
        </div>

        <form onSubmit={submit} className="space-y-5">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">
              Nome da Organização <span className="text-red-400">*</span>
            </label>
            <input
              required
              className="input-dark w-full"
              placeholder="Acme Security Ltda"
              value={form.name}
              onChange={handleNameChange}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">
              Slug (URL) <span className="text-red-400">*</span>
            </label>
            <div className="flex items-center bg-dark-700 border border-dark-600 rounded-lg overflow-hidden focus-within:border-red-600/60 transition">
              <span className="px-3 text-gray-500 text-sm select-none border-r border-dark-600 py-2.5">penteia.io/</span>
              <input
                required
                className="flex-1 bg-transparent px-3 py-2.5 text-gray-100 text-sm outline-none placeholder-gray-600"
                placeholder="acme-security"
                value={form.slug}
                onChange={handleSlugChange}
              />
            </div>
            <p className="text-xs text-gray-500 mt-1">Apenas letras minúsculas, números e hífens.</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Plano</label>
            <div className="grid grid-cols-2 gap-2">
              {planOptions.map(opt => {
                const cfg = PLANS[opt.value]
                return (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setForm(f => ({ ...f, plan: opt.value }))}
                    className={`text-left p-3 rounded-lg border transition ${
                      form.plan === opt.value
                        ? 'border-red-600 bg-red-900/20'
                        : 'border-dark-600 bg-dark-700 hover:border-dark-500'
                    }`}
                  >
                    <p className={`text-sm font-bold ${cfg.color}`}>{opt.label}</p>
                    <p className="text-xs text-gray-500 mt-0.5">{opt.desc}</p>
                  </button>
                )
              })}
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-3 bg-red-700 hover:bg-red-600 disabled:opacity-60 text-white rounded-lg font-semibold transition"
          >
            {loading ? <Spinner size={4} /> : <Building2 className="w-5 h-5" />}
            Criar Organização
          </button>
        </form>
      </div>
    </div>
  )
}

// ── section A: org card ───────────────────────────────────────────────────────

function OrgCard({ org, usage }) {
  const planCfg = PLANS[org.plan] || PLANS.starter

  return (
    <div className="bg-dark-800 border border-dark-600 rounded-xl p-6">
      <div className="flex items-start justify-between mb-5">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-red-900/30 border border-red-700/50 rounded-xl flex items-center justify-center flex-shrink-0">
            <Building2 className="w-6 h-6 text-red-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-gray-100">{org.name}</h2>
            <div className="flex items-center gap-2 mt-0.5">
              <Globe className="w-3.5 h-3.5 text-gray-500" />
              <span className="text-sm text-gray-500 font-mono">{org.slug}</span>
            </div>
          </div>
        </div>
        <PlanBadge plan={org.plan} />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="bg-dark-700 rounded-lg p-4 space-y-3">
          <div className="flex items-center gap-2 text-sm font-medium text-gray-300 mb-2">
            <Users className="w-4 h-4 text-blue-400" />
            Usuários
          </div>
          <UsageBar
            value={usage?.users_count ?? 0}
            max={org.max_users ?? planCfg.maxUsers}
            label="Membros ativos"
            colorClass="bg-blue-500"
          />
        </div>

        <div className="bg-dark-700 rounded-lg p-4 space-y-3">
          <div className="flex items-center gap-2 text-sm font-medium text-gray-300 mb-2">
            <Zap className="w-4 h-4 text-yellow-400" />
            Simulações
          </div>
          <UsageBar
            value={usage?.simulations_this_month ?? 0}
            max={org.max_simulations ?? planCfg.sims}
            label="Este mês"
            colorClass="bg-yellow-500"
          />
        </div>
      </div>
    </div>
  )
}

// ── section B: members table ──────────────────────────────────────────────────

function MembersSection({ members, onRefresh }) {
  const [showInvite, setShowInvite] = useState(false)

  return (
    <div className="bg-dark-800 border border-dark-600 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-6 py-4 border-b border-dark-700">
        <div className="flex items-center gap-2">
          <Users className="w-5 h-5 text-blue-400" />
          <h2 className="text-lg font-bold text-gray-100">Membros da Organização</h2>
          <span className="text-xs text-gray-500 bg-dark-700 px-2 py-0.5 rounded-full">
            {members.length}
          </span>
        </div>
        <button
          onClick={() => setShowInvite(true)}
          className="flex items-center gap-2 text-sm px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white rounded-lg transition font-medium"
        >
          <Plus className="w-4 h-4" />
          Convidar Membro
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-dark-700">
              <th className="px-4 py-3 text-xs font-semibold text-gray-400 text-left">Usuário</th>
              <th className="px-4 py-3 text-xs font-semibold text-gray-400 text-left">E-mail</th>
              <th className="px-4 py-3 text-xs font-semibold text-gray-400 text-left">Papel</th>
              <th className="px-4 py-3 text-xs font-semibold text-gray-400 text-left">Membro desde</th>
            </tr>
          </thead>
          <tbody>
            {members.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-4 py-14 text-center">
                  <Users className="w-8 h-8 text-gray-600 mx-auto mb-3" />
                  <p className="text-gray-500 text-sm">Nenhum membro encontrado.</p>
                  <p className="text-gray-600 text-xs mt-1">Convide membros para colaborar nesta organização.</p>
                </td>
              </tr>
            ) : (
              members.map(m => (
                <tr key={m.id} className="border-b border-dark-700/40 hover:bg-dark-700/25 transition">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 bg-dark-600 border border-dark-500 rounded-full flex items-center justify-center flex-shrink-0">
                        <span className="text-xs font-bold text-gray-300">
                          {(m.username || '?').charAt(0).toUpperCase()}
                        </span>
                      </div>
                      <span className="text-sm font-medium text-gray-200">{m.username}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-400">{m.email}</td>
                  <td className="px-4 py-3">
                    <RoleBadge role={m.role} />
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">{fmtDate(m.created_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {showInvite && (
        <InviteModal
          onClose={() => setShowInvite(false)}
          onSuccess={() => { setShowInvite(false); onRefresh() }}
        />
      )}
    </div>
  )
}

// ── section C: plan & limits ──────────────────────────────────────────────────

function PlanSection({ org }) {
  const currentPlan = PLANS[org.plan] || PLANS.starter
  const isUpgradeable = org.plan === 'starter' || org.plan === 'professional'

  const featureMatrix = [
    { feature: 'Usuários',          starter: '5',       professional: '20',     enterprise: 'Ilimitado', mssp: 'Ilimitado' },
    { feature: 'Simulações/mês',    starter: '20',      professional: '100',    enterprise: 'Ilimitado', mssp: 'Ilimitado' },
    { feature: 'Multi-tenant',      starter: false,     professional: false,    enterprise: false,       mssp: true },
    { feature: 'API Access',        starter: false,     professional: true,     enterprise: true,        mssp: true },
    { feature: 'Relatórios CISO',   starter: false,     professional: true,     enterprise: true,        mssp: true },
    { feature: 'SLA 99.9%',         starter: false,     professional: false,    enterprise: true,        mssp: true },
    { feature: 'Suporte dedicado',  starter: false,     professional: false,    enterprise: true,        mssp: true },
  ]

  const PLAN_ORDER = ['starter', 'professional', 'enterprise', 'mssp']

  return (
    <div className="bg-dark-800 border border-dark-600 rounded-xl overflow-hidden">
      <div className="flex items-center gap-2 px-6 py-4 border-b border-dark-700">
        <Crown className="w-5 h-5 text-yellow-400" />
        <h2 className="text-lg font-bold text-gray-100">Plano & Limites</h2>
      </div>

      <div className="p-6">
        {/* current plan summary */}
        <div className={`flex items-center justify-between p-4 rounded-xl border mb-6 ${
          org.plan === 'mssp'
            ? 'bg-red-900/20 border-red-700/50'
            : org.plan === 'enterprise'
            ? 'bg-purple-900/20 border-purple-700/50'
            : org.plan === 'professional'
            ? 'bg-blue-900/20 border-blue-700/50'
            : 'bg-dark-700 border-dark-600'
        }`}>
          <div>
            <p className="text-xs text-gray-400 mb-0.5">Plano atual</p>
            <p className={`text-2xl font-bold ${currentPlan.color}`}>{currentPlan.label}</p>
          </div>
          <div className="text-right text-sm text-gray-400 space-y-0.5">
            <p>{currentPlan.maxUsers ? `Até ${currentPlan.maxUsers} usuários` : 'Usuários ilimitados'}</p>
            <p>{currentPlan.sims ? `${currentPlan.sims} simulações/mês` : 'Simulações ilimitadas'}</p>
          </div>
        </div>

        {/* feature table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-dark-700">
                <th className="py-2 pr-4 text-left text-xs text-gray-400 font-medium w-40">Recurso</th>
                {PLAN_ORDER.map(p => (
                  <th key={p} className={`py-2 px-3 text-center text-xs font-semibold ${
                    p === org.plan ? PLANS[p].color : 'text-gray-500'
                  }`}>
                    {PLANS[p].label}
                    {p === org.plan && (
                      <span className="ml-1 text-[9px] font-bold bg-red-700 text-white px-1 py-0.5 rounded uppercase">atual</span>
                    )}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {featureMatrix.map((row) => (
                <tr key={row.feature} className="border-b border-dark-700/40">
                  <td className="py-2 pr-4 text-gray-400 text-xs">{row.feature}</td>
                  {PLAN_ORDER.map(p => {
                    const val = row[p]
                    return (
                      <td key={p} className={`py-2 px-3 text-center ${p === org.plan ? 'bg-dark-700/30' : ''}`}>
                        {typeof val === 'boolean' ? (
                          val
                            ? <CheckCircle className="w-4 h-4 text-green-500 mx-auto" />
                            : <X className="w-4 h-4 text-gray-600 mx-auto" />
                        ) : (
                          <span className={`text-xs font-medium ${p === org.plan ? PLANS[p].color : 'text-gray-500'}`}>
                            {val}
                          </span>
                        )}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* upgrade CTA */}
        {isUpgradeable && (
          <div className="mt-6 p-4 bg-gradient-to-r from-red-900/20 to-orange-900/20 border border-red-700/40 rounded-xl">
            <div className="flex items-start gap-3">
              <TrendingUp className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="text-sm font-semibold text-gray-100 mb-1">
                  Faça upgrade para{' '}
                  {org.plan === 'starter' ? 'Professional ou Enterprise' : 'Enterprise'}
                </p>
                <p className="text-xs text-gray-400">
                  {org.plan === 'starter'
                    ? 'Acesse mais usuários, simulações ilimitadas e relatórios avançados para sua equipe.'
                    : 'Desbloqueie usuários e simulações ilimitadas, SLA garantido e suporte dedicado.'}
                </p>
              </div>
              <button className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white rounded-lg transition font-medium flex-shrink-0">
                Upgrade
                <ChevronRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── main page ─────────────────────────────────────────────────────────────────

export default function Tenants() {
  const toast = useToast()
  const [org, setOrg] = useState(null)
  const [members, setMembers] = useState([])
  const [usage, setUsage] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [refreshing, setRefreshing] = useState(false)

  const fetchAll = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      // org may return 404 if not yet created — treat as "no org"
      let orgData = null
      try {
        const r = await api.get('/api/org')
        orgData = r.data?.organization ?? r.data?.organizations?.[0] ?? r.data
      } catch (err) {
        if (err.response?.status !== 404) throw err
      }

      setOrg(orgData)

      if (orgData) {
        const [membersRes, usageRes] = await Promise.allSettled([
          api.get('/api/org/users'),
          api.get('/api/org/usage'),
        ])
        if (membersRes.status === 'fulfilled') { const d = membersRes.value.data; setMembers(Array.isArray(d) ? d : (d?.users ?? d?.members ?? [])) }
        if (usageRes.status === 'fulfilled') setUsage(usageRes.value.data || null)
      }
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Erro ao carregar dados'
      setError(msg)
      toast(msg, 'error')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [toast])

  useEffect(() => { fetchAll() }, [fetchAll])

  const handleOrgCreated = () => fetchAll()
  const handleRefresh = () => fetchAll(true)

  // ── loading ──
  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <div className="text-center">
          <div className="w-10 h-10 border-2 border-red-600 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-gray-400 text-sm">Carregando organização...</p>
        </div>
      </div>
    )
  }

  // ── error ──
  if (error && !org) {
    return (
      <div className="max-w-lg mx-auto mt-16">
        <div className="bg-red-900/20 border border-red-700/50 rounded-xl p-6 text-center">
          <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
          <p className="text-gray-200 font-medium mb-1">Erro ao carregar</p>
          <p className="text-gray-400 text-sm mb-4">{error}</p>
          <button
            onClick={() => fetchAll()}
            className="flex items-center gap-2 mx-auto px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-200 rounded-lg transition text-sm"
          >
            <RefreshCw className="w-4 h-4" /> Tentar novamente
          </button>
        </div>
      </div>
    )
  }

  // ── page ──
  return (
    <div className="space-y-6">
      {/* header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100">
            MSSP — <span className="text-red-600">Gestão de Organização</span>
          </h1>
          <p className="text-gray-400 mt-1">
            Configure sua organização, gerencie membros e acompanhe o uso da plataforma.
          </p>
        </div>
        {org && (
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            title="Atualizar"
            className="p-2 text-gray-400 hover:text-gray-100 hover:bg-dark-700 rounded-lg transition disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        )}
      </div>

      {/* breadcrumb chips */}
      <div className="flex items-center gap-2 text-xs text-gray-500">
        <Shield className="w-3.5 h-3.5" />
        <span>PenteIA</span>
        <ChevronRight className="w-3 h-3" />
        <span>MSSP</span>
        <ChevronRight className="w-3 h-3" />
        <span className="text-gray-300">Organização</span>
      </div>

      {/* no org yet */}
      {!org ? (
        <CreateOrgPanel onCreated={handleOrgCreated} />
      ) : (
        <>
          {/* A: org overview card */}
          <OrgCard org={org} usage={usage} />

          {/* B: members table */}
          <MembersSection members={members} onRefresh={handleRefresh} />

          {/* C: plan & limits */}
          <PlanSection org={org} />
        </>
      )}
    </div>
  )
}
