import React, { useState, useEffect, useCallback } from 'react'
import {
  Building2, Users, Palette, Globe, Plus, Trash2, Edit, Eye,
  BarChart2, DollarSign, ChevronRight, ChevronLeft, X, Loader,
  AlertTriangle, CheckCircle, RefreshCw
} from 'lucide-react'
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

function riskColor(score) {
  if (score == null) return 'text-gray-400'
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-orange-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-green-400'
}

function riskBg(score) {
  if (score == null) return 'bg-gray-700/40 text-gray-400'
  if (score >= 80) return 'bg-red-900/40 text-red-300 border border-red-700/40'
  if (score >= 60) return 'bg-orange-900/40 text-orange-300 border border-orange-700/40'
  if (score >= 40) return 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40'
  return 'bg-green-900/40 text-green-300 border border-green-700/40'
}

// ── plan config ───────────────────────────────────────────────────────────────

const MSSP_PLANS = [
  {
    id: 'mssp_standard',
    label: 'MSSP Standard',
    maxClients: 20,
    color: 'text-blue-400',
    badge: 'bg-blue-900/30 text-blue-300 border border-blue-700/40',
    icon: '🔵',
  },
  {
    id: 'mssp_professional',
    label: 'MSSP Professional',
    maxClients: 100,
    color: 'text-purple-400',
    badge: 'bg-purple-900/30 text-purple-300 border border-purple-700/40',
    icon: '🟣',
  },
  {
    id: 'enterprise',
    label: 'Enterprise',
    maxClients: null,
    color: 'text-amber-400',
    badge: 'bg-amber-900/30 text-amber-300 border border-amber-700/40',
    icon: '⭐',
  },
]

function PlanBadge({ plan }) {
  const cfg = MSSP_PLANS.find(p => p.id === plan) || MSSP_PLANS[0]
  return (
    <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold ${cfg.badge}`}>
      {cfg.icon} {cfg.label}
      {cfg.maxClients ? ` · ${cfg.maxClients} clientes` : ' · Ilimitado'}
    </span>
  )
}

// ── spinner ───────────────────────────────────────────────────────────────────

function Spinner({ size = 5 }) {
  return (
    <div
      className={`w-${size} h-${size} border-2 border-white/20 border-t-white rounded-full animate-spin`}
    />
  )
}

// ── toast ─────────────────────────────────────────────────────────────────────

function useToast() {
  const [toasts, setToasts] = useState([])
  const add = useCallback((msg, type = 'info') => {
    const id = Date.now()
    setToasts(prev => [...prev, { id, msg, type }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000)
  }, [])
  return { toasts, add }
}

function ToastArea({ toasts }) {
  if (!toasts.length) return null
  return (
    <div className="fixed bottom-4 right-4 z-[200] flex flex-col gap-2">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`flex items-center gap-2 px-4 py-3 rounded-lg shadow-xl text-sm font-medium border
            ${t.type === 'error'   ? 'bg-red-900/90 text-red-200 border-red-700/60' :
              t.type === 'success' ? 'bg-green-900/90 text-green-200 border-green-700/60' :
              'bg-dark-700 text-gray-200 border-dark-600'}`}
        >
          {t.type === 'error'   && <AlertTriangle className="w-4 h-4 flex-shrink-0" />}
          {t.type === 'success' && <CheckCircle   className="w-4 h-4 flex-shrink-0" />}
          {t.msg}
        </div>
      ))}
    </div>
  )
}

// ── modal wrapper ─────────────────────────────────────────────────────────────

function Modal({ title, onClose, children, wide = false }) {
  useEffect(() => {
    const handler = e => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div
        className={`relative bg-dark-800 border border-dark-600 rounded-xl shadow-2xl flex flex-col
          ${wide ? 'w-full max-w-3xl' : 'w-full max-w-lg'} max-h-[90vh]`}
      >
        {/* header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-dark-600 flex-shrink-0">
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-dark-600 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        {/* body */}
        <div className="overflow-y-auto px-6 py-4 flex-1">
          {children}
        </div>
      </div>
    </div>
  )
}

// ── field helpers ─────────────────────────────────────────────────────────────

function Field({ label, children }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-xs font-medium text-gray-400 uppercase tracking-wide">{label}</label>
      {children}
    </div>
  )
}

const inputCls =
  'w-full bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors'

// ── sector bar chart (CSS) ────────────────────────────────────────────────────

function SectorChart({ sectors }) {
  if (!sectors || !Object.keys(sectors).length) {
    return <p className="text-xs text-gray-500 italic">Sem dados de setor disponíveis.</p>
  }
  const entries = Object.entries(sectors).sort((a, b) => b[1] - a[1])
  const max = entries[0][1]
  const COLORS = [
    'bg-blue-500', 'bg-purple-500', 'bg-emerald-500', 'bg-amber-500',
    'bg-rose-500', 'bg-cyan-500', 'bg-orange-500', 'bg-indigo-500',
  ]
  return (
    <div className="flex flex-col gap-2">
      {entries.map(([name, count], idx) => (
        <div key={name} className="flex items-center gap-3">
          <span className="w-28 text-xs text-gray-400 truncate text-right flex-shrink-0">{name}</span>
          <div className="flex-1 h-5 bg-dark-700 rounded overflow-hidden">
            <div
              className={`h-full ${COLORS[idx % COLORS.length]} rounded transition-all duration-500`}
              style={{ width: `${(count / max) * 100}%` }}
            />
          </div>
          <span className="w-6 text-xs text-gray-300 font-semibold text-right flex-shrink-0">{count}</span>
        </div>
      ))}
    </div>
  )
}

// ── brand preview ─────────────────────────────────────────────────────────────

function BrandPreview({ name, logoUrl, primaryColor, secondaryColor }) {
  const bg = primaryColor || '#1e293b'
  const accent = secondaryColor || '#3b82f6'

  return (
    <div className="rounded-xl overflow-hidden border border-dark-500 shadow-xl">
      {/* simulated report header */}
      <div
        className="px-6 py-4 flex items-center justify-between"
        style={{ backgroundColor: bg }}
      >
        <div className="flex items-center gap-3">
          {logoUrl ? (
            <img
              src={logoUrl}
              alt="logo"
              className="h-9 w-auto object-contain rounded"
              onError={e => { e.target.style.display = 'none' }}
            />
          ) : (
            <div
              className="h-9 w-9 rounded flex items-center justify-center font-bold text-white text-lg"
              style={{ backgroundColor: accent }}
            >
              {(name || 'P').charAt(0).toUpperCase()}
            </div>
          )}
          <div>
            <p className="text-white font-bold text-base leading-none">{name || 'Partner Name'}</p>
            <p className="text-white/60 text-xs mt-0.5">Security Assessment Report</p>
          </div>
        </div>
        <div
          className="px-3 py-1 rounded text-white text-xs font-semibold"
          style={{ backgroundColor: accent }}
        >
          CONFIDENTIAL
        </div>
      </div>
      {/* simulated body placeholder */}
      <div className="bg-dark-900 px-6 py-5">
        <div className="flex gap-4 mb-4">
          {['Critical', 'High', 'Medium', 'Low'].map((s, i) => (
            <div
              key={s}
              className="flex-1 rounded-lg py-3 text-center border"
              style={{ borderColor: `${accent}40`, backgroundColor: `${bg}22` }}
            >
              <p className="text-2xl font-bold text-white">{[3, 7, 12, 5][i]}</p>
              <p className="text-xs mt-1" style={{ color: accent }}>{s}</p>
            </div>
          ))}
        </div>
        <div className="h-2 rounded-full bg-dark-700 overflow-hidden">
          <div className="h-full rounded-full" style={{ width: '62%', backgroundColor: accent }} />
        </div>
        <p className="text-xs text-gray-500 mt-2">Risk Score · 62 / 100</p>
      </div>
      {/* simulated footer */}
      <div
        className="px-6 py-2 flex items-center justify-between"
        style={{ backgroundColor: `${bg}cc` }}
      >
        <p className="text-white/50 text-xs">Generated by PenteIA · {name || 'Partner'}</p>
        <p className="text-white/50 text-xs">Page 1 / 12</p>
      </div>
    </div>
  )
}

// ── create partner modal ──────────────────────────────────────────────────────

function CreatePartnerModal({ onClose, onCreated }) {
  const [form, setForm] = useState({
    name: '', slug: '', logo_url: '',
    primary_color: '#1e293b', secondary_color: '#3b82f6',
    contact_email: '',
  })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')

  function set(k, v) {
    setForm(prev => {
      const next = { ...prev, [k]: v }
      if (k === 'name') next.slug = slugify(v)
      return next
    })
  }

  async function submit(e) {
    e.preventDefault()
    if (!form.name.trim()) return setErr('Nome é obrigatório.')
    if (!form.contact_email.trim()) return setErr('E-mail de contato é obrigatório.')
    setSaving(true)
    setErr('')
    try {
      const { data } = await api.post('/api/mssp/partners', form)
      onCreated(data)
    } catch (ex) {
      setErr(ex.response?.data?.detail || ex.message || 'Erro ao criar parceiro.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal title="Novo Parceiro MSSP" onClose={onClose} wide>
      <form onSubmit={submit} className="flex flex-col gap-4">
        <div className="grid grid-cols-2 gap-4">
          <Field label="Nome do Parceiro *">
            <input
              className={inputCls} value={form.name} required
              placeholder="Acme Security Ltd."
              onChange={e => set('name', e.target.value)}
            />
          </Field>
          <Field label="Slug (URL)">
            <input
              className={inputCls} value={form.slug}
              placeholder="acme-security"
              onChange={e => set('slug', slugify(e.target.value))}
            />
          </Field>
        </div>

        <Field label="Logo URL">
          <input
            className={inputCls} value={form.logo_url}
            placeholder="https://cdn.acme.com/logo.svg"
            onChange={e => set('logo_url', e.target.value)}
          />
        </Field>

        <div className="grid grid-cols-2 gap-4">
          <Field label="Cor Primária">
            <div className="flex items-center gap-2">
              <input
                type="color" value={form.primary_color}
                onChange={e => set('primary_color', e.target.value)}
                className="w-10 h-9 rounded cursor-pointer border border-dark-500 bg-transparent"
              />
              <input
                className={inputCls} value={form.primary_color}
                onChange={e => set('primary_color', e.target.value)}
              />
            </div>
          </Field>
          <Field label="Cor Secundária">
            <div className="flex items-center gap-2">
              <input
                type="color" value={form.secondary_color}
                onChange={e => set('secondary_color', e.target.value)}
                className="w-10 h-9 rounded cursor-pointer border border-dark-500 bg-transparent"
              />
              <input
                className={inputCls} value={form.secondary_color}
                onChange={e => set('secondary_color', e.target.value)}
              />
            </div>
          </Field>
        </div>

        <Field label="E-mail de Contato *">
          <input
            className={inputCls} type="email" value={form.contact_email} required
            placeholder="ops@acme.com"
            onChange={e => set('contact_email', e.target.value)}
          />
        </Field>

        {/* live preview inside create modal */}
        <div>
          <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Preview</p>
          <BrandPreview
            name={form.name}
            logoUrl={form.logo_url}
            primaryColor={form.primary_color}
            secondaryColor={form.secondary_color}
          />
        </div>

        {err && (
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 border border-red-700/40 rounded-lg px-3 py-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            {err}
          </div>
        )}

        <div className="flex justify-end gap-3 pt-2 border-t border-dark-600">
          <button
            type="button" onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm text-gray-300 hover:text-white hover:bg-dark-600 transition-colors"
          >
            Cancelar
          </button>
          <button
            type="submit" disabled={saving}
            className="flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 transition-colors text-white"
          >
            {saving ? <Spinner size={4} /> : <Plus className="w-4 h-4" />}
            Criar Parceiro
          </button>
        </div>
      </form>
    </Modal>
  )
}

// ── add client modal ──────────────────────────────────────────────────────────

function AddClientModal({ partnerId, onClose, onAdded }) {
  const [form, setForm] = useState({ name: '', sector: '', contact_email: '' })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')

  const SECTORS = [
    'Financeiro', 'Saúde', 'Varejo', 'Tecnologia', 'Educação',
    'Governo', 'Energia', 'Telecomunicações', 'Indústria', 'Outro',
  ]

  async function submit(e) {
    e.preventDefault()
    if (!form.name.trim()) return setErr('Nome é obrigatório.')
    setSaving(true)
    setErr('')
    try {
      const { data } = await api.post(`/api/mssp/partners/${partnerId}/clients`, form)
      onAdded(data)
    } catch (ex) {
      setErr(ex.response?.data?.detail || ex.message || 'Erro ao adicionar cliente.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal title="Adicionar Cliente" onClose={onClose}>
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Field label="Nome do Cliente *">
          <input
            className={inputCls} value={form.name} required
            placeholder="Empresa XYZ S.A."
            onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
          />
        </Field>
        <Field label="Setor">
          <select
            className={inputCls}
            value={form.sector}
            onChange={e => setForm(p => ({ ...p, sector: e.target.value }))}
          >
            <option value="">Selecione o setor…</option>
            {SECTORS.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="E-mail de Contato">
          <input
            className={inputCls} type="email" value={form.contact_email}
            placeholder="ciso@empresa.com"
            onChange={e => setForm(p => ({ ...p, contact_email: e.target.value }))}
          />
        </Field>

        {err && (
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 border border-red-700/40 rounded-lg px-3 py-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            {err}
          </div>
        )}

        <div className="flex justify-end gap-3 pt-2 border-t border-dark-600">
          <button
            type="button" onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm text-gray-300 hover:text-white hover:bg-dark-600 transition-colors"
          >
            Cancelar
          </button>
          <button
            type="submit" disabled={saving}
            className="flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-semibold bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 transition-colors text-white"
          >
            {saving ? <Spinner size={4} /> : <Plus className="w-4 h-4" />}
            Adicionar
          </button>
        </div>
      </form>
    </Modal>
  )
}

// ── branding editor ───────────────────────────────────────────────────────────

function BrandingEditor({ partner, onSaved, toast }) {
  const [form, setForm] = useState({
    logo_url: partner.logo_url || '',
    primary_color: partner.primary_color || '#1e293b',
    secondary_color: partner.secondary_color || '#3b82f6',
    company_name: partner.company_name || partner.name || '',
    report_footer: partner.report_footer || '',
  })
  const [saving, setSaving] = useState(false)

  function set(k, v) { setForm(prev => ({ ...prev, [k]: v })) }

  async function save() {
    setSaving(true)
    try {
      const { data } = await api.patch(`/api/mssp/partners/${partner.id}/branding`, form)
      toast('Branding salvo com sucesso.', 'success')
      onSaved(data)
    } catch (ex) {
      toast(ex.response?.data?.detail || 'Erro ao salvar branding.', 'error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
      {/* left: form */}
      <div className="flex flex-col gap-4">
        <Field label="Logo URL">
          <input
            className={inputCls} value={form.logo_url}
            placeholder="https://cdn.parceiro.com/logo.svg"
            onChange={e => set('logo_url', e.target.value)}
          />
        </Field>
        <Field label="Nome da Empresa (nos relatórios)">
          <input
            className={inputCls} value={form.company_name}
            onChange={e => set('company_name', e.target.value)}
          />
        </Field>
        <div className="grid grid-cols-2 gap-4">
          <Field label="Cor Primária">
            <div className="flex items-center gap-2">
              <input
                type="color" value={form.primary_color}
                onChange={e => set('primary_color', e.target.value)}
                className="w-10 h-9 rounded cursor-pointer border border-dark-500 bg-transparent"
              />
              <input
                className={inputCls} value={form.primary_color}
                onChange={e => set('primary_color', e.target.value)}
              />
            </div>
          </Field>
          <Field label="Cor Secundária">
            <div className="flex items-center gap-2">
              <input
                type="color" value={form.secondary_color}
                onChange={e => set('secondary_color', e.target.value)}
                className="w-10 h-9 rounded cursor-pointer border border-dark-500 bg-transparent"
              />
              <input
                className={inputCls} value={form.secondary_color}
                onChange={e => set('secondary_color', e.target.value)}
              />
            </div>
          </Field>
        </div>
        <Field label="Rodapé do Relatório">
          <textarea
            className={`${inputCls} resize-none`}
            rows={3}
            value={form.report_footer}
            placeholder="© 2026 Acme Security Ltd. · Documento Confidencial"
            onChange={e => set('report_footer', e.target.value)}
          />
        </Field>
        <button
          onClick={save} disabled={saving}
          className="flex items-center gap-2 self-start px-5 py-2 rounded-lg text-sm font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50 transition-colors text-white"
        >
          {saving ? <Spinner size={4} /> : <Palette className="w-4 h-4" />}
          Salvar Branding
        </button>
      </div>

      {/* right: live preview */}
      <div>
        <p className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-3 flex items-center gap-1.5">
          <Eye className="w-3.5 h-3.5" /> Preview ao Vivo
        </p>
        <BrandPreview
          name={form.company_name || partner.name}
          logoUrl={form.logo_url}
          primaryColor={form.primary_color}
          secondaryColor={form.secondary_color}
        />
        {form.report_footer && (
          <div
            className="mt-2 rounded-lg px-4 py-2 text-xs text-white/60 text-center"
            style={{ backgroundColor: `${form.primary_color}55` }}
          >
            {form.report_footer}
          </div>
        )}
      </div>
    </div>
  )
}

// ── portfolio summary ─────────────────────────────────────────────────────────

function PortfolioSummary({ partner, clients }) {
  const total = clients.length
  const avgRisk = total
    ? Math.round(clients.reduce((s, c) => s + (c.risk_score || 0), 0) / total)
    : 0
  const critical = clients.filter(c => (c.risk_score || 0) >= 80).length

  const sectors = clients.reduce((acc, c) => {
    const s = c.sector || 'Sem setor'
    acc[s] = (acc[s] || 0) + 1
    return acc
  }, {})

  const metrics = [
    { label: 'Total de Clientes', value: total,    icon: Users,    color: 'text-blue-400',   bg: 'bg-blue-900/20 border-blue-700/30' },
    { label: 'Risco Médio',       value: avgRisk,  icon: BarChart2, color: riskColor(avgRisk), bg: 'bg-dark-700 border-dark-600' },
    { label: 'Clientes Críticos', value: critical, icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-900/20 border-red-700/30' },
  ]

  return (
    <div className="flex flex-col gap-6">
      {/* stat cards */}
      <div className="grid grid-cols-3 gap-4">
        {metrics.map(m => (
          <div key={m.label} className={`rounded-xl border px-5 py-4 flex flex-col gap-1 ${m.bg}`}>
            <div className="flex items-center gap-2 text-xs text-gray-400">
              <m.icon className={`w-3.5 h-3.5 ${m.color}`} />
              {m.label}
            </div>
            <p className={`text-3xl font-bold ${m.color}`}>{m.value}</p>
          </div>
        ))}
      </div>

      {/* sector chart */}
      <div className="bg-dark-700/50 border border-dark-600 rounded-xl p-5">
        <p className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Globe className="w-4 h-4 text-blue-400" />
          Distribuição por Setor
        </p>
        {total === 0 ? (
          <p className="text-xs text-gray-500 italic">Nenhum cliente cadastrado ainda.</p>
        ) : (
          <SectorChart sectors={sectors} />
        )}
      </div>
    </div>
  )
}

// ── clients table ─────────────────────────────────────────────────────────────

function ClientsTable({ partnerId, clients, onClientDeleted, toast }) {
  const [deleting, setDeleting] = useState(null)

  async function deleteClient(clientId) {
    if (!window.confirm('Remover este cliente do portfólio?')) return
    setDeleting(clientId)
    try {
      await api.delete(`/api/mssp/partners/${partnerId}/clients/${clientId}`)
      onClientDeleted(clientId)
      toast('Cliente removido.', 'success')
    } catch (ex) {
      toast(ex.response?.data?.detail || 'Erro ao remover cliente.', 'error')
    } finally {
      setDeleting(null)
    }
  }

  if (!clients.length) {
    return (
      <div className="text-center py-16 text-gray-500">
        <Users className="w-10 h-10 mx-auto mb-3 opacity-30" />
        <p className="text-sm">Nenhum cliente neste portfólio.</p>
        <p className="text-xs mt-1">Clique em "Adicionar Cliente" para começar.</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-dark-600">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-dark-600 bg-dark-700/50">
            <th className="text-left px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wide">Cliente</th>
            <th className="text-left px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wide">Setor</th>
            <th className="text-center px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wide">Risk Score</th>
            <th className="text-left px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wide">Última Sim.</th>
            <th className="px-4 py-3" />
          </tr>
        </thead>
        <tbody className="divide-y divide-dark-700">
          {clients.map(c => (
            <tr key={c.id} className="hover:bg-dark-700/30 transition-colors">
              <td className="px-4 py-3">
                <div>
                  <p className="font-medium text-white">{c.name}</p>
                  {c.contact_email && <p className="text-xs text-gray-500 mt-0.5">{c.contact_email}</p>}
                </div>
              </td>
              <td className="px-4 py-3 text-gray-400 text-xs">{c.sector || '—'}</td>
              <td className="px-4 py-3 text-center">
                {c.risk_score != null ? (
                  <span className={`inline-flex items-center justify-center w-14 py-0.5 rounded-full text-xs font-bold ${riskBg(c.risk_score)}`}>
                    {c.risk_score}
                  </span>
                ) : (
                  <span className="text-gray-600 text-xs">—</span>
                )}
              </td>
              <td className="px-4 py-3 text-gray-500 text-xs">{fmtDate(c.last_sim)}</td>
              <td className="px-4 py-3 text-right">
                <button
                  onClick={() => deleteClient(c.id)}
                  disabled={deleting === c.id}
                  className="p-1.5 rounded-lg text-gray-500 hover:text-red-400 hover:bg-red-900/20 transition-colors disabled:opacity-40"
                >
                  {deleting === c.id ? <Spinner size={3.5} /> : <Trash2 className="w-3.5 h-3.5" />}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── partner detail view ───────────────────────────────────────────────────────

const DETAIL_TABS = [
  { id: 'branding',   label: 'Branding',   icon: Palette },
  { id: 'portfolio',  label: 'Portfolio',  icon: BarChart2 },
  { id: 'clients',    label: 'Clientes',   icon: Users },
]

function PartnerDetail({ partner: initPartner, onBack, toast }) {
  const [partner, setPartner] = useState(initPartner)
  const [tab, setTab] = useState('branding')
  const [clients, setClients] = useState([])
  const [loadingClients, setLoadingClients] = useState(false)
  const [showAddClient, setShowAddClient] = useState(false)
  const [loadingReport, setLoadingReport] = useState(false)
  const [reportData, setReportData] = useState(null)
  const [showReport, setShowReport] = useState(false)

  const fetchClients = useCallback(async () => {
    setLoadingClients(true)
    try {
      const { data } = await api.get(`/api/mssp/partners/${partner.id}/clients`)
      setClients(Array.isArray(data) ? data : (data.clients || []))
    } catch {
      toast('Erro ao carregar clientes.', 'error')
    } finally {
      setLoadingClients(false)
    }
  }, [partner.id, toast])

  useEffect(() => {
    if (tab === 'clients' || tab === 'portfolio') {
      fetchClients()
    }
  }, [tab, fetchClients])

  async function generateReport() {
    setLoadingReport(true)
    setReportData(null)
    try {
      const { data } = await api.get(`/api/mssp/partners/${partner.id}/report-data`)
      setReportData(data)
      setShowReport(true)
    } catch (ex) {
      toast(ex.response?.data?.detail || 'Erro ao gerar relatório.', 'error')
    } finally {
      setLoadingReport(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {/* top bar */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-white transition-colors"
          >
            <ChevronLeft className="w-4 h-4" /> Parceiros
          </button>
          <span className="text-dark-500">/</span>
          <div className="flex items-center gap-2">
            {partner.logo_url ? (
              <img src={partner.logo_url} alt="" className="h-6 w-auto object-contain rounded" />
            ) : (
              <div
                className="h-7 w-7 rounded flex items-center justify-center text-white text-sm font-bold"
                style={{ backgroundColor: partner.secondary_color || '#3b82f6' }}
              >
                {(partner.name || 'P').charAt(0).toUpperCase()}
              </div>
            )}
            <h1 className="text-lg font-bold text-white">{partner.name}</h1>
            {partner.plan && <PlanBadge plan={partner.plan} />}
          </div>
        </div>
        <button
          onClick={generateReport}
          disabled={loadingReport}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-purple-600 hover:bg-purple-500 disabled:opacity-50 transition-colors text-white"
        >
          {loadingReport ? <Spinner size={4} /> : <BarChart2 className="w-4 h-4" />}
          Gerar Relatório do Portfolio
        </button>
      </div>

      {/* tabs */}
      <div className="flex gap-1 bg-dark-800 border border-dark-600 rounded-xl p-1 w-fit">
        {DETAIL_TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors
              ${tab === t.id
                ? 'bg-blue-600 text-white shadow'
                : 'text-gray-400 hover:text-white hover:bg-dark-700'}`}
          >
            <t.icon className="w-4 h-4" />
            {t.label}
          </button>
        ))}
      </div>

      {/* tab content */}
      {tab === 'branding' && (
        <BrandingEditor
          partner={partner}
          onSaved={updated => setPartner(p => ({ ...p, ...updated }))}
          toast={toast}
        />
      )}

      {tab === 'portfolio' && (
        loadingClients
          ? <div className="flex justify-center py-16"><Spinner size={8} /></div>
          : <PortfolioSummary partner={partner} clients={clients} />
      )}

      {tab === 'clients' && (
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-400">
              {clients.length} cliente{clients.length !== 1 ? 's' : ''} cadastrado{clients.length !== 1 ? 's' : ''}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={fetchClients}
                className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-dark-600 transition-colors"
              >
                <RefreshCw className={`w-4 h-4 ${loadingClients ? 'animate-spin' : ''}`} />
              </button>
              <button
                onClick={() => setShowAddClient(true)}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-emerald-600 hover:bg-emerald-500 transition-colors text-white"
              >
                <Plus className="w-4 h-4" />
                Adicionar Cliente
              </button>
            </div>
          </div>

          {loadingClients
            ? <div className="flex justify-center py-16"><Spinner size={8} /></div>
            : (
              <ClientsTable
                partnerId={partner.id}
                clients={clients}
                onClientDeleted={id => setClients(prev => prev.filter(c => c.id !== id))}
                toast={toast}
              />
            )}
        </div>
      )}

      {/* add client modal */}
      {showAddClient && (
        <AddClientModal
          partnerId={partner.id}
          onClose={() => setShowAddClient(false)}
          onAdded={c => {
            setClients(prev => [c, ...prev])
            setShowAddClient(false)
            toast('Cliente adicionado com sucesso.', 'success')
          }}
        />
      )}

      {/* report modal */}
      {showReport && reportData && (
        <Modal title="Relatório do Portfolio — Dados JSON" onClose={() => setShowReport(false)} wide>
          <div className="flex flex-col gap-3">
            <p className="text-xs text-gray-400">
              Sumário gerado em tempo real para o parceiro <strong className="text-white">{partner.name}</strong>.
              Use estes dados para alimentar relatórios externos ou integrações.
            </p>
            <pre className="bg-dark-900 border border-dark-600 rounded-lg p-4 text-xs text-green-300 overflow-x-auto max-h-96 whitespace-pre-wrap break-all">
              {JSON.stringify(reportData, null, 2)}
            </pre>
          </div>
        </Modal>
      )}
    </div>
  )
}

// ── partner card ──────────────────────────────────────────────────────────────

function PartnerCard({ partner, onClick }) {
  const riskScore = partner.avg_risk_score ?? null

  return (
    <div
      onClick={onClick}
      className="bg-dark-800 border border-dark-600 hover:border-dark-500 rounded-xl p-5 cursor-pointer
        transition-all duration-150 hover:shadow-xl hover:shadow-black/30 group"
    >
      <div className="flex items-start justify-between mb-4">
        {/* logo / avatar */}
        {partner.logo_url ? (
          <img
            src={partner.logo_url}
            alt={partner.name}
            className="h-10 w-auto max-w-[120px] object-contain rounded"
            onError={e => { e.target.style.display = 'none' }}
          />
        ) : (
          <div
            className="h-10 w-10 rounded-xl flex items-center justify-center text-white font-bold text-xl"
            style={{ backgroundColor: partner.secondary_color || '#3b82f6' }}
          >
            {(partner.name || 'P').charAt(0).toUpperCase()}
          </div>
        )}
        <ChevronRight className="w-4 h-4 text-gray-600 group-hover:text-gray-300 transition-colors" />
      </div>

      <h3 className="font-semibold text-white text-base mb-1 truncate">{partner.name}</h3>
      {partner.slug && <p className="text-xs text-gray-500 mb-3">/{partner.slug}</p>}

      {partner.plan && (
        <div className="mb-3">
          <PlanBadge plan={partner.plan} />
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 mt-3">
        <div className="bg-dark-700/50 rounded-lg px-3 py-2 flex flex-col gap-0.5">
          <div className="flex items-center gap-1 text-gray-500 text-xs">
            <Users className="w-3 h-3" /> Clientes
          </div>
          <p className="text-white font-bold text-lg">{partner.client_count ?? 0}</p>
        </div>
        <div className="bg-dark-700/50 rounded-lg px-3 py-2 flex flex-col gap-0.5">
          <div className="flex items-center gap-1 text-gray-500 text-xs">
            <BarChart2 className="w-3 h-3" /> Risco Médio
          </div>
          <p className={`font-bold text-lg ${riskColor(riskScore)}`}>
            {riskScore != null ? riskScore : '—'}
          </p>
        </div>
      </div>

      {partner.contact_email && (
        <p className="text-xs text-gray-600 mt-3 truncate">{partner.contact_email}</p>
      )}
    </div>
  )
}

// ── empty state ───────────────────────────────────────────────────────────────

function EmptyState({ onCreate }) {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center px-4">
      <div className="w-20 h-20 rounded-2xl bg-dark-700 border border-dark-600 flex items-center justify-center mb-5">
        <Building2 className="w-10 h-10 text-gray-600" />
      </div>
      <h3 className="text-lg font-semibold text-gray-300 mb-2">
        Nenhum parceiro cadastrado
      </h3>
      <p className="text-sm text-gray-500 max-w-xs mb-6">
        Crie seu primeiro perfil MSSP e gerencie clientes com branding white-label personalizado.
      </p>
      <button
        onClick={onCreate}
        className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold bg-blue-600 hover:bg-blue-500 transition-colors text-white"
      >
        <Plus className="w-4 h-4" />
        Criar Primeiro Parceiro MSSP
      </button>
    </div>
  )
}

// ── plan legend ───────────────────────────────────────────────────────────────

function PlanLegend() {
  return (
    <div className="flex flex-wrap gap-3">
      {MSSP_PLANS.map(p => (
        <div key={p.id} className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-medium ${p.badge}`}>
          <DollarSign className="w-3 h-3" />
          <span className="font-bold">{p.label}</span>
          <span className="opacity-70">
            {p.maxClients ? `até ${p.maxClients} clientes` : 'ilimitado'}
          </span>
        </div>
      ))}
    </div>
  )
}

// ── main page ─────────────────────────────────────────────────────────────────

export default function MSSP() {
  const { toasts, add: toast } = useToast()

  const [partners, setPartners] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [selectedPartner, setSelectedPartner] = useState(null)
  const [search, setSearch] = useState('')

  const fetchPartners = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/mssp/partners')
      setPartners(Array.isArray(data) ? data : (data.partners || []))
    } catch (ex) {
      toast(ex.response?.data?.detail || 'Erro ao carregar parceiros.', 'error')
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => { fetchPartners() }, [fetchPartners])

  const filtered = partners.filter(p =>
    !search || p.name?.toLowerCase().includes(search.toLowerCase()) ||
    p.slug?.toLowerCase().includes(search.toLowerCase())
  )

  // ── detail view ──
  if (selectedPartner) {
    return (
      <div className="min-h-screen bg-dark-900 p-6">
        <PartnerDetail
          partner={selectedPartner}
          onBack={() => { setSelectedPartner(null); fetchPartners() }}
          toast={toast}
        />
        <ToastArea toasts={toasts} />
      </div>
    )
  }

  // ── list view ──
  return (
    <div className="min-h-screen bg-dark-900 p-6 flex flex-col gap-6">
      {/* header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-9 h-9 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center">
              <Building2 className="w-5 h-5 text-blue-400" />
            </div>
            <h1 className="text-2xl font-bold text-white">MSSP White-Label Portal</h1>
          </div>
          <p className="text-sm text-gray-400 ml-12">
            Gerencie parceiros MSSP com branding personalizado, portfólios de clientes e relatórios white-label.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold bg-blue-600 hover:bg-blue-500 transition-colors text-white shadow-lg shadow-blue-900/30"
        >
          <Plus className="w-4 h-4" />
          Novo Parceiro
        </button>
      </div>

      {/* plan legend */}
      <PlanLegend />

      {/* search + refresh */}
      {partners.length > 0 && (
        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-sm">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              className="w-full bg-dark-700 border border-dark-500 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
              placeholder="Buscar parceiro…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <button
            onClick={fetchPartners}
            className="p-2.5 rounded-lg text-gray-400 hover:text-white hover:bg-dark-700 border border-dark-600 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <span className="text-xs text-gray-500">
            {filtered.length} parceiro{filtered.length !== 1 ? 's' : ''}
          </span>
        </div>
      )}

      {/* content */}
      {loading ? (
        <div className="flex justify-center py-24">
          <Spinner size={10} />
        </div>
      ) : partners.length === 0 ? (
        <EmptyState onCreate={() => setShowCreate(true)} />
      ) : filtered.length === 0 ? (
        <div className="text-center py-16 text-gray-500 text-sm">
          Nenhum parceiro encontrado para "{search}".
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {filtered.map(p => (
            <PartnerCard
              key={p.id}
              partner={p}
              onClick={() => setSelectedPartner(p)}
            />
          ))}
        </div>
      )}

      {/* modals */}
      {showCreate && (
        <CreatePartnerModal
          onClose={() => setShowCreate(false)}
          onCreated={p => {
            setPartners(prev => [p, ...prev])
            setShowCreate(false)
            toast(`Parceiro "${p.name}" criado com sucesso.`, 'success')
          }}
        />
      )}

      <ToastArea toasts={toasts} />
    </div>
  )
}
