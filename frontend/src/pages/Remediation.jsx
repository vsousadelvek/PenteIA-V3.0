import React, { useState, useEffect, useCallback } from 'react'
import { Wrench, Plus, RefreshCw, X, AlertTriangle, CheckCircle, Clock, ChevronRight, Trash2, ExternalLink, Zap, Shield, ChevronDown, Loader } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

const STATUS_CONFIG = {
  open:        { label: 'Aberto',       color: 'text-red-400',    bg: 'bg-red-900/20 border-red-800/40',    dot: 'bg-red-500' },
  in_progress: { label: 'Em Andamento', color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-800/40', dot: 'bg-yellow-500' },
  resolved:    { label: 'Resolvido',    color: 'text-blue-400',   bg: 'bg-blue-900/20 border-blue-800/40',  dot: 'bg-blue-500' },
  verified:    { label: 'Verificado',   color: 'text-green-400',  bg: 'bg-green-900/20 border-green-800/40', dot: 'bg-green-500' },
}

const SEV_BADGE = {
  Critical: 'bg-red-900/50 text-red-400 border-red-700',
  High:     'bg-orange-900/50 text-orange-400 border-orange-700',
  Medium:   'bg-yellow-900/50 text-yellow-400 border-yellow-700',
  Low:      'bg-blue-900/50 text-blue-400 border-blue-700',
}

const WAF_TYPES = [
  { value: 'generic_webhook', label: 'Generic Webhook' },
  { value: 'aws_waf',         label: 'AWS WAF' },
  { value: 'cloudflare',      label: 'Cloudflare WAF' },
  { value: 'pfsense',         label: 'pfSense' },
]

// ─── WAF Config Panel ────────────────────────────────────────────────────────

function WafConfigPanel({ onConfigSaved }) {
  const toast = useToast()
  const [open, setOpen] = useState(false)
  const [wafType, setWafType] = useState('generic_webhook')
  const [config, setConfig] = useState({})
  const [saving, setSaving] = useState(false)

  const setField = (key, val) => setConfig(c => ({ ...c, [key]: val }))

  const renderFields = () => {
    switch (wafType) {
      case 'generic_webhook':
        return (
          <>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">URL do Webhook</label>
              <input
                className="input-dark w-full text-sm"
                placeholder="https://hooks.example.com/waf"
                value={config.url || ''}
                onChange={e => setField('url', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Secret</label>
              <input
                type="password"
                className="input-dark w-full text-sm"
                placeholder="shared-secret"
                value={config.secret || ''}
                onChange={e => setField('secret', e.target.value)}
              />
            </div>
          </>
        )
      case 'aws_waf':
        return (
          <>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Region</label>
              <input
                className="input-dark w-full text-sm"
                placeholder="us-east-1"
                value={config.region || ''}
                onChange={e => setField('region', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">WebACL ID</label>
              <input
                className="input-dark w-full text-sm"
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                value={config.webacl_id || ''}
                onChange={e => setField('webacl_id', e.target.value)}
              />
            </div>
          </>
        )
      case 'cloudflare':
        return (
          <>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Zone ID</label>
              <input
                className="input-dark w-full text-sm"
                placeholder="abc123..."
                value={config.zone_id || ''}
                onChange={e => setField('zone_id', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">API Token</label>
              <input
                type="password"
                className="input-dark w-full text-sm"
                placeholder="Bearer token"
                value={config.api_token || ''}
                onChange={e => setField('api_token', e.target.value)}
              />
            </div>
          </>
        )
      case 'pfsense':
        return (
          <>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">URL do pfSense</label>
              <input
                className="input-dark w-full text-sm"
                placeholder="https://192.168.1.1"
                value={config.url || ''}
                onChange={e => setField('url', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">API Key</label>
              <input
                type="password"
                className="input-dark w-full text-sm"
                placeholder="pfsense-api-key"
                value={config.api_key || ''}
                onChange={e => setField('api_key', e.target.value)}
              />
            </div>
          </>
        )
      default:
        return null
    }
  }

  const save = async () => {
    setSaving(true)
    try {
      await api.post('/api/mitigations/configure-waf', { waf_type: wafType, config })
      toast('Configuração WAF salva', 'success')
      setOpen(false)
      if (onConfigSaved) onConfigSaved({ waf_type: wafType, config })
    } catch (e) {
      toast(e.response?.data?.detail || 'Erro ao salvar config WAF', 'error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="card-dark border border-dark-600 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-5 py-3 hover:bg-dark-700 transition"
      >
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span className="text-sm font-semibold text-gray-200">Configurar WAF para Auto-Mitigação</span>
        </div>
        <ChevronDown className={`w-4 h-4 text-gray-400 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="border-t border-dark-600 p-5 space-y-4">
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Tipo de WAF</label>
            <select
              className="select-dark w-full text-sm"
              value={wafType}
              onChange={e => { setWafType(e.target.value); setConfig({}) }}
            >
              {WAF_TYPES.map(w => (
                <option key={w.value} value={w.value}>{w.label}</option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {renderFields()}
          </div>

          <div className="flex justify-end">
            <button
              onClick={save}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-700 hover:bg-cyan-600 text-white rounded text-sm transition disabled:opacity-50"
            >
              {saving ? <Loader className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
              {saving ? 'Salvando...' : 'Salvar Config WAF'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Bulk Create Modal ───────────────────────────────────────────────────────

function BulkModal({ onClose, onSaved }) {
  const toast = useToast()
  const [simulations, setSimulations] = useState([])
  const [form, setForm] = useState({ simulation_id: '', severity_filter: '' })
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    api.get('/api/bas/simulations').then(r => setSimulations((r.data.simulations || []).filter(s => s.status === 'completed'))).catch(() => {})
  }, [])

  const submit = async () => {
    if (!form.simulation_id) { toast('Selecione uma simulação', 'warning'); return }
    setLoading(true)
    try {
      const r = await api.post('/api/remediation/tickets/bulk-create', {
        simulation_id: form.simulation_id,
        severity_filter: form.severity_filter || null,
      })
      toast(`${r.data.created ?? r.data.tickets_created ?? '?'} tickets criados`, 'success')
      onSaved()
      onClose()
    } catch (e) { toast(e.response?.data?.detail || 'Erro', 'error') }
    finally { setLoading(false) }
  }

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-dark-800 border border-dark-600 rounded-xl shadow-2xl w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-5 border-b border-dark-600">
          <h2 className="text-lg font-bold text-gray-100">Criar Tickets em Lote</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-100"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Simulação BAS</label>
            <select className="select-dark w-full" value={form.simulation_id} onChange={e => setForm(f => ({ ...f, simulation_id: e.target.value }))}>
              <option value="">Selecione uma simulação</option>
              {simulations.map(s => (
                <option key={s.id} value={s.id}>{s.playbook_name || s.id.slice(0, 8)} — {s.target}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Filtrar por severidade <span className="text-gray-600">(opcional)</span></label>
            <select className="select-dark w-full" value={form.severity_filter} onChange={e => setForm(f => ({ ...f, severity_filter: e.target.value }))}>
              <option value="">Todas as severidades</option>
              <option value="Critical">Apenas Critical</option>
              <option value="High">Apenas High</option>
              <option value="Medium">Apenas Medium</option>
            </select>
          </div>
          <p className="text-xs text-gray-500">
            Cria um ticket para cada técnica vulnerável encontrada na simulação.
            Tickets duplicados são ignorados automaticamente.
          </p>
        </div>
        <div className="flex justify-end gap-2 p-5 border-t border-dark-600">
          <button onClick={onClose} className="px-4 py-2 bg-dark-700 text-gray-300 rounded text-sm">Cancelar</button>
          <button onClick={submit} disabled={loading} className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded text-sm">
            <Zap className="w-4 h-4" />
            {loading ? 'Criando...' : 'Criar Tickets'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Ticket Card ─────────────────────────────────────────────────────────────

function TicketCard({ ticket, onUpdate, onDelete, supportedTechniques, activeWafType }) {
  const toast = useToast()
  const [expanded, setExpanded] = useState(false)
  const [editing, setEditing] = useState(false)
  const [assignee, setAssignee] = useState(ticket.assignee || '')
  const [extId, setExtId] = useState(ticket.external_ticket_id || '')
  const [mitigating, setMitigating] = useState(false)
  const [mitigationResult, setMitigationResult] = useState(null) // { ok: bool, msg: string }
  const cfg = STATUS_CONFIG[ticket.status] || STATUS_CONFIG.open

  const changeStatus = async (s) => {
    await onUpdate(ticket.id, { status: s })
  }

  const saveEdits = async () => {
    await onUpdate(ticket.id, { assignee, external_ticket_id: extId })
    setEditing(false)
  }

  const isOverdue = ticket.sla_days_remaining != null && ticket.sla_days_remaining < 0 && !['resolved', 'verified'].includes(ticket.status)
  const canMitigate = ticket.technique_id && supportedTechniques.includes(ticket.technique_id)

  const wafLabel = WAF_TYPES.find(w => w.value === activeWafType)?.label || activeWafType || 'WAF'

  const mitigate = async () => {
    if (!activeWafType) {
      toast('Configure o WAF primeiro na seção de Auto-Mitigação', 'warning')
      return
    }
    setMitigating(true)
    setMitigationResult(null)
    try {
      await api.post('/api/mitigations/push', {
        technique_id: ticket.technique_id,
        waf_type: activeWafType,
      })
      setMitigationResult({ ok: true, msg: `Regra enviada para ${wafLabel}` })
    } catch (e) {
      setMitigationResult({ ok: false, msg: e.response?.data?.detail || 'Erro ao enviar regra' })
    } finally {
      setMitigating(false)
    }
  }

  return (
    <div className={`rounded-lg border p-4 ${cfg.bg}`}>
      <div className="flex items-start gap-3">
        <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${cfg.dot}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1">
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <span className="text-xs font-mono text-gray-500">{ticket.technique_id}</span>
                <span className={`text-xs px-1.5 py-0.5 rounded border ${SEV_BADGE[ticket.severity] || SEV_BADGE.Medium}`}>{ticket.severity}</span>
                {ticket.cvss > 0 && <span className="text-xs text-gray-500">CVSS {ticket.cvss}</span>}
                {isOverdue && <span className="text-xs bg-red-900/50 text-red-400 px-2 py-0.5 rounded border border-red-700">SLA Expirado</span>}
              </div>
              <p className="text-sm font-medium text-gray-200">{ticket.title}</p>
              <div className="flex items-center gap-3 mt-1 text-xs text-gray-500">
                <span className={cfg.color}>{cfg.label}</span>
                {ticket.assignee && <span>→ {ticket.assignee}</span>}
                {ticket.sla_days_remaining != null && !['resolved', 'verified'].includes(ticket.status) && (
                  <span className={ticket.sla_days_remaining < 0 ? 'text-red-400' : ticket.sla_days_remaining < 3 ? 'text-yellow-400' : 'text-gray-500'}>
                    <Clock className="w-3 h-3 inline mr-0.5" />
                    {ticket.sla_days_remaining >= 0 ? `${ticket.sla_days_remaining}d restantes` : `${Math.abs(ticket.sla_days_remaining)}d atrasado`}
                  </span>
                )}
                {ticket.external_ticket_id && (
                  <span className="text-cyan-400 flex items-center gap-0.5">
                    <ExternalLink className="w-3 h-3" /> {ticket.external_system || 'Externo'}: {ticket.external_ticket_id}
                  </span>
                )}
              </div>
            </div>
            <div className="flex items-center gap-1 shrink-0">
              {canMitigate && (
                <button
                  onClick={mitigate}
                  disabled={mitigating}
                  title={`Mitigar automaticamente via ${wafLabel}`}
                  className="flex items-center gap-1 px-2 py-1 bg-cyan-900/40 hover:bg-cyan-800/60 border border-cyan-700/50 text-cyan-400 rounded text-xs transition disabled:opacity-50"
                >
                  {mitigating
                    ? <Loader className="w-3 h-3 animate-spin" />
                    : <Zap className="w-3 h-3" />}
                  {mitigating ? '' : 'Mitigar'}
                </button>
              )}
              <button onClick={() => setExpanded(v => !v)} className="p-1.5 text-gray-500 hover:text-gray-300 rounded">
                {expanded ? <ChevronRight className="w-4 h-4 rotate-90" /> : <ChevronRight className="w-4 h-4" />}
              </button>
              <button onClick={() => onDelete(ticket.id)} className="p-1.5 text-gray-600 hover:text-red-400 rounded">
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Inline mitigation result */}
          {mitigationResult && (
            <div className={`mt-2 text-xs px-2 py-1 rounded flex items-center gap-1 ${mitigationResult.ok ? 'bg-green-900/30 text-green-400 border border-green-800/40' : 'bg-red-900/30 text-red-400 border border-red-800/40'}`}>
              {mitigationResult.ok ? <CheckCircle className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
              {mitigationResult.msg}
              {mitigationResult.ok && ' ✓'}
            </div>
          )}

          {expanded && (
            <div className="mt-3 space-y-3 border-t border-dark-600 pt-3">
              {ticket.remediation_steps && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Passos de remediação</p>
                  <p className="text-xs text-gray-300 leading-relaxed">{ticket.remediation_steps}</p>
                </div>
              )}
              {ticket.compliance?.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {ticket.compliance.map(c => (
                    <span key={c} className="text-xs px-1.5 py-0.5 rounded bg-dark-700 text-cyan-400 border border-dark-500">{c}</span>
                  ))}
                </div>
              )}

              {editing ? (
                <div className="space-y-2">
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="text-[10px] text-gray-500 mb-0.5 block">Responsável</label>
                      <input className="input-dark w-full text-xs" value={assignee} onChange={e => setAssignee(e.target.value)} placeholder="nome@empresa.com" />
                    </div>
                    <div>
                      <label className="text-[10px] text-gray-500 mb-0.5 block">ID Ticket Externo</label>
                      <input className="input-dark w-full text-xs" value={extId} onChange={e => setExtId(e.target.value)} placeholder="JIRA-123" />
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={saveEdits} className="px-3 py-1 bg-red-700 hover:bg-red-600 text-white rounded text-xs">Salvar</button>
                    <button onClick={() => setEditing(false)} className="px-3 py-1 bg-dark-700 text-gray-300 rounded text-xs">Cancelar</button>
                  </div>
                </div>
              ) : (
                <button onClick={() => setEditing(true)} className="text-xs text-gray-500 hover:text-gray-300">Editar responsável / ticket externo</button>
              )}

              <div className="flex gap-1 flex-wrap">
                {Object.entries(STATUS_CONFIG).map(([s, c]) => (
                  <button key={s} onClick={() => changeStatus(s)}
                    className={`text-xs px-2 py-1 rounded border transition ${ticket.status === s ? `${c.bg} ${c.color}` : 'bg-dark-700 border-dark-600 text-gray-500 hover:text-gray-300'}`}>
                    {c.label}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function Remediation() {
  const toast = useToast()
  const [tickets, setTickets] = useState([])
  const [stats, setStats] = useState({})
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [showBulk, setShowBulk] = useState(false)

  // Auto-mitigation state
  const [supportedTechniques, setSupportedTechniques] = useState([])
  const [activeWafType, setActiveWafType] = useState(null)
  const [bulkMitigating, setBulkMitigating] = useState(false)
  const [bulkResult, setBulkResult] = useState(null) // { pushed, failed, errors }

  const load = useCallback(() => {
    setLoading(true)
    api.get('/api/remediation/tickets').then(r => {
      setTickets(r.data.tickets || [])
      setStats(r.data.stats || {})
    }).catch(() => {}).finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  // Fetch supported technique IDs on mount
  useEffect(() => {
    api.get('/api/mitigations/supported')
      .then(r => setSupportedTechniques(r.data?.techniques || []))
      .catch(() => {})
  }, [])

  const update = async (id, data) => {
    try {
      await api.put(`/api/remediation/tickets/${id}`, data)
      load()
    } catch (e) { toast(e.response?.data?.detail || 'Erro', 'error') }
  }

  const del = async (id) => {
    if (!window.confirm('Excluir ticket?')) return
    try {
      await api.delete(`/api/remediation/tickets/${id}`)
      toast('Ticket excluído', 'info')
      load()
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao excluir ticket', 'error') }
  }

  const filtered = tickets.filter(t => {
    if (statusFilter !== 'all' && t.status !== statusFilter) return false
    if (severityFilter !== 'all' && t.severity !== severityFilter) return false
    return true
  })

  const columns = ['open', 'in_progress', 'resolved', 'verified']

  // Critical tickets that have a simulation_id (needed for push-all)
  const criticalSimIds = [...new Set(
    tickets.filter(t => t.severity === 'Critical' && t.simulation_id).map(t => t.simulation_id)
  )]

  const pushAllCritical = async () => {
    if (!activeWafType) {
      toast('Configure o WAF primeiro na seção de Auto-Mitigação', 'warning')
      return
    }
    if (criticalSimIds.length === 0) {
      toast('Nenhum ticket crítico com simulação associada encontrado', 'warning')
      return
    }
    setBulkMitigating(true)
    setBulkResult(null)
    try {
      // Push for each distinct simulation with critical tickets
      const results = await Promise.allSettled(
        criticalSimIds.map(simId =>
          api.post(`/api/mitigations/push-all/${simId}`, { waf_type: activeWafType })
        )
      )
      let pushed = 0, failed = 0, errors = []
      results.forEach((r, i) => {
        if (r.status === 'fulfilled') {
          pushed += r.value.data.pushed || 0
          failed += r.value.data.failed || 0
          if (r.value.data.errors?.length) errors.push(...r.value.data.errors)
        } else {
          failed++
          errors.push(r.reason?.response?.data?.detail || `Sim ${criticalSimIds[i]} falhou`)
        }
      })
      setBulkResult({ pushed, failed, errors })
      if (pushed > 0) toast(`${pushed} regras enviadas para o WAF`, 'success')
      if (failed > 0) toast(`${failed} falha(s) ao enviar regras`, 'warning')
    } catch (e) {
      toast(e.response?.data?.detail || 'Erro na mitigação em massa', 'error')
    } finally {
      setBulkMitigating(false)
    }
  }

  const wafLabel = WAF_TYPES.find(w => w.value === activeWafType)?.label || ''

  return (
    <div className="space-y-6">
      {/* ── Header ── */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <Wrench className="w-6 h-6 text-red-500" />
            Remediation Tracker
          </h1>
          <p className="text-sm text-gray-400 mt-1">Gerencie o ciclo de vida da remediação das vulnerabilidades encontradas</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <button onClick={load} className="p-2 text-gray-400 hover:text-gray-200 hover:bg-dark-700 rounded transition">
            <RefreshCw className="w-4 h-4" />
          </button>
          {/* Mitigação em Massa */}
          <button
            onClick={pushAllCritical}
            disabled={bulkMitigating}
            className="flex items-center gap-2 px-4 py-2 bg-purple-800 hover:bg-purple-700 border border-purple-600 text-white rounded-lg text-sm transition disabled:opacity-50"
          >
            {bulkMitigating
              ? <Loader className="w-4 h-4 animate-spin" />
              : <Zap className="w-4 h-4" />}
            {bulkMitigating ? 'Mitigando...' : 'Mitigar Todos os Tickets Críticos'}
          </button>
          <button onClick={() => setShowBulk(true)} className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-gray-300 rounded-lg text-sm transition">
            <Zap className="w-4 h-4" /> Importar da Simulação
          </button>
        </div>
      </div>

      {/* ── Bulk mitigation result banner ── */}
      {bulkResult && (
        <div className={`rounded-lg border p-4 flex items-start gap-3 ${bulkResult.failed === 0 ? 'bg-green-900/20 border-green-800/40' : 'bg-yellow-900/20 border-yellow-800/40'}`}>
          {bulkResult.failed === 0
            ? <CheckCircle className="w-5 h-5 text-green-400 shrink-0 mt-0.5" />
            : <AlertTriangle className="w-5 h-5 text-yellow-400 shrink-0 mt-0.5" />}
          <div className="flex-1">
            <p className="text-sm font-medium text-gray-200">
              Mitigação em Massa concluída — {bulkResult.pushed} regra(s) enviada(s)
              {bulkResult.failed > 0 && `, ${bulkResult.failed} falha(s)`}
              {wafLabel ? ` via ${wafLabel}` : ''}
            </p>
            {bulkResult.errors?.length > 0 && (
              <ul className="mt-2 space-y-0.5">
                {bulkResult.errors.map((err, i) => (
                  <li key={i} className="text-xs text-red-400">{err}</li>
                ))}
              </ul>
            )}
          </div>
          <button onClick={() => setBulkResult(null)} className="text-gray-500 hover:text-gray-300 shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* ── Stats ── */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { key: 'open', label: 'Abertos', color: 'text-red-400' },
          { key: 'in_progress', label: 'Em Andamento', color: 'text-yellow-400' },
          { key: 'resolved', label: 'Resolvidos', color: 'text-blue-400' },
          { key: 'verified', label: 'Verificados', color: 'text-green-400' },
          { key: 'overdue', label: 'SLA Expirado', color: 'text-orange-400' },
        ].map(s => (
          <div key={s.key} className="card-dark p-3 text-center">
            <p className={`text-2xl font-bold ${s.color}`}>{stats[s.key] || 0}</p>
            <p className="text-xs text-gray-500">{s.label}</p>
          </div>
        ))}
      </div>

      {/* ── Auto-Mitigação Panel ── */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">Auto-Mitigacao</h2>
          {activeWafType && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-900/40 border border-cyan-700/50 text-cyan-400">
              {wafLabel} ativo
            </span>
          )}
          {supportedTechniques.length > 0 && (
            <span className="text-xs text-gray-600 ml-auto">{supportedTechniques.length} tecnicas suportadas</span>
          )}
        </div>
        <WafConfigPanel onConfigSaved={({ waf_type }) => setActiveWafType(waf_type)} />
      </div>

      {/* ── Filters ── */}
      <div className="flex flex-wrap gap-2">
        <select className="select-dark text-sm" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="all">Todos os status</option>
          {Object.entries(STATUS_CONFIG).map(([s, c]) => (
            <option key={s} value={s}>{c.label}</option>
          ))}
        </select>
        <select className="select-dark text-sm" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
          <option value="all">Toda severidade</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <span className="text-xs text-gray-500 self-center">{filtered.length} tickets</span>
      </div>

      {/* ── Ticket board ── */}
      {loading ? (
        <div className="flex justify-center py-16">
          <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="card-dark p-12 text-center">
          <Wrench className="w-10 h-10 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">Nenhum ticket encontrado</p>
          <p className="text-gray-600 text-sm mt-1">Importe vulnerabilidades de uma simulação BAS para começar</p>
          <button onClick={() => setShowBulk(true)} className="mt-4 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded text-sm">
            Importar da Simulação
          </button>
        </div>
      ) : (
        <>
          <div className="hidden md:grid grid-cols-4 gap-4">
            {columns.map(col => {
              const colTickets = filtered.filter(t => t.status === col)
              const cfg = STATUS_CONFIG[col]
              return (
                <div key={col} className="space-y-2">
                  <div className="flex items-center gap-2 pb-2 border-b border-dark-600">
                    <div className={`w-2 h-2 rounded-full ${cfg.dot}`} />
                    <span className={`text-xs font-semibold ${cfg.color}`}>{cfg.label}</span>
                    <span className="text-xs text-gray-600 ml-auto">{colTickets.length}</span>
                  </div>
                  {colTickets.map(t => (
                    <TicketCard
                      key={t.id}
                      ticket={t}
                      onUpdate={update}
                      onDelete={del}
                      supportedTechniques={supportedTechniques}
                      activeWafType={activeWafType}
                    />
                  ))}
                  {colTickets.length === 0 && (
                    <p className="text-xs text-gray-700 text-center py-4">Vazio</p>
                  )}
                </div>
              )
            })}
          </div>

          <div className="md:hidden space-y-3">
            {filtered.map(t => (
              <TicketCard
                key={t.id}
                ticket={t}
                onUpdate={update}
                onDelete={del}
                supportedTechniques={supportedTechniques}
                activeWafType={activeWafType}
              />
            ))}
          </div>
        </>
      )}

      {showBulk && <BulkModal onClose={() => setShowBulk(false)} onSaved={load} />}
    </div>
  )
}
