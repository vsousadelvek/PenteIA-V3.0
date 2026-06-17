import React, { useState, useEffect, useCallback } from 'react'
import {
  Calendar,
  Clock,
  Play,
  Pause,
  Trash2,
  Plus,
  RefreshCw,
  Zap,
  Settings,
  AlertTriangle,
  ChevronRight,
  X,
  Loader,
  CheckCircle,
  XCircle,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import api from '../api'
import { useToast } from '../components/Toast'

// ─── Constants ────────────────────────────────────────────────────────────────

const FALLBACK_SCHEDULES = []

const CRON_PRESETS = [
  { label: 'Diário às 02:00',             value: '0 2 * * *' },
  { label: 'Diário às 04:00',             value: '0 4 * * *' },
  { label: 'Semanal (Segunda 03:00)',      value: '0 3 * * 1' },
  { label: 'Semanal (Sexta 23:00)',        value: '0 23 * * 5' },
  { label: 'Quinzenal (1º e 15 às 02:00)',value: '0 2 1,15 * *' },
  { label: 'Mensal (dia 1 às 02:00)',      value: '0 2 1 * *' },
  { label: 'A cada 6 horas',              value: '0 */6 * * *' },
  { label: 'Personalizado',               value: '__custom__' },
]

const STATUS_MAP = {
  enabled:  { label: 'Ativo',      cls: 'bg-green-900/40 text-green-400 border border-green-700/40' },
  disabled: { label: 'Inativo',    cls: 'bg-gray-800 text-gray-500 border border-gray-700/40' },
  running:  { label: 'Executando', cls: 'bg-blue-900/40 text-blue-400 border border-blue-700/40' },
  error:    { label: 'Erro',       cls: 'bg-red-900/40 text-red-400 border border-red-700/40' },
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatDateBR(iso) {
  if (!iso) return '—'
  try {
    const d = new Date(iso)
    return d.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
  } catch {
    return iso
  }
}

function countdown(iso) {
  if (!iso) return null
  const diff = new Date(iso) - Date.now()
  if (diff <= 0) return 'Agora'
  const h = Math.floor(diff / 3_600_000)
  const m = Math.floor((diff % 3_600_000) / 60_000)
  if (h > 48) return `em ${Math.floor(h / 24)}d`
  if (h > 0) return `em ${h}h ${m}m`
  return `em ${m}m`
}

function parseCronHuman(expr) {
  const preset = CRON_PRESETS.find(p => p.value === expr)
  if (preset && preset.value !== '__custom__') return preset.label
  return expr
}

// ─── Modal ────────────────────────────────────────────────────────────────────

function CreateScheduleModal({ playbooks, onClose, onCreated }) {
  const toast = useToast()
  const [form, setForm] = useState({
    name: '',
    playbook_id: '',
    target: '',
    cron_expression: '',
    preset: '',
    enabled: true,
  })
  const [customCron, setCustomCron] = useState(false)
  const [loading, setLoading] = useState(false)
  const [errors, setErrors] = useState({})

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const handlePreset = (val) => {
    set('preset', val)
    if (val === '__custom__') {
      setCustomCron(true)
      set('cron_expression', '')
    } else {
      setCustomCron(false)
      set('cron_expression', val)
    }
  }

  const validate = () => {
    const e = {}
    if (!form.name.trim()) e.name = 'Nome obrigatório'
    if (!form.playbook_id) e.playbook_id = 'Selecione um playbook'
    if (!form.target.trim()) e.target = 'Alvo obrigatório'
    if (!form.cron_expression.trim()) e.cron_expression = 'Expressão cron obrigatória'
    setErrors(e)
    return Object.keys(e).length === 0
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!validate()) return
    setLoading(true)
    try {
      const payload = {
        name: form.name.trim(),
        playbook_id: form.playbook_id,
        target: form.target.trim(),
        cron_expression: form.cron_expression.trim(),
        enabled: form.enabled,
      }
      const res = await api.post('/api/schedules', payload)
      toast('Agendamento criado com sucesso!', 'success')
      onCreated(res.data)
    } catch (err) {
      const msg = err.response?.data?.detail || 'Erro ao criar agendamento'
      toast(msg, 'error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-dark-800 border border-dark-600 rounded-xl w-full max-w-lg shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-dark-600">
          <div className="flex items-center gap-2 text-gray-100 font-semibold text-base">
            <Calendar className="w-5 h-5 text-orange-400" />
            Novo Agendamento BAS
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">Nome do agendamento *</label>
            <input
              type="text"
              value={form.name}
              onChange={e => set('name', e.target.value)}
              placeholder="Ex: Scan semanal produção"
              className="w-full bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-orange-500 transition"
            />
            {errors.name && <p className="text-red-400 text-xs mt-1">{errors.name}</p>}
          </div>

          {/* Playbook */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">Playbook *</label>
            <select
              value={form.playbook_id}
              onChange={e => set('playbook_id', e.target.value)}
              className="w-full bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-orange-500 transition"
            >
              <option value="">Selecione um playbook...</option>
              {playbooks.map(pb => (
                <option key={pb.id} value={pb.id}>{pb.name}</option>
              ))}
            </select>
            {errors.playbook_id && <p className="text-red-400 text-xs mt-1">{errors.playbook_id}</p>}
          </div>

          {/* Target */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">Alvo (URL / IP) *</label>
            <input
              type="text"
              value={form.target}
              onChange={e => set('target', e.target.value)}
              placeholder="https://target.example.com"
              className="w-full bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-orange-500 transition"
            />
            {errors.target && <p className="text-red-400 text-xs mt-1">{errors.target}</p>}
          </div>

          {/* Preset selector */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">Frequência</label>
            <select
              value={form.preset}
              onChange={e => handlePreset(e.target.value)}
              className="w-full bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-orange-500 transition"
            >
              <option value="">Selecione um preset...</option>
              {CRON_PRESETS.map(p => (
                <option key={p.value} value={p.value}>{p.label}</option>
              ))}
            </select>
          </div>

          {/* Cron expression (shown always so user can see / always editable if custom) */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">
              Expressão Cron *
              <span className="ml-2 text-gray-600 font-mono text-[10px]">min hora dia mês dia-semana</span>
            </label>
            <input
              type="text"
              value={form.cron_expression}
              onChange={e => set('cron_expression', e.target.value)}
              readOnly={!customCron && !!form.cron_expression && form.preset !== '__custom__'}
              placeholder="0 2 * * *"
              className={`w-full bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm font-mono placeholder-gray-600 focus:outline-none focus:border-orange-500 transition ${
                customCron || !form.cron_expression ? 'text-gray-100' : 'text-orange-300 cursor-not-allowed'
              }`}
            />
            {errors.cron_expression && <p className="text-red-400 text-xs mt-1">{errors.cron_expression}</p>}
          </div>

          {/* Enabled toggle */}
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => set('enabled', !form.enabled)}
              className={`relative w-10 h-5 rounded-full transition-colors duration-200 ${form.enabled ? 'bg-orange-500' : 'bg-dark-500'}`}
            >
              <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform duration-200 ${form.enabled ? 'translate-x-5' : ''}`} />
            </button>
            <span className="text-sm text-gray-400">
              {form.enabled ? 'Ativar agendamento imediatamente' : 'Criar desativado'}
            </span>
          </div>

          {/* Actions */}
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 rounded-lg border border-dark-500 text-gray-400 text-sm hover:border-gray-500 hover:text-gray-200 transition"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-orange-600 hover:bg-orange-500 text-white text-sm font-medium transition disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
              {loading ? 'Criando...' : 'Criar Agendamento'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Schedule Card ─────────────────────────────────────────────────────────────

function ScheduleCard({ schedule, onToggle, onDelete, navigate }) {
  const [toggling, setToggling] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const toast = useToast()

  const status = STATUS_MAP[schedule.status] || STATUS_MAP.disabled
  const isEnabled = schedule.status === 'enabled' || schedule.status === 'running'
  const nextRun = countdown(schedule.next_run)

  const handleToggle = async () => {
    setToggling(true)
    try {
      await onToggle(schedule.id)
    } finally {
      setToggling(false)
    }
  }

  const handleDelete = async () => {
    if (!window.confirm(`Excluir o agendamento "${schedule.name}"?`)) return
    setDeleting(true)
    try {
      await onDelete(schedule.id)
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className={`bg-dark-800 border rounded-xl p-5 transition hover:border-dark-500 ${
      isEnabled ? 'border-dark-600 hover:border-orange-600/30' : 'border-dark-700 opacity-75'
    }`}>
      {/* Row 1: name + status + actions */}
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-gray-100 font-semibold text-sm truncate">{schedule.name}</span>
            <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${status.cls}`}>
              {status.label}
            </span>
          </div>
          {schedule.playbook_name && (
            <p className="text-xs text-gray-500 mt-0.5">
              Playbook: <span className="text-gray-400">{schedule.playbook_name}</span>
            </p>
          )}
          {schedule.target && (
            <p className="text-xs text-gray-600 mt-0.5 font-mono truncate">{schedule.target}</p>
          )}
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-1 flex-shrink-0">
          <button
            onClick={handleToggle}
            disabled={toggling}
            title={isEnabled ? 'Desativar' : 'Ativar'}
            className={`p-1.5 rounded-lg text-xs transition ${
              isEnabled
                ? 'text-yellow-400 hover:bg-yellow-900/30'
                : 'text-green-400 hover:bg-green-900/30'
            } disabled:opacity-50`}
          >
            {toggling
              ? <Loader className="w-4 h-4 animate-spin" />
              : isEnabled
                ? <Pause className="w-4 h-4" />
                : <Play className="w-4 h-4" />
            }
          </button>
          <button
            onClick={handleDelete}
            disabled={deleting}
            title="Excluir"
            className="p-1.5 rounded-lg text-red-500 hover:bg-red-900/30 transition disabled:opacity-50"
          >
            {deleting ? <Loader className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Row 2: cron + schedule info */}
      <div className="grid grid-cols-2 gap-3 mb-3">
        <div className="bg-dark-700 rounded-lg px-3 py-2">
          <div className="flex items-center gap-1.5 mb-0.5">
            <Settings className="w-3 h-3 text-gray-500" />
            <span className="text-[10px] text-gray-500 uppercase tracking-wide">Cron</span>
          </div>
          <p className="text-xs font-mono text-orange-300">{schedule.cron_expression || '—'}</p>
          <p className="text-[10px] text-gray-600 mt-0.5">{parseCronHuman(schedule.cron_expression)}</p>
        </div>

        <div className="bg-dark-700 rounded-lg px-3 py-2">
          <div className="flex items-center gap-1.5 mb-0.5">
            <Clock className="w-3 h-3 text-gray-500" />
            <span className="text-[10px] text-gray-500 uppercase tracking-wide">Próxima Execução</span>
          </div>
          {schedule.next_run ? (
            <>
              <p className="text-xs text-cyan-300 font-medium">{nextRun}</p>
              <p className="text-[10px] text-gray-600 mt-0.5">{formatDateBR(schedule.next_run)}</p>
            </>
          ) : (
            <p className="text-xs text-gray-600">—</p>
          )}
        </div>
      </div>

      {/* Row 3: stats */}
      <div className="flex items-center gap-4 text-xs text-gray-500 border-t border-dark-700 pt-3 mt-1">
        <span className="flex items-center gap-1">
          <Zap className="w-3 h-3 text-gray-600" />
          <span>{schedule.run_count ?? 0} execuções</span>
        </span>

        {schedule.last_run && (
          <span className="flex items-center gap-1">
            <Calendar className="w-3 h-3 text-gray-600" />
            Última: {formatDateBR(schedule.last_run)}
          </span>
        )}

        {schedule.last_sim_id && (
          <button
            onClick={() => navigate('/bas')}
            className="flex items-center gap-1 text-orange-400/80 hover:text-orange-400 transition ml-auto"
          >
            Sim #{schedule.last_sim_id}
            <ChevronRight className="w-3 h-3" />
          </button>
        )}
      </div>
    </div>
  )
}

// ─── Empty State ───────────────────────────────────────────────────────────────

function EmptyState({ onCreate }) {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center px-4">
      <div className="w-16 h-16 rounded-2xl bg-dark-700 border border-dark-600 flex items-center justify-center mb-5">
        <Calendar className="w-8 h-8 text-gray-600" />
      </div>
      <h3 className="text-gray-200 font-semibold text-base mb-2">Nenhum agendamento configurado</h3>
      <p className="text-gray-500 text-sm max-w-sm mb-6">
        Automatize suas simulações BAS criando um agendamento recorrente. O sistema executará os playbooks automaticamente no horário definido.
      </p>
      <button
        onClick={onCreate}
        className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-orange-600 hover:bg-orange-500 text-white text-sm font-medium transition shadow-lg shadow-orange-900/20"
      >
        <Plus className="w-4 h-4" />
        Criar Primeiro Agendamento
      </button>
    </div>
  )
}

// ─── Stats Bar ─────────────────────────────────────────────────────────────────

function StatsBar({ schedules }) {
  const total    = schedules.length
  const active   = schedules.filter(s => s.status === 'enabled' || s.status === 'running').length
  const disabled = schedules.filter(s => s.status === 'disabled').length
  const errored  = schedules.filter(s => s.status === 'error').length
  const runs     = schedules.reduce((acc, s) => acc + (s.run_count || 0), 0)

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
      {[
        { label: 'Total', value: total,    icon: Calendar,    color: 'text-gray-300' },
        { label: 'Ativos',value: active,   icon: CheckCircle, color: 'text-green-400' },
        { label: 'Inativos',value: disabled,icon: XCircle,   color: 'text-gray-500' },
        { label: 'Execuções',value: runs,  icon: Zap,        color: 'text-orange-400' },
      ].map(({ label, value, icon: Icon, color }) => (
        <div key={label} className="bg-dark-800 border border-dark-600 rounded-xl px-4 py-3 flex items-center gap-3">
          <Icon className={`w-5 h-5 ${color} flex-shrink-0`} />
          <div>
            <p className={`text-lg font-bold ${color}`}>{value}</p>
            <p className="text-[10px] text-gray-500 uppercase tracking-wide">{label}</p>
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function ScheduledBAS() {
  const navigate  = useNavigate()
  const toast     = useToast()

  const [schedules,  setSchedules]  = useState(FALLBACK_SCHEDULES)
  const [playbooks,  setPlaybooks]  = useState([])
  const [loading,    setLoading]    = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [showModal,  setShowModal]  = useState(false)
  const [filter,     setFilter]     = useState('all') // all | active | disabled

  // ── Fetch ──────────────────────────────────────────────────────────────────

  const fetchSchedules = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    else setRefreshing(true)
    try {
      const res = await api.get('/api/schedules')
      setSchedules(res.data ?? FALLBACK_SCHEDULES)
    } catch (err) {
      if (!quiet) {
        const msg = err.response?.data?.detail || 'Erro ao carregar agendamentos'
        toast(msg, 'error')
        setSchedules(FALLBACK_SCHEDULES)
      }
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [toast])

  const fetchPlaybooks = useCallback(async () => {
    try {
      const res = await api.get('/api/bas/playbooks')
      setPlaybooks(res.data ?? [])
    } catch {
      // non-critical — playbooks list may be empty
      setPlaybooks([])
    }
  }, [])

  useEffect(() => {
    fetchSchedules()
    fetchPlaybooks()
  }, [fetchSchedules, fetchPlaybooks])

  // Auto-refresh every 30 s
  useEffect(() => {
    const interval = setInterval(() => fetchSchedules(true), 30_000)
    return () => clearInterval(interval)
  }, [fetchSchedules])

  // ── Actions ────────────────────────────────────────────────────────────────

  const handleToggle = useCallback(async (id) => {
    try {
      const res = await api.patch(`/api/schedules/${id}/toggle`)
      const updated = res.data
      setSchedules(prev => prev.map(s => s.id === id ? { ...s, ...updated } : s))
      const isNowEnabled = updated.status === 'enabled' || updated.status === 'running'
      toast(isNowEnabled ? 'Agendamento ativado.' : 'Agendamento desativado.', 'success')
    } catch (err) {
      const msg = err.response?.data?.detail || 'Erro ao alternar agendamento'
      toast(msg, 'error')
    }
  }, [toast])

  const handleDelete = useCallback(async (id) => {
    try {
      await api.delete(`/api/schedules/${id}`)
      setSchedules(prev => prev.filter(s => s.id !== id))
      toast('Agendamento excluído.', 'success')
    } catch (err) {
      const msg = err.response?.data?.detail || 'Erro ao excluir agendamento'
      toast(msg, 'error')
    }
  }, [toast])

  const handleCreated = useCallback((newSchedule) => {
    setSchedules(prev => [newSchedule, ...prev])
    setShowModal(false)
  }, [])

  // ── Filtered list ──────────────────────────────────────────────────────────

  const filtered = schedules.filter(s => {
    if (filter === 'active')   return s.status === 'enabled' || s.status === 'running'
    if (filter === 'disabled') return s.status === 'disabled'
    return true
  })

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-dark-900 text-gray-100 p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Calendar className="w-6 h-6 text-orange-400" />
            <h1 className="text-xl font-bold text-gray-100">Agendamentos BAS</h1>
          </div>
          <p className="text-sm text-gray-500">
            Automatize simulações Breach &amp; Attack com execuções agendadas via cron.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => fetchSchedules(true)}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-dark-600 text-gray-400 text-sm hover:border-gray-500 hover:text-gray-200 transition disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Atualizar
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-orange-600 hover:bg-orange-500 text-white text-sm font-medium transition shadow-lg shadow-orange-900/20"
          >
            <Plus className="w-4 h-4" />
            Novo Agendamento
          </button>
        </div>
      </div>

      {/* Stats */}
      {!loading && schedules.length > 0 && (
        <StatsBar schedules={schedules} />
      )}

      {/* Filter tabs */}
      {!loading && schedules.length > 0 && (
        <div className="flex items-center gap-1 mb-5">
          {[
            { key: 'all',      label: 'Todos' },
            { key: 'active',   label: 'Ativos' },
            { key: 'disabled', label: 'Inativos' },
          ].map(tab => (
            <button
              key={tab.key}
              onClick={() => setFilter(tab.key)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                filter === tab.key
                  ? 'bg-orange-600 text-white'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-dark-700'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      )}

      {/* Content */}
      {loading ? (
        <div className="flex flex-col items-center justify-center py-24 gap-4">
          <Loader className="w-8 h-8 text-orange-400 animate-spin" />
          <p className="text-gray-500 text-sm">Carregando agendamentos...</p>
        </div>
      ) : schedules.length === 0 ? (
        <EmptyState onCreate={() => setShowModal(true)} />
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <AlertTriangle className="w-8 h-8 text-gray-600 mb-3" />
          <p className="text-gray-400 text-sm">Nenhum agendamento nesta categoria.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map(schedule => (
            <ScheduleCard
              key={schedule.id}
              schedule={schedule}
              onToggle={handleToggle}
              onDelete={handleDelete}
              navigate={navigate}
            />
          ))}
        </div>
      )}

      {/* Info footer */}
      {!loading && schedules.length > 0 && (
        <p className="text-[11px] text-gray-700 text-center mt-8">
          Atualiza automaticamente a cada 30 segundos. Os horários exibidos seguem o fuso do servidor.
        </p>
      )}

      {/* Modal */}
      {showModal && (
        <CreateScheduleModal
          playbooks={playbooks}
          onClose={() => setShowModal(false)}
          onCreated={handleCreated}
        />
      )}
    </div>
  )
}
