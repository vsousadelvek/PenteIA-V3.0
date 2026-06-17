import React, { useState, useEffect, useCallback } from 'react'
import {
  Shield, AlertTriangle, Key, Users, Server, GitBranch,
  Play, ChevronDown, ChevronUp, Clock, Target,
  Loader, X, CheckCircle, XCircle, ArrowRight, ExternalLink, Info,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useToast } from '../components/Toast'
import api from '../api'
import { ReactFlow, Background, Controls } from '@xyflow/react'
import '@xyflow/react/dist/style.css'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEV_CONFIG = {
  Critical: {
    text: 'text-red-400',
    bg: 'bg-red-900/30',
    border: 'border-red-700/60',
    badge: 'bg-red-900/60 text-red-300 border border-red-700/50',
    dot: 'bg-red-500',
  },
  High: {
    text: 'text-orange-400',
    bg: 'bg-orange-900/20',
    border: 'border-orange-700/50',
    badge: 'bg-orange-900/60 text-orange-300 border border-orange-700/50',
    dot: 'bg-orange-500',
  },
  Medium: {
    text: 'text-yellow-400',
    bg: 'bg-yellow-900/15',
    border: 'border-yellow-700/40',
    badge: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700/50',
    dot: 'bg-yellow-500',
  },
  Low: {
    text: 'text-blue-400',
    bg: 'bg-blue-900/15',
    border: 'border-blue-700/40',
    badge: 'bg-blue-900/60 text-blue-300 border border-blue-700/50',
    dot: 'bg-blue-500',
  },
}

const DIFF_CONFIG = {
  low: { label: 'Fácil', text: 'text-green-400', badge: 'bg-green-900/50 text-green-300 border border-green-700/50' },
  medium: { label: 'Médio', badge: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700/50' },
  high: { label: 'Difícil', text: 'text-red-400', badge: 'bg-red-900/50 text-red-300 border border-red-700/50' },
}

const TACTIC_ICON = {
  'Credential Access': Key,
  'Privilege Escalation': AlertTriangle,
  'Lateral Movement': GitBranch,
  'Persistence': Server,
  'Discovery': Target,
  'Collection': Users,
  'Defense Evasion': Shield,
}

function getTacticIcon(tactic) {
  if (!tactic) return Shield
  for (const [key, Icon] of Object.entries(TACTIC_ICON)) {
    if (tactic.toLowerCase().includes(key.toLowerCase())) return Icon
  }
  return Shield
}

function cvssColor(score) {
  if (!score) return 'bg-gray-800 text-gray-500'
  if (score >= 9.0) return 'bg-red-900/70 text-red-300 border border-red-700/50'
  if (score >= 7.0) return 'bg-orange-900/70 text-orange-300 border border-orange-700/50'
  if (score >= 4.0) return 'bg-yellow-900/70 text-yellow-300 border border-yellow-700/50'
  return 'bg-blue-900/70 text-blue-300 border border-blue-700/50'
}

// ---------------------------------------------------------------------------
// Skeleton loader
// ---------------------------------------------------------------------------

function SkeletonCard() {
  return (
    <div className="rounded-xl border border-dark-600 bg-dark-800 p-4 space-y-3 animate-pulse">
      <div className="flex items-start justify-between">
        <div className="h-4 w-24 bg-dark-600 rounded" />
        <div className="h-5 w-16 bg-dark-600 rounded" />
      </div>
      <div className="h-5 w-3/4 bg-dark-600 rounded" />
      <div className="flex gap-2">
        <div className="h-4 w-20 bg-dark-600 rounded" />
        <div className="h-4 w-14 bg-dark-600 rounded" />
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Simulate Modal
// ---------------------------------------------------------------------------

function SimulateModal({ technique, onClose, onResult }) {
  const toast = useToast()
  const [targetDomain, setTargetDomain] = useState('')
  const [targetDc, setTargetDc] = useState('')
  const [running, setRunning] = useState(false)

  const handleSimulate = async () => {
    if (!targetDomain.trim()) {
      toast.error('Informe o domínio alvo')
      return
    }
    setRunning(true)
    try {
      const res = await api.post(`/api/ad-attacks/techniques/${technique.id}/simulate`, {
        target_domain: targetDomain.trim(),
        target_dc: targetDc.trim() || undefined,
      })
      onResult(res.data)
      onClose()
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Erro ao simular técnica')
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md bg-dark-800 border border-dark-600 rounded-2xl shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-dark-600">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-red-900/40 border border-red-700/50 flex items-center justify-center">
              <Play className="w-4 h-4 text-red-400" />
            </div>
            <div>
              <p className="text-gray-100 font-semibold text-sm">Simular Técnica</p>
              <p className="text-gray-500 text-xs font-mono">{technique.id}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs text-gray-400 font-medium mb-1.5">
              Domínio Alvo <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              placeholder="ex: corp.empresa.local"
              value={targetDomain}
              onChange={e => setTargetDomain(e.target.value)}
              className="w-full bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-200
                         placeholder-gray-600 focus:outline-none focus:border-red-600 transition"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 font-medium mb-1.5">
              Domain Controller (opcional)
            </label>
            <input
              type="text"
              placeholder="ex: 10.0.0.1 ou dc01.corp.local"
              value={targetDc}
              onChange={e => setTargetDc(e.target.value)}
              className="w-full bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-200
                         placeholder-gray-600 focus:outline-none focus:border-red-600 transition"
            />
          </div>

          {/* Warning */}
          <div className="flex items-start gap-2 p-3 rounded-lg bg-yellow-900/20 border border-yellow-700/30">
            <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
            <p className="text-yellow-300 text-xs leading-relaxed">
              Execute apenas em ambientes autorizados. Esta simulação requer permissão explícita do responsável pela rede.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-dark-600 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200 transition"
          >
            Cancelar
          </button>
          <button
            onClick={handleSimulate}
            disabled={running}
            className="flex items-center gap-2 px-5 py-2 rounded-lg bg-red-700 hover:bg-red-600
                       text-white text-sm font-semibold transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {running ? <Loader className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {running ? 'Simulando...' : 'Executar Simulação'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Simulation Result Panel
// ---------------------------------------------------------------------------

function SimResultPanel({ result, onClose }) {
  const navigate = useNavigate()

  if (!result) return null

  const steps = result.kill_chain_steps || []
  const findings = result.findings || []
  const simId = result.simulation_id

  return (
    <div className="rounded-xl border border-dark-600 bg-dark-800 overflow-hidden">
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-3 bg-dark-700 border-b border-dark-600">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
          <span className="text-sm font-semibold text-gray-100">Resultado da Simulação</span>
          {simId && (
            <span className="text-xs font-mono text-gray-500 ml-1">#{simId.slice(0, 8)}</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {simId && (
            <button
              onClick={() => navigate(`/attack-path/${simId}`)}
              className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 transition"
            >
              <ExternalLink className="w-3 h-3" />
              Ver Grafo
            </button>
          )}
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition">
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Kill chain steps */}
        {steps.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Kill Chain Executada</p>
            <div className="space-y-1.5">
              {steps.map((step, i) => (
                <div key={i} className="flex items-start gap-2.5">
                  <div className={`flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center mt-0.5 ${
                    step.success ? 'bg-red-900/60 border border-red-600' : 'bg-green-900/60 border border-green-600'
                  }`}>
                    {step.success
                      ? <CheckCircle className="w-3 h-3 text-red-400" />
                      : <XCircle className="w-3 h-3 text-green-400" />
                    }
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-gray-300 font-medium">{step.phase || step.name}</p>
                    {step.detail && <p className="text-xs text-gray-500 mt-0.5">{step.detail}</p>}
                  </div>
                  <span className={`text-xs px-1.5 py-0.5 rounded font-mono flex-shrink-0 ${
                    step.success ? 'bg-red-900/40 text-red-400' : 'bg-green-900/40 text-green-400'
                  }`}>
                    {step.success ? 'EXEC' : 'BLOCK'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Findings */}
        {findings.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Findings</p>
            <div className="space-y-1">
              {findings.map((f, i) => (
                <div key={i} className="flex items-start gap-2 p-2 rounded-lg bg-red-950/30 border border-red-800/30">
                  <AlertTriangle className="w-3.5 h-3.5 text-red-400 flex-shrink-0 mt-0.5" />
                  <p className="text-xs text-red-300">{typeof f === 'string' ? f : f.description || JSON.stringify(f)}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Conclusion */}
        {result.conclusion && (
          <div className="p-3 rounded-lg bg-dark-700 border border-dark-500">
            <p className="text-xs text-gray-400 font-medium mb-1">Conclusão</p>
            <p className="text-sm text-gray-200">{result.conclusion}</p>
          </div>
        )}

        {/* Link to attack path */}
        {simId && (
          <button
            onClick={() => navigate(`/attack-path/${simId}`)}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg
                       bg-cyan-900/30 border border-cyan-700/40 text-cyan-400 text-sm
                       hover:bg-cyan-900/50 transition font-medium"
          >
            <GitBranch className="w-4 h-4" />
            Ver Attack Path Completo
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Technique Card
// ---------------------------------------------------------------------------

function TechniqueCard({ technique, onSimulate }) {
  const [expanded, setExpanded] = useState(false)
  const sev = SEV_CONFIG[technique.severity] || SEV_CONFIG.Low
  const TacticIcon = getTacticIcon(technique.tactic)

  return (
    <div className={`rounded-xl border ${sev.border} bg-dark-800 overflow-hidden
                    transition-all duration-200 hover:shadow-lg hover:shadow-black/30`}>
      {/* Card header — always visible */}
      <div
        className="p-4 cursor-pointer select-none"
        onClick={() => setExpanded(e => !e)}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0">
            {/* Tactic icon */}
            <div className={`flex-shrink-0 w-9 h-9 rounded-lg ${sev.bg} border ${sev.border}
                            flex items-center justify-center mt-0.5`}>
              <TacticIcon className={`w-4 h-4 ${sev.text}`} />
            </div>
            <div className="min-w-0">
              {/* ID badge */}
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <span className="font-mono text-xs bg-dark-700 text-gray-400 border border-dark-500 px-2 py-0.5 rounded">
                  {technique.id}
                </span>
                {technique.br_context && (
                  <span className="text-xs px-2 py-0.5 rounded-full bg-green-900/40 text-green-400 border border-green-700/40 font-medium">
                    Contexto Brasil
                  </span>
                )}
              </div>
              {/* Name */}
              <p className="text-gray-100 font-semibold text-sm leading-snug">{technique.name}</p>
            </div>
          </div>

          {/* Right: badges + chevron */}
          <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
            <span className={`text-xs px-2.5 py-1 rounded-full font-bold ${sev.badge}`}>
              {technique.severity}
            </span>
            {expanded
              ? <ChevronUp className="w-4 h-4 text-gray-500" />
              : <ChevronDown className="w-4 h-4 text-gray-500" />
            }
          </div>
        </div>

        {/* Tactic + CVSS row */}
        <div className="flex items-center gap-2 mt-3 flex-wrap">
          {technique.tactic && (
            <span className="text-xs px-2 py-0.5 rounded bg-dark-700 text-purple-400 border border-purple-800/40">
              {technique.tactic}
            </span>
          )}
          {technique.cvss_score > 0 && (
            <span className={`font-mono text-xs px-2 py-0.5 rounded font-bold ${cvssColor(technique.cvss_score)}`}>
              CVSS {technique.cvss_score.toFixed(1)}
            </span>
          )}
          {technique.mitre_url && (
            <a
              href={technique.mitre_url}
              target="_blank"
              rel="noopener noreferrer"
              onClick={e => e.stopPropagation()}
              className="text-xs text-gray-500 hover:text-cyan-400 transition flex items-center gap-1"
            >
              <ExternalLink className="w-3 h-3" />
              MITRE
            </a>
          )}
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-dark-600 px-4 py-4 space-y-4">
          {/* Description */}
          {technique.description && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">Descrição</p>
              <p className="text-sm text-gray-300 leading-relaxed">{technique.description}</p>
            </div>
          )}

          {/* Prerequisites */}
          {technique.prerequisites?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">Pré-requisitos</p>
              <ul className="space-y-1">
                {technique.prerequisites.map((p, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-gray-400">
                    <ArrowRight className="w-3 h-3 text-orange-500 flex-shrink-0 mt-0.5" />
                    {p}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Kill chain */}
          {technique.kill_chain?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Kill Chain</p>
              <div className="flex flex-wrap items-center gap-1.5">
                {technique.kill_chain.map((phase, i) => (
                  <React.Fragment key={i}>
                    <span className="text-xs px-2.5 py-1 rounded-full bg-dark-700 border border-dark-500 text-gray-300">
                      {phase}
                    </span>
                    {i < technique.kill_chain.length - 1 && (
                      <ArrowRight className="w-3 h-3 text-gray-600" />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}

          {/* Tools */}
          {technique.tools?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">Ferramentas</p>
              <div className="flex flex-wrap gap-1.5">
                {technique.tools.map((t, i) => (
                  <span key={i} className="text-xs px-2 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-800/40 font-mono">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Mitigations */}
          {technique.mitigations?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">Mitigações</p>
              <ul className="space-y-1">
                {technique.mitigations.map((m, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-green-400">
                    <Shield className="w-3 h-3 flex-shrink-0 mt-0.5" />
                    {m}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Detection hints */}
          {technique.detection_hints?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">Dicas de Detecção</p>
              <ul className="space-y-1">
                {technique.detection_hints.map((d, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-cyan-400">
                    <Target className="w-3 h-3 flex-shrink-0 mt-0.5" />
                    {d}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* BR Context detail */}
          {technique.br_context_detail && (
            <div className="p-3 rounded-lg bg-green-900/15 border border-green-700/30">
              <div className="flex items-center gap-1.5 mb-1.5">
                <Info className="w-3.5 h-3.5 text-green-400" />
                <p className="text-xs font-semibold text-green-400">Relevância Brasil</p>
              </div>
              <p className="text-xs text-green-300">{technique.br_context_detail}</p>
            </div>
          )}

          {/* Simulate button */}
          <button
            onClick={() => onSimulate(technique)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-700 hover:bg-red-600
                       text-white text-sm font-semibold transition w-full justify-center mt-1"
          >
            <Play className="w-4 h-4" />
            Simular Técnica
          </button>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Tab 1 — AD Techniques
// ---------------------------------------------------------------------------

function ADTechniquesTab() {
  const [techniques, setTechniques] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [simulateTarget, setSimulateTarget] = useState(null)
  const [simResults, setSimResults] = useState({})   // techniqueId → result
  const [filterSev, setFilterSev] = useState('All')
  const [filterTactic, setFilterTactic] = useState('All')
  const [search, setSearch] = useState('')

  useEffect(() => {
    api.get('/api/ad-attacks/techniques')
      .then(res => setTechniques(res.data?.techniques || res.data || []))
      .catch(err => setError(err.response?.data?.detail || 'Erro ao carregar técnicas'))
      .finally(() => setLoading(false))
  }, [])

  const allTactics = ['All', ...new Set(techniques.map(t => t.tactic).filter(Boolean))]

  const filtered = techniques.filter(t => {
    const matchSev = filterSev === 'All' || t.severity === filterSev
    const matchTac = filterTactic === 'All' || t.tactic === filterTactic
    const matchSearch = !search || t.name?.toLowerCase().includes(search.toLowerCase())
      || t.id?.toLowerCase().includes(search.toLowerCase())
    return matchSev && matchTac && matchSearch
  })

  const handleSimResult = useCallback((techniqueId, result) => {
    setSimResults(prev => ({ ...prev, [techniqueId]: result }))
  }, [])

  if (loading) return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      {Array.from({ length: 6 }).map((_, i) => <SkeletonCard key={i} />)}
    </div>
  )

  if (error) return (
    <div className="card-dark p-8 text-center">
      <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
      <p className="text-red-400">{error}</p>
    </div>
  )

  return (
    <div className="space-y-5">
      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <input
          type="text"
          placeholder="Buscar técnica ou ID..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-200
                     placeholder-gray-600 focus:outline-none focus:border-red-600 transition w-56"
        />
        <select
          value={filterSev}
          onChange={e => setFilterSev(e.target.value)}
          className="bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-red-600 transition"
        >
          <option value="All">Todas as Severidades</option>
          {['Critical', 'High', 'Medium', 'Low'].map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={filterTactic}
          onChange={e => setFilterTactic(e.target.value)}
          className="bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-red-600 transition"
        >
          {allTactics.map(t => (
            <option key={t} value={t}>{t === 'All' ? 'Todas as Táticas' : t}</option>
          ))}
        </select>
        <span className="text-xs text-gray-500 ml-auto">
          {filtered.length} de {techniques.length} técnicas
        </span>
      </div>

      {/* Grid */}
      {filtered.length === 0 ? (
        <div className="text-center py-16">
          <Shield className="w-12 h-12 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-500">Nenhuma técnica encontrada</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map(t => (
            <div key={t.id} className="space-y-3">
              <TechniqueCard
                technique={t}
                onSimulate={setSimulateTarget}
              />
              {simResults[t.id] && (
                <SimResultPanel
                  result={simResults[t.id]}
                  onClose={() => setSimResults(prev => {
                    const next = { ...prev }
                    delete next[t.id]
                    return next
                  })}
                />
              )}
            </div>
          ))}
        </div>
      )}

      {/* Simulate modal */}
      {simulateTarget && (
        <SimulateModal
          technique={simulateTarget}
          onClose={() => setSimulateTarget(null)}
          onResult={result => handleSimResult(simulateTarget.id, result)}
        />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Path visual diagram
// ---------------------------------------------------------------------------

function PathDiagram({ steps }) {
  if (!steps?.length) return null
  return (
    <div className="flex flex-wrap items-center gap-1.5 py-2">
      {steps.map((step, i) => (
        <React.Fragment key={i}>
          <div className="flex flex-col items-center">
            <span className="font-mono text-xs bg-dark-700 border border-dark-500 text-gray-400 px-2.5 py-1.5 rounded-lg whitespace-nowrap">
              {step}
            </span>
          </div>
          {i < steps.length - 1 && (
            <ArrowRight className="w-4 h-4 text-red-500 flex-shrink-0" />
          )}
        </React.Fragment>
      ))}
      <div className="flex flex-col items-center ml-1">
        <span className="font-mono text-xs bg-red-900/50 border border-red-700/60 text-red-400 px-2.5 py-1.5 rounded-lg font-bold whitespace-nowrap">
          Domain Admin
        </span>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Path Simulate Modal
// ---------------------------------------------------------------------------

function PathSimulateModal({ path, onClose, onResult }) {
  const toast = useToast()
  const [targetDomain, setTargetDomain] = useState('')
  const [running, setRunning] = useState(false)

  const handleSimulate = async () => {
    if (!targetDomain.trim()) {
      toast.error('Informe o domínio alvo')
      return
    }
    setRunning(true)
    try {
      const res = await api.post(`/api/ad-attacks/paths/${path.id}/simulate`, {
        target_domain: targetDomain.trim(),
      })
      onResult(res.data)
      onClose()
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Erro ao simular caminho')
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md bg-dark-800 border border-dark-600 rounded-2xl shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-dark-600">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-red-900/40 border border-red-700/50 flex items-center justify-center">
              <GitBranch className="w-4 h-4 text-red-400" />
            </div>
            <div>
              <p className="text-gray-100 font-semibold text-sm">{path.name}</p>
              <p className="text-gray-500 text-xs">Simulação de caminho completo</p>
            </div>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs text-gray-400 font-medium mb-1.5">
              Domínio Alvo <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              placeholder="ex: corp.empresa.local"
              value={targetDomain}
              onChange={e => setTargetDomain(e.target.value)}
              className="w-full bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-200
                         placeholder-gray-600 focus:outline-none focus:border-red-600 transition"
            />
          </div>
          <div className="flex items-start gap-2 p-3 rounded-lg bg-yellow-900/20 border border-yellow-700/30">
            <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
            <p className="text-yellow-300 text-xs leading-relaxed">
              Esta simulação executará {path.step_count || path.steps?.length || '?'} técnicas em sequência. Use somente em ambientes de laboratório autorizados.
            </p>
          </div>
        </div>
        <div className="px-6 py-4 border-t border-dark-600 flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200 transition">
            Cancelar
          </button>
          <button
            onClick={handleSimulate}
            disabled={running}
            className="flex items-center gap-2 px-5 py-2 rounded-lg bg-red-700 hover:bg-red-600
                       text-white text-sm font-semibold transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {running ? <Loader className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {running ? 'Executando...' : 'Simular Caminho Completo'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Path Result Panel
// ---------------------------------------------------------------------------

function PathResultPanel({ result, onClose }) {
  const navigate = useNavigate()
  if (!result) return null

  const steps = result.steps || []
  const simId = result.simulation_id

  const successCount = steps.filter(s => s.success).length
  const totalCount = steps.length

  return (
    <div className="rounded-xl border border-dark-600 bg-dark-800 overflow-hidden mt-3">
      <div className="flex items-center justify-between px-4 py-3 bg-dark-700 border-b border-dark-600">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
          <span className="text-sm font-semibold text-gray-100">Resultado do Caminho</span>
          <span className="text-xs text-gray-500">
            {successCount}/{totalCount} passos bem-sucedidos
          </span>
        </div>
        <div className="flex items-center gap-2">
          {simId && (
            <button
              onClick={() => navigate(`/attack-path/${simId}`)}
              className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 transition"
            >
              <ExternalLink className="w-3 h-3" />
              Ver Grafo
            </button>
          )}
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition">
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Progress bar */}
        <div>
          <div className="flex justify-between text-xs text-gray-400 mb-1.5">
            <span>Progresso do ataque</span>
            <span>{totalCount > 0 ? Math.round((successCount / totalCount) * 100) : 0}%</span>
          </div>
          <div className="w-full h-2 bg-dark-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-red-600 to-red-400 rounded-full transition-all duration-500"
              style={{ width: totalCount > 0 ? `${(successCount / totalCount) * 100}%` : '0%' }}
            />
          </div>
        </div>

        {/* Step-by-step */}
        {steps.length > 0 && (
          <div className="space-y-2">
            {steps.map((step, i) => (
              <div
                key={i}
                className={`flex items-start gap-3 p-3 rounded-lg border ${
                  step.success
                    ? 'bg-red-950/20 border-red-800/30'
                    : 'bg-green-950/20 border-green-800/30'
                }`}
              >
                <div className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                  step.success ? 'bg-red-900/60 text-red-400' : 'bg-green-900/60 text-green-400'
                }`}>
                  {i + 1}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className="text-xs text-gray-200 font-medium">
                      {step.technique_id && (
                        <span className="font-mono text-gray-500 mr-1">{step.technique_id}</span>
                      )}
                      {step.name || step.phase}
                    </p>
                    <span className={`text-xs px-1.5 py-0.5 rounded font-mono ${
                      step.success ? 'bg-red-900/40 text-red-400' : 'bg-green-900/40 text-green-400'
                    }`}>
                      {step.success ? 'COMPROMETIDO' : 'BLOQUEADO'}
                    </span>
                  </div>
                  {step.detail && (
                    <p className="text-xs text-gray-500 mt-1">{step.detail}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Conclusion */}
        {result.conclusion && (
          <div className={`p-3 rounded-lg border ${
            successCount > totalCount / 2
              ? 'bg-red-950/30 border-red-700/40'
              : 'bg-green-950/20 border-green-700/30'
          }`}>
            <p className="text-xs font-medium mb-1 text-gray-400">Conclusão</p>
            <p className="text-sm text-gray-200">{result.conclusion}</p>
          </div>
        )}

        {simId && (
          <button
            onClick={() => navigate(`/attack-path/${simId}`)}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg
                       bg-cyan-900/30 border border-cyan-700/40 text-cyan-400 text-sm
                       hover:bg-cyan-900/50 transition font-medium"
          >
            <GitBranch className="w-4 h-4" />
            Ver Attack Path Completo
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Attack Path Card
// ---------------------------------------------------------------------------

function AttackPathCard({ path }) {
  const [expanded, setExpanded] = useState(false)
  const [simulatePath, setSimulatePath] = useState(false)
  const [pathResult, setPathResult] = useState(null)

  const diff = DIFF_CONFIG[path.difficulty?.toLowerCase()] || DIFF_CONFIG.medium

  return (
    <div className="rounded-xl border border-dark-600 bg-dark-800 overflow-hidden
                    transition-all duration-200 hover:shadow-lg hover:shadow-black/30">
      {/* Header */}
      <div
        className="p-5 cursor-pointer select-none"
        onClick={() => setExpanded(e => !e)}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0">
            <div className="flex-shrink-0 w-10 h-10 rounded-xl bg-red-900/30 border border-red-700/40
                            flex items-center justify-center">
              <GitBranch className="w-5 h-5 text-red-400" />
            </div>
            <div className="min-w-0">
              <p className="text-gray-100 font-bold text-base leading-tight">{path.name}</p>
              {path.description && (
                <p className="text-gray-500 text-xs mt-1 line-clamp-2">{path.description}</p>
              )}
            </div>
          </div>
          <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
            <span className={`text-xs px-2.5 py-1 rounded-full font-bold ${diff.badge}`}>
              {diff.label || path.difficulty}
            </span>
            {expanded
              ? <ChevronUp className="w-4 h-4 text-gray-500" />
              : <ChevronDown className="w-4 h-4 text-gray-500" />
            }
          </div>
        </div>

        {/* Meta row */}
        <div className="flex items-center gap-4 mt-3 text-xs text-gray-500 flex-wrap">
          {(path.step_count ?? path.steps?.length) != null && (
            <span className="flex items-center gap-1">
              <Target className="w-3.5 h-3.5" />
              {path.step_count ?? path.steps?.length} técnicas
            </span>
          )}
          {path.estimated_time && (
            <span className="flex items-center gap-1">
              <Clock className="w-3.5 h-3.5" />
              {path.estimated_time}
            </span>
          )}
          {path.success_probability != null && (
            <span className="flex items-center gap-1 text-orange-400">
              <AlertTriangle className="w-3.5 h-3.5" />
              {Math.round(path.success_probability * 100)}% prob. de sucesso
            </span>
          )}
        </div>
      </div>

      {/* Expanded */}
      {expanded && (
        <div className="border-t border-dark-600 px-5 py-4 space-y-4">
          {/* Visual path diagram */}
          {(path.steps || path.technique_ids) && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                Diagrama do Caminho
              </p>
              <div className="bg-dark-900/60 rounded-xl p-3 border border-dark-600 overflow-x-auto">
                <PathDiagram steps={path.steps || path.technique_ids} />
              </div>
            </div>
          )}

          {/* Required privileges */}
          {path.required_privileges?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">
                Privilégios Iniciais Necessários
              </p>
              <div className="flex flex-wrap gap-1.5">
                {path.required_privileges.map((p, i) => (
                  <span key={i} className="text-xs px-2 py-0.5 rounded bg-orange-900/30 text-orange-400 border border-orange-800/40">
                    {p}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Objectives */}
          {path.objectives?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">
                Objetivos do Caminho
              </p>
              <ul className="space-y-1">
                {path.objectives.map((o, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-gray-400">
                    <Target className="w-3 h-3 text-red-500 flex-shrink-0 mt-0.5" />
                    {o}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Simulate button */}
          <button
            onClick={() => setSimulatePath(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-700 hover:bg-red-600
                       text-white text-sm font-semibold transition w-full justify-center"
          >
            <Play className="w-4 h-4" />
            Simular Caminho Completo
          </button>

          {/* Path result inline */}
          {pathResult && (
            <PathResultPanel
              result={pathResult}
              onClose={() => setPathResult(null)}
            />
          )}
        </div>
      )}

      {/* Simulate modal */}
      {simulatePath && (
        <PathSimulateModal
          path={path}
          onClose={() => setSimulatePath(false)}
          onResult={r => {
            setPathResult(r)
            setExpanded(true)
          }}
        />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Tab 3 — Attack Graph (React Flow)
// ---------------------------------------------------------------------------

function AttackGraphTab() {
  const [graph, setGraph] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [dcHost, setDcHost] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [domain, setDomain] = useState('')
  const [showCreds, setShowCreds] = useState(false)

  const loadGraph = useCallback((opts = {}) => {
    setLoading(true)
    setError(null)
    const params = new URLSearchParams()
    if (opts.dc_host) params.set('dc_host', opts.dc_host)
    if (opts.username) params.set('username', opts.username)
    if (opts.password) params.set('password', opts.password)
    if (opts.domain) params.set('domain', opts.domain)
    const qs = params.toString() ? '?' + params.toString() : ''
    api.get('/api/ad/attack-graph' + qs)
      .then(res => setGraph(res.data))
      .catch(err => setError(err.response?.data?.detail || 'Erro ao carregar grafo'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { loadGraph() }, [loadGraph])

  if (loading) return (
    <div className="flex items-center justify-center h-96">
      <Loader className="w-8 h-8 text-red-400 animate-spin" />
    </div>
  )

  if (error) return (
    <div className="card-dark p-8 text-center">
      <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
      <p className="text-red-400">{error}</p>
    </div>
  )

  const isDemo = graph?.data_source === 'demo'
  const summary = graph?.summary || {}

  return (
    <div className="space-y-4">
      {/* Demo notice + credentials */}
      <div className="rounded-xl border border-dark-500 bg-dark-800 p-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            {isDemo
              ? <Info className="w-4 h-4 text-blue-400 flex-shrink-0" />
              : <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
            }
            <span className="text-sm text-gray-300">
              {isDemo
                ? 'Grafo demonstrativo — configure credenciais AD para dados reais via LDAP'
                : 'Grafo com dados reais do LDAP'}
            </span>
          </div>
          <button
            onClick={() => setShowCreds(v => !v)}
            className="text-xs px-3 py-1.5 rounded-lg bg-dark-700 border border-dark-500 text-gray-400 hover:text-gray-200 flex items-center gap-1.5"
          >
            <Key className="w-3.5 h-3.5" />
            {showCreds ? 'Ocultar credenciais' : 'Configurar AD'}
          </button>
        </div>

        {showCreds && (
          <div className="mt-4 grid grid-cols-2 gap-3">
            <input
              className="col-span-2 bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600"
              placeholder="DC hostname ou IP (ex: dc01.corp.local)"
              value={dcHost} onChange={e => setDcHost(e.target.value)}
            />
            <input
              className="bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600"
              placeholder="Usuário (ex: corp\admin)"
              value={username} onChange={e => setUsername(e.target.value)}
            />
            <input
              type="password"
              className="bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600"
              placeholder="Senha"
              value={password} onChange={e => setPassword(e.target.value)}
            />
            <input
              className="bg-dark-700 border border-dark-500 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600"
              placeholder="Domínio (ex: corp.local)"
              value={domain} onChange={e => setDomain(e.target.value)}
            />
            <button
              onClick={() => loadGraph({ dc_host: dcHost, username, password, domain })}
              className="px-4 py-2 rounded-lg bg-red-700 hover:bg-red-600 text-white text-sm font-semibold flex items-center gap-2"
            >
              <Play className="w-4 h-4" /> Enumerar via LDAP
            </button>
          </div>
        )}
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Risk Score', value: summary.risk_score + '/100', color: summary.risk_score >= 70 ? 'text-red-400' : summary.risk_score >= 40 ? 'text-orange-400' : 'text-green-400' },
          { label: 'Kerberoastable', value: summary.kerberoastable_accounts, color: 'text-red-400' },
          { label: 'AS-REP Roastable', value: summary.asrep_roastable, color: 'text-orange-400' },
          { label: 'Delegation Irrestrita', value: summary.unconstrained_delegation_hosts, color: 'text-yellow-400' },
        ].map(card => (
          <div key={card.label} className="card-dark p-3 text-center">
            <div className={'text-2xl font-bold ' + card.color}>{card.value}</div>
            <div className="text-xs text-gray-500 mt-1">{card.label}</div>
          </div>
        ))}
      </div>

      {/* Critical findings */}
      {summary.critical_findings?.length > 0 && (
        <div className="rounded-xl border border-red-800/50 bg-red-950/20 p-4">
          <p className="text-xs font-bold text-red-400 mb-2 uppercase tracking-wide">Achados Críticos</p>
          <ul className="space-y-1">
            {summary.critical_findings.map((f, i) => (
              <li key={i} className="flex items-center gap-2 text-sm text-red-300">
                <XCircle className="w-4 h-4 text-red-500 flex-shrink-0" /> {f}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* React Flow graph */}
      <div className="rounded-xl border border-dark-500 overflow-hidden" style={{ height: 480 }}>
        <ReactFlow
          nodes={graph?.nodes || []}
          edges={graph?.edges || []}
          fitView
          nodesDraggable={true}
          nodesConnectable={false}
          elementsSelectable={true}
          colorMode="dark"
        >
          <Background color="#374151" gap={20} />
          <Controls />
        </ReactFlow>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Tab 2 — Attack Paths
// ---------------------------------------------------------------------------

function AttackPathsTab() {
  const [paths, setPaths] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filterDiff, setFilterDiff] = useState('All')

  useEffect(() => {
    api.get('/api/ad-attacks/paths')
      .then(res => setPaths(res.data?.paths || res.data || []))
      .catch(err => setError(err.response?.data?.detail || 'Erro ao carregar caminhos'))
      .finally(() => setLoading(false))
  }, [])

  const filtered = filterDiff === 'All'
    ? paths
    : paths.filter(p => p.difficulty?.toLowerCase() === filterDiff.toLowerCase())

  if (loading) return (
    <div className="space-y-4">
      {Array.from({ length: 3 }).map((_, i) => <SkeletonCard key={i} />)}
    </div>
  )

  if (error) return (
    <div className="card-dark p-8 text-center">
      <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
      <p className="text-red-400">{error}</p>
    </div>
  )

  return (
    <div className="space-y-5">
      {/* Filter */}
      <div className="flex items-center gap-3">
        {['All', 'low', 'medium', 'high'].map(d => (
          <button
            key={d}
            onClick={() => setFilterDiff(d)}
            className={`text-xs px-3 py-1.5 rounded-lg font-semibold transition ${
              filterDiff === d
                ? 'bg-red-700 text-white'
                : 'bg-dark-700 text-gray-400 hover:text-gray-200 border border-dark-500'
            }`}
          >
            {d === 'All' ? 'Todos' : DIFF_CONFIG[d]?.label || d}
          </button>
        ))}
        <span className="text-xs text-gray-500 ml-auto">{filtered.length} caminhos</span>
      </div>

      {filtered.length === 0 ? (
        <div className="text-center py-16">
          <GitBranch className="w-12 h-12 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-500">Nenhum caminho encontrado</p>
        </div>
      ) : (
        <div className="space-y-4">
          {filtered.map(p => (
            <AttackPathCard key={p.id} path={p} />
          ))}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Risk Summary Widget
// ---------------------------------------------------------------------------

function RiskSummaryWidget({ techniques }) {
  const critCount = techniques.filter(t => t.severity === 'Critical').length
  const highCount = techniques.filter(t => t.severity === 'High').length
  const uncontrolled = techniques.filter(t =>
    (t.severity === 'Critical' || t.severity === 'High') &&
    (!t.mitigations?.length && !t.detection_hints?.length)
  ).length

  return (
    <div className="rounded-xl border border-red-800/40 bg-gradient-to-r from-red-950/40 to-dark-800 p-4">
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-sm font-bold text-red-300">
            {uncontrolled > 0
              ? `${uncontrolled} técnica${uncontrolled > 1 ? 's' : ''} crítica${uncontrolled > 1 ? 's' : ''} de AD sem controles detectados`
              : 'Nenhuma técnica crítica sem controles identificada'
            }
          </p>
        </div>
        <div className="flex items-center gap-3 ml-auto">
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-red-500" />
            <span className="text-xs text-gray-400">{critCount} Críticas</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-orange-500" />
            <span className="text-xs text-gray-400">{highCount} Altas</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-green-500" />
            <span className="text-xs text-gray-400">
              {techniques.length - critCount - highCount} Outras
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

export default function ADAttacks() {
  const [activeTab, setActiveTab] = useState('techniques')
  const [techniquesCache, setTechniquesCache] = useState([])

  // Pre-load techniques for the risk widget (shared state)
  useEffect(() => {
    api.get('/api/ad-attacks/techniques')
      .then(res => setTechniquesCache(res.data?.techniques || res.data || []))
      .catch(() => {})
  }, [])

  const TABS = [
    { id: 'techniques', label: 'Técnicas AD', icon: Shield },
    { id: 'paths', label: 'Caminhos até Domain Admin', icon: GitBranch },
    { id: 'graph', label: 'Grafo de Ataque', icon: Target },
  ]

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-10 h-10 rounded-xl bg-red-900/40 border border-red-700/50 flex items-center justify-center">
              <Users className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-100">Active Directory Attacks</h1>
              <p className="text-gray-400 text-sm">Análise de superfície de ataque e simulação de comprometimento de AD</p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs px-3 py-1.5 rounded-full bg-red-900/30 text-red-400 border border-red-700/40 font-semibold">
            BloodHound-style Analysis
          </span>
          <span className="text-xs px-3 py-1.5 rounded-full bg-purple-900/30 text-purple-400 border border-purple-700/40 font-semibold">
            MITRE ATT&amp;CK
          </span>
        </div>
      </div>

      {/* Risk summary */}
      <RiskSummaryWidget techniques={techniquesCache} />

      {/* Tabs */}
      <div className="flex border-b border-dark-600 gap-1">
        {TABS.map(tab => {
          const Icon = tab.icon
          const active = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-5 py-3 text-sm font-semibold border-b-2 transition -mb-px
                ${active
                  ? 'border-red-500 text-red-400'
                  : 'border-transparent text-gray-500 hover:text-gray-300'
                }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'techniques' && <ADTechniquesTab />}
        {activeTab === 'paths' && <AttackPathsTab />}
        {activeTab === 'graph' && <AttackGraphTab />}
      </div>
    </div>
  )
}
