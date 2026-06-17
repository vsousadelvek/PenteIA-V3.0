import React, { useState, useEffect, useCallback } from 'react'
import {
  Zap, RefreshCw, Plus, Trash2, Play, ChevronDown, ChevronUp,
  AlertTriangle, Shield, Clock, ExternalLink, Search, Filter,
  Brain, CheckCircle, XCircle, Loader,
} from 'lucide-react'
import api from '../api'
import { useToast } from '../components/Toast'

const SEVERITY_COLORS = {
  critical: 'text-red-400 bg-red-900/30 border-red-700',
  high:     'text-orange-400 bg-orange-900/30 border-orange-700',
  medium:   'text-yellow-400 bg-yellow-900/30 border-yellow-700',
  low:      'text-blue-400 bg-blue-900/30 border-blue-700',
}

const TACTIC_COLORS = {
  INITIAL_ACCESS:       'bg-purple-900/40 text-purple-300',
  EXECUTION:            'bg-red-900/40 text-red-300',
  PERSISTENCE:          'bg-orange-900/40 text-orange-300',
  PRIVILEGE_ESCALATION: 'bg-yellow-900/40 text-yellow-300',
  DEFENSE_EVASION:      'bg-green-900/40 text-green-300',
  CREDENTIAL_ACCESS:    'bg-pink-900/40 text-pink-300',
  LATERAL_MOVEMENT:     'bg-cyan-900/40 text-cyan-300',
  COLLECTION:           'bg-indigo-900/40 text-indigo-300',
  EXFILTRATION:         'bg-teal-900/40 text-teal-300',
  IMPACT:               'bg-red-900/60 text-red-200',
  COMMAND_AND_CONTROL:  'bg-gray-700 text-gray-300',
}

function SeverityBadge({ severity }) {
  return (
    <span className={`px-2 py-0.5 rounded border text-xs font-bold uppercase ${SEVERITY_COLORS[severity] || 'text-gray-400 bg-gray-800 border-gray-700'}`}>
      {severity}
    </span>
  )
}

function TacticBadge({ tactic }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono ${TACTIC_COLORS[tactic] || 'bg-gray-700 text-gray-300'}`}>
      {tactic?.replace(/_/g, ' ')}
    </span>
  )
}

function ScenarioCard({ scenario, onDelete, onRun }) {
  const [expanded, setExpanded] = useState(false)
  const [runTarget, setRunTarget] = useState('')
  const [running, setRunning] = useState(false)
  const toast = useToast()

  const handleRun = async () => {
    if (!runTarget.trim()) { toast('Informe o target', 'error'); return }
    setRunning(true)
    try {
      const r = await api.post(`/api/ai-scenarios/${scenario.id}/run`, { target: runTarget })
      toast(`Simulação criada — Score: ${r.data.score}%`, 'success')
      onRun?.(r.data)
    } catch {
      toast('Erro ao executar simulação', 'error')
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="bg-dark-700 border border-gray-700 rounded-lg overflow-hidden">
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              {scenario.cve_id && (
                <span className="text-xs font-mono text-blue-400 bg-blue-900/20 px-2 py-0.5 rounded border border-blue-800">
                  {scenario.cve_id}
                </span>
              )}
              <SeverityBadge severity={scenario.severity} />
              <TacticBadge tactic={scenario.tactic} />
              {scenario.source === 'ai_generated' && (
                <span className="text-xs text-purple-400 bg-purple-900/20 px-2 py-0.5 rounded border border-purple-800 flex items-center gap-1">
                  <Brain size={10} /> AI
                </span>
              )}
            </div>
            <h3 className="text-gray-100 font-semibold text-sm leading-tight">
              {scenario.attack_name || scenario.technique_name}
            </h3>
            <p className="text-gray-400 text-xs mt-1 line-clamp-2">{scenario.description}</p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-xs font-mono text-gray-500">{scenario.technique_id}</span>
            <button
              onClick={() => setExpanded(e => !e)}
              className="p-1.5 hover:bg-gray-700 rounded text-gray-400 hover:text-gray-200"
            >
              {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>
          </div>
        </div>

        {/* Affected systems */}
        {scenario.affected_systems?.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {scenario.affected_systems.map((sys, i) => (
              <span key={i} className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded">
                {sys}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="border-t border-gray-700 p-4 space-y-4">
          {/* Kill chain */}
          {scenario.kill_chain?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Kill Chain</p>
              <div className="space-y-1">
                {scenario.kill_chain.map((step) => (
                  <div key={step.step} className="flex gap-2 text-xs">
                    <span className="text-red-400 font-mono shrink-0 w-5">{step.step}.</span>
                    <span className="text-gray-300">{step.action}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Detection hints */}
          {scenario.detection_hints?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Detecção</p>
              <div className="space-y-1">
                {scenario.detection_hints.map((hint, i) => (
                  <div key={i} className="flex gap-2 text-xs text-green-300">
                    <Shield size={12} className="shrink-0 mt-0.5" />
                    <span>{hint}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation */}
          {scenario.remediation?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Remediação</p>
              <div className="space-y-1">
                {scenario.remediation.map((rem, i) => (
                  <div key={i} className="flex gap-2 text-xs text-blue-300">
                    <CheckCircle size={12} className="shrink-0 mt-0.5" />
                    <span>{rem}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Run as simulation */}
          <div className="flex gap-2 pt-2 border-t border-gray-700">
            <input
              value={runTarget}
              onChange={e => setRunTarget(e.target.value)}
              placeholder="Target (ex: 192.168.1.0/24)"
              className="flex-1 bg-dark-800 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
            <button
              onClick={handleRun}
              disabled={running}
              className="px-3 py-1.5 bg-red-600 hover:bg-red-700 rounded text-white text-sm font-medium flex items-center gap-1.5 disabled:opacity-50"
            >
              {running ? <Loader size={14} className="animate-spin" /> : <Play size={14} />}
              Simular
            </button>
            <button
              onClick={() => onDelete(scenario.id)}
              className="p-1.5 text-gray-500 hover:text-red-400 hover:bg-red-900/20 rounded"
            >
              <Trash2 size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function KEVEntry({ entry, onGenerate, generating }) {
  return (
    <div className={`bg-dark-700 border rounded p-3 flex items-start gap-3 ${entry.already_generated ? 'border-green-800 opacity-60' : 'border-gray-700'}`}>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-xs font-mono text-blue-400">{entry.cveID}</span>
          {entry.knownRansomwareCampaignUse === 'Known' && (
            <span className="text-xs text-red-400 bg-red-900/20 px-1.5 rounded border border-red-800">Ransomware</span>
          )}
          {entry.already_generated && (
            <span className="text-xs text-green-400 flex items-center gap-1"><CheckCircle size={10} /> Gerado</span>
          )}
        </div>
        <p className="text-xs text-gray-300 font-medium">{entry.vendorProject} — {entry.product}</p>
        <p className="text-xs text-gray-500 mt-0.5 line-clamp-2">{entry.shortDescription}</p>
        <p className="text-xs text-gray-600 mt-0.5">Adicionado: {entry.dateAdded}</p>
      </div>
      <button
        onClick={() => onGenerate(entry)}
        disabled={entry.already_generated || generating === entry.cveID}
        className="shrink-0 px-2 py-1 bg-purple-700 hover:bg-purple-600 rounded text-xs text-white font-medium flex items-center gap-1 disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {generating === entry.cveID ? <Loader size={12} className="animate-spin" /> : <Brain size={12} />}
        Gerar
      </button>
    </div>
  )
}

export default function AIScenarios() {
  const toast = useToast()
  const [tab, setTab] = useState('scenarios')
  const [scenarios, setScenarios] = useState([])
  const [kevFeed, setKevFeed] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(false)
  const [sweeping, setSweeping] = useState(false)
  const [generating, setGenerating] = useState(null)
  const [search, setSearch] = useState('')
  const [filterSev, setFilterSev] = useState('')
  const [manualForm, setManualForm] = useState({ cve_id: '', product: '', description: '', cvss: '7.0', ransomware: false })
  const [manualLoading, setManualLoading] = useState(false)

  const loadScenarios = useCallback(async () => {
    setLoading(true)
    try {
      const [scRes, stRes] = await Promise.all([
        api.get('/api/ai-scenarios'),
        api.get('/api/ai-scenarios/stats'),
      ])
      setScenarios(scRes.data.scenarios || [])
      setStats(stRes.data)
    } catch { /* ignore */ }
    finally { setLoading(false) }
  }, [])

  const loadKev = useCallback(async () => {
    try {
      const r = await api.get('/api/ai-scenarios/kev-feed?limit=30')
      setKevFeed(r.data.vulnerabilities || [])
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { loadScenarios() }, [loadScenarios])
  useEffect(() => { if (tab === 'kev') loadKev() }, [tab, loadKev])

  const handleSweep = async () => {
    setSweeping(true)
    try {
      const r = await api.post('/api/ai-scenarios/kev-sweep?max_new=5')
      toast(`${r.data.processed} novos cenários gerados do KEV`, 'success')
      loadScenarios()
      if (tab === 'kev') loadKev()
    } catch {
      toast('Erro no KEV sweep', 'error')
    } finally { setSweeping(false) }
  }

  const handleGenerateFromKEV = async (entry) => {
    setGenerating(entry.cveID)
    try {
      await api.post('/api/ai-scenarios/generate', {
        cve_id: entry.cveID,
        product: `${entry.vendorProject} ${entry.product}`,
        description: entry.shortDescription,
        cvss: 8.0,
        ransomware: entry.knownRansomwareCampaignUse === 'Known',
      })
      toast(`Cenário gerado para ${entry.cveID}`, 'success')
      loadScenarios()
      loadKev()
    } catch {
      toast('Erro ao gerar cenário', 'error')
    } finally { setGenerating(null) }
  }

  const handleManualGenerate = async () => {
    if (!manualForm.cve_id || !manualForm.product || !manualForm.description) {
      toast('Preencha CVE ID, produto e descrição', 'error')
      return
    }
    setManualLoading(true)
    try {
      await api.post('/api/ai-scenarios/generate', {
        cve_id: manualForm.cve_id,
        product: manualForm.product,
        description: manualForm.description,
        cvss: parseFloat(manualForm.cvss) || 7.0,
        ransomware: manualForm.ransomware,
      })
      toast(`Cenário gerado para ${manualForm.cve_id}`, 'success')
      setManualForm({ cve_id: '', product: '', description: '', cvss: '7.0', ransomware: false })
      loadScenarios()
      setTab('scenarios')
    } catch {
      toast('Erro ao gerar cenário', 'error')
    } finally { setManualLoading(false) }
  }

  const handleDelete = async (id) => {
    try {
      await api.delete(`/api/ai-scenarios/${id}`)
      setScenarios(prev => prev.filter(s => s.id !== id))
      toast('Cenário removido', 'success')
    } catch {
      toast('Erro ao remover', 'error')
    }
  }

  const filtered = scenarios.filter(s => {
    const q = search.toLowerCase()
    const matchSearch = !q || s.attack_name?.toLowerCase().includes(q) || s.cve_id?.toLowerCase().includes(q) || s.technique_id?.toLowerCase().includes(q)
    const matchSev = !filterSev || s.severity === filterSev
    return matchSearch && matchSev
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <Brain className="text-purple-400" size={24} />
            AI Scenario Generation
          </h1>
          <p className="text-gray-400 text-sm mt-0.5">
            Cenários BAS gerados automaticamente via CISA KEV + Claude AI
          </p>
        </div>
        <button
          onClick={handleSweep}
          disabled={sweeping}
          className="px-4 py-2 bg-purple-700 hover:bg-purple-600 rounded-lg text-white font-medium flex items-center gap-2 disabled:opacity-50"
        >
          {sweeping ? <Loader size={16} className="animate-spin" /> : <Zap size={16} />}
          KEV Sweep
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Total Gerados', value: stats.total_generated, color: 'text-purple-400' },
            { label: 'KEVs Processados', value: stats.kev_ids_processed, color: 'text-blue-400' },
            { label: 'Críticos', value: stats.by_severity?.critical || 0, color: 'text-red-400' },
            { label: 'Altos', value: stats.by_severity?.high || 0, color: 'text-orange-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-dark-700 border border-gray-700 rounded-lg p-4">
              <p className="text-gray-400 text-xs mb-1">{label}</p>
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 bg-dark-800 rounded-lg p-1 w-fit">
        {[
          { id: 'scenarios', label: 'Cenários Gerados' },
          { id: 'kev', label: 'CISA KEV Feed' },
          { id: 'manual', label: 'Gerar Manual' },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 rounded text-sm font-medium transition-colors ${tab === t.id ? 'bg-purple-700 text-white' : 'text-gray-400 hover:text-gray-200'}`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab: Scenarios */}
      {tab === 'scenarios' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Buscar por CVE, nome, técnica..."
                className="w-full bg-dark-700 border border-gray-700 rounded-lg pl-9 pr-4 py-2 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-purple-500"
              />
            </div>
            <select
              value={filterSev}
              onChange={e => setFilterSev(e.target.value)}
              className="bg-dark-700 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-purple-500"
            >
              <option value="">Todas severidades</option>
              <option value="critical">Crítico</option>
              <option value="high">Alto</option>
              <option value="medium">Médio</option>
              <option value="low">Baixo</option>
            </select>
            <button onClick={loadScenarios} className="p-2 bg-dark-700 border border-gray-700 rounded-lg text-gray-400 hover:text-gray-200">
              <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>

          {loading && <div className="text-center py-8 text-gray-500">Carregando...</div>}

          {!loading && filtered.length === 0 && (
            <div className="text-center py-16 text-gray-500">
              <Brain size={40} className="mx-auto mb-3 opacity-30" />
              <p className="font-medium">Nenhum cenário gerado ainda</p>
              <p className="text-sm mt-1">Clique em "KEV Sweep" para gerar automaticamente</p>
            </div>
          )}

          <div className="space-y-3">
            {filtered.map(s => (
              <ScenarioCard key={s.id} scenario={s} onDelete={handleDelete} onRun={loadScenarios} />
            ))}
          </div>
        </div>
      )}

      {/* Tab: KEV Feed */}
      {tab === 'kev' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-400">Últimas vulnerabilidades conhecidas exploradas (CISA KEV)</p>
            <button onClick={loadKev} className="p-2 bg-dark-700 border border-gray-700 rounded-lg text-gray-400 hover:text-gray-200">
              <RefreshCw size={16} />
            </button>
          </div>
          {kevFeed.length === 0 && (
            <div className="text-center py-8 text-gray-500">Carregando feed CISA...</div>
          )}
          {kevFeed.map(entry => (
            <KEVEntry
              key={entry.cveID}
              entry={entry}
              onGenerate={handleGenerateFromKEV}
              generating={generating}
            />
          ))}
        </div>
      )}

      {/* Tab: Manual */}
      {tab === 'manual' && (
        <div className="bg-dark-700 border border-gray-700 rounded-lg p-6 max-w-2xl space-y-4">
          <h2 className="text-gray-100 font-semibold flex items-center gap-2">
            <Brain size={16} className="text-purple-400" />
            Gerar Cenário de CVE Específico
          </h2>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-gray-400 mb-1 block">CVE ID *</label>
              <input
                value={manualForm.cve_id}
                onChange={e => setManualForm(f => ({ ...f, cve_id: e.target.value }))}
                placeholder="CVE-2024-XXXXX"
                className="w-full bg-dark-800 border border-gray-600 rounded px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-purple-500 font-mono"
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">CVSS Score</label>
              <input
                type="number"
                min="0" max="10" step="0.1"
                value={manualForm.cvss}
                onChange={e => setManualForm(f => ({ ...f, cvss: e.target.value }))}
                className="w-full bg-dark-800 border border-gray-600 rounded px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-purple-500"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Produto / Vendor *</label>
            <input
              value={manualForm.product}
              onChange={e => setManualForm(f => ({ ...f, product: e.target.value }))}
              placeholder="ex: Fortinet FortiGate"
              className="w-full bg-dark-800 border border-gray-600 rounded px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-purple-500"
            />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Descrição da vulnerabilidade *</label>
            <textarea
              value={manualForm.description}
              onChange={e => setManualForm(f => ({ ...f, description: e.target.value }))}
              rows={4}
              placeholder="Descreva a vulnerabilidade..."
              className="w-full bg-dark-800 border border-gray-600 rounded px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-purple-500 resize-none"
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={manualForm.ransomware}
              onChange={e => setManualForm(f => ({ ...f, ransomware: e.target.checked }))}
              className="accent-red-500"
            />
            Associado a campanhas de ransomware
          </label>
          <button
            onClick={handleManualGenerate}
            disabled={manualLoading}
            className="w-full py-2.5 bg-purple-700 hover:bg-purple-600 rounded-lg text-white font-medium flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {manualLoading ? <Loader size={16} className="animate-spin" /> : <Brain size={16} />}
            {manualLoading ? 'Gerando com IA...' : 'Gerar Cenário com Claude AI'}
          </button>
        </div>
      )}
    </div>
  )
}
