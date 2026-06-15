import React, { useState, useEffect } from 'react'
import { Shield, Target, AlertTriangle, CheckCircle, XCircle, BarChart3, RefreshCw, X, ChevronRight } from 'lucide-react'
import api from '../api'

const STATUS_STYLE = {
  found:      'bg-red-900/60 border-red-700 text-red-300 hover:bg-red-800/60',
  blocked:    'bg-green-900/40 border-green-800 text-green-300 hover:bg-green-800/40',
  not_tested: 'bg-dark-700 border-dark-600 text-gray-600 hover:bg-dark-600',
}

const SEV_COLOR = {
  Critical: 'bg-red-900/40 text-red-400 border-red-700',
  High: 'bg-orange-900/40 text-orange-400 border-orange-700',
  Medium: 'bg-yellow-900/40 text-yellow-400 border-yellow-700',
  Low: 'bg-blue-900/40 text-blue-400 border-blue-700',
}

export default function ATTCKMatrix() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all')
  const [selected, setSelected] = useState(null)
  const [simulations, setSimulations] = useState([])
  const [simId, setSimId] = useState('')

  const load = (sid = '') => {
    setLoading(true)
    setError(null)
    const params = sid ? `?simulation_id=${sid}` : ''
    api.get(`/api/bas/attck-matrix${params}`)
      .then(r => setData(r.data))
      .catch(e => setError(e.response?.data?.detail || 'Erro ao carregar matriz'))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    api.get('/api/bas/simulations').then(r => setSimulations(r.data.simulations || [])).catch(() => {})
  }, [])

  const filterTech = (t) => {
    if (filter === 'all') return true
    return t.status === filter
  }

  if (loading) return (
    <div className="flex items-center justify-center h-96">
      <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
    </div>
  )

  if (error) return (
    <div className="card-dark p-8 text-center">
      <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
      <p className="text-red-400">{error}</p>
      <button onClick={() => load()} className="mt-4 btn-blue text-sm">Tentar novamente</button>
    </div>
  )

  const stats = data?.stats || {}
  const tactics = data?.tactics || []

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <Shield className="w-6 h-6 text-red-500" />
            MITRE ATT&amp;CK Matrix
          </h1>
          <p className="text-gray-400 text-sm mt-0.5">Cobertura de técnicas testadas vs. todas as táticas MITRE</p>
        </div>
        <div className="flex gap-2 items-center">
          <select
            className="select-dark text-sm"
            value={simId}
            onChange={e => { setSimId(e.target.value); load(e.target.value) }}
          >
            <option value="">Todas as simulações</option>
            {simulations.filter(s => s.status === 'done').map(s => (
              <option key={s.id} value={s.id}>{s.playbook_name || s.id.slice(0,8)} — {s.target}</option>
            ))}
          </select>
          <button onClick={() => load(simId)} className="p-2 text-gray-400 hover:text-gray-200 hover:bg-dark-700 rounded transition">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Total', value: stats.total, color: 'text-gray-100' },
          { label: 'Testadas', value: stats.tested, color: 'text-blue-400' },
          { label: 'Vulneráveis', value: stats.found, color: 'text-red-400' },
          { label: 'Bloqueadas', value: stats.blocked, color: 'text-green-400' },
          { label: 'Cobertura', value: `${stats.coverage_pct || 0}%`, color: stats.coverage_pct >= 50 ? 'text-green-400' : 'text-yellow-400' },
        ].map(s => (
          <div key={s.label} className="card-dark p-3 text-center">
            <p className="text-gray-500 text-xs mb-1">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Filters + Legend */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex gap-1">
          {[
            { key: 'all', label: 'Todas' },
            { key: 'found', label: 'Vulneráveis' },
            { key: 'blocked', label: 'Bloqueadas' },
            { key: 'not_tested', label: 'Não testadas' },
          ].map(f => (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              className={`px-3 py-1.5 rounded text-xs font-medium transition ${filter === f.key ? 'bg-red-700 text-white' : 'bg-dark-700 text-gray-400 hover:bg-dark-600'}`}
            >
              {f.label}
            </button>
          ))}
        </div>
        <div className="flex gap-3 text-xs text-gray-500 ml-2">
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border border-red-700 bg-red-900/60 inline-block" /> Vulnerável</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border border-green-800 bg-green-900/40 inline-block" /> Bloqueado</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded border border-dark-600 bg-dark-700 inline-block" /> Não testado</span>
        </div>
      </div>

      {/* Matrix */}
      <div className="overflow-x-auto">
        <div className="flex gap-2" style={{ minWidth: `${tactics.length * 160}px` }}>
          {tactics.map(tactic => {
            const visible = tactic.techniques.filter(filterTech)
            return (
              <div key={tactic.id} className="flex-shrink-0" style={{ width: 152 }}>
                {/* Tactic header */}
                <div className="bg-dark-700 border border-dark-600 rounded-t px-2 py-2 text-center mb-1 sticky top-0 z-10">
                  <p className="text-[10px] font-bold text-red-400 uppercase tracking-wide truncate">{tactic.short}</p>
                  <p className="text-[9px] text-gray-500">{tactic.id}</p>
                  <p className="text-[9px] text-gray-500 mt-0.5">
                    {tactic.techniques.filter(t => t.status === 'found').length} vuln / {tactic.techniques.length}
                  </p>
                </div>
                {/* Techniques */}
                <div className="space-y-1">
                  {visible.length === 0 && (
                    <p className="text-[10px] text-gray-600 text-center py-2">Sem resultados</p>
                  )}
                  {visible.map(tech => (
                    <button
                      key={tech.id}
                      onClick={() => setSelected(tech)}
                      className={`w-full text-left p-1.5 rounded border text-[10px] transition cursor-pointer ${STATUS_STYLE[tech.status] || STATUS_STYLE.not_tested}`}
                    >
                      <span className="font-mono font-bold block">{tech.id}</span>
                      <span className="truncate block leading-tight">{tech.name}</span>
                      {tech.cvss > 0 && <span className="text-[9px] opacity-70">CVSS {tech.cvss}</span>}
                    </button>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Detail drawer */}
      {selected && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-end md:items-center justify-center p-4" onClick={() => setSelected(null)}>
          <div className="bg-dark-800 border border-dark-600 rounded-xl shadow-2xl w-full max-w-lg max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between items-start p-5 border-b border-dark-600">
              <div>
                <p className="text-xs text-gray-500 font-mono">{selected.id}</p>
                <h3 className="text-lg font-bold text-gray-100 mt-0.5">{selected.name}</h3>
                <div className="flex gap-2 mt-2">
                  <span className={`text-xs px-2 py-0.5 rounded border font-medium ${
                    selected.status === 'found' ? 'bg-red-900/40 text-red-400 border-red-700' :
                    selected.status === 'blocked' ? 'bg-green-900/40 text-green-400 border-green-800' :
                    'bg-dark-700 text-gray-500 border-dark-600'
                  }`}>
                    {selected.status === 'found' ? 'Vulnerável' : selected.status === 'blocked' ? 'Bloqueado' : 'Não testado'}
                  </span>
                  {selected.cvss > 0 && (
                    <span className="text-xs px-2 py-0.5 rounded border bg-dark-700 text-gray-300 border-dark-500">
                      CVSS {selected.cvss}
                    </span>
                  )}
                </div>
              </div>
              <button onClick={() => setSelected(null)} className="text-gray-500 hover:text-gray-100">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-5 space-y-4 text-sm">
              {selected.description && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Descrição</p>
                  <p className="text-gray-300 leading-relaxed">{selected.description}</p>
                </div>
              )}
              {selected.simulations > 0 && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Simulações</p>
                  <p className="text-gray-300">Técnica testada em <span className="text-blue-400 font-bold">{selected.simulations}</span> simulação(ões)</p>
                </div>
              )}
              {selected.compliance?.length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Compliance</p>
                  <div className="flex flex-wrap gap-1">
                    {selected.compliance.map(c => (
                      <span key={c} className="text-xs px-2 py-0.5 rounded bg-dark-700 text-cyan-400 border border-dark-500">{c}</span>
                    ))}
                  </div>
                </div>
              )}
              {selected.remediation && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Remediação recomendada</p>
                  <p className="text-gray-300 leading-relaxed text-xs">{selected.remediation}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
