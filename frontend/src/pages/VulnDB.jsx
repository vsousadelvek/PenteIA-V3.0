import React, { useState, useEffect, useMemo } from 'react'
import { Database, AlertTriangle, Shield, ChevronDown, ChevronUp, Download, Search, X, RefreshCw, Zap, Info } from 'lucide-react'
import api from '../api'
import { useToast } from '../components/Toast'

const SEV_BADGE = {
  Critical: 'bg-red-900/50 text-red-400 border-red-700',
  High:     'bg-orange-900/50 text-orange-400 border-orange-700',
  Medium:   'bg-yellow-900/50 text-yellow-400 border-yellow-700',
  Low:      'bg-blue-900/50 text-blue-400 border-blue-700',
  '':       'bg-dark-700 text-gray-500 border-dark-600',
}

const PRIORITY_BADGE = {
  CRITICAL: 'bg-red-900/60 text-red-300 border-red-600',
  HIGH:     'bg-orange-900/60 text-orange-300 border-orange-600',
  MEDIUM:   'bg-yellow-900/60 text-yellow-300 border-yellow-600',
  LOW:      'bg-blue-900/60 text-blue-300 border-blue-600',
}

const PAGE_SIZE = 20

function EpssCell({ epss }) {
  if (epss == null) return <span className="text-gray-600">—</span>
  const pct = (epss * 100).toFixed(1)
  const color = epss >= 0.7 ? 'text-red-400' : epss >= 0.4 ? 'text-yellow-400' : 'text-gray-400'
  return <span className={`font-mono font-bold ${color}`}>{pct}%</span>
}

function KevBadge({ kev }) {
  if (!kev) return <span className="text-gray-600 text-xs">—</span>
  return (
    <span className="text-[10px] px-1.5 py-0.5 rounded border bg-red-900/60 text-red-300 border-red-600 font-bold whitespace-nowrap">
      CISA KEV
    </span>
  )
}

function PriorityBadge({ priority }) {
  if (!priority) return <span className="text-gray-600 text-xs">—</span>
  return (
    <span className={`text-xs px-2 py-0.5 rounded border font-bold ${PRIORITY_BADGE[priority] || 'bg-dark-700 text-gray-400 border-dark-600'}`}>
      {priority}
    </span>
  )
}

export default function VulnDB() {
  const toast = useToast()
  const [vulns, setVulns] = useState([])
  const [stats, setStats] = useState({})
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [daysFilter, setDaysFilter] = useState(0)
  const [sortCol, setSortCol] = useState('cvss')
  const [sortDir, setSortDir] = useState('desc')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState(null)

  // EPSS/KEV enrichment state
  const [enrichMap, setEnrichMap] = useState({})   // keyed by technique_id
  const [enrichLoading, setEnrichLoading] = useState(false)
  const [enrichError, setEnrichError] = useState('')
  const [isEnriched, setIsEnriched] = useState(false)
  const [showInfo, setShowInfo] = useState(false)

  const load = () => {
    setLoading(true)
    const params = {}
    if (daysFilter > 0) params.days = daysFilter
    api.get('/api/bas/vulndb', { params })
      .then(r => { setVulns(r.data.vulns || []); setStats(r.data.stats || {}) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [daysFilter])

  // When vulns reload, clear enrichment so stale data doesn't linger
  useEffect(() => {
    setEnrichMap({})
    setIsEnriched(false)
    setEnrichError('')
  }, [vulns])

  const handleEnrich = async () => {
    setEnrichError('')
    // Build CVE payload from current filtered + all vulns that have a CVE-like technique_id
    const candidates = vulns
      .filter(v => v.technique_id && /^CVE-\d{4}-\d+$/i.test(v.technique_id.trim()))
    if (candidates.length === 0) {
      setEnrichError('Nenhum CVE encontrado na base. Os findings precisam ter IDs no formato CVE-YYYY-NNNN.')
      return
    }
    // Deduplicate by CVE id
    const seen = new Set()
    const payload = []
    for (const v of candidates) {
      const id = v.technique_id.trim().toUpperCase()
      if (!seen.has(id)) {
        seen.add(id)
        payload.push({ cve_id: id, cvss: v.cvss || 0, name: v.name || '' })
      }
    }
    setEnrichLoading(true)
    try {
      const r = await api.post('/api/vulns/prioritize', { cves: payload })
      const map = {}
      for (const item of (r.data?.results || r.data || [])) {
        if (!item.cve_id) continue
        map[item.cve_id.toUpperCase()] = {
          ...item,
          epss: item.epss ?? item.epss_score ?? null,
          kev: item.kev ?? item.is_kev ?? false,
          composite_score: item.composite_score ?? item.composite_risk ?? null,
        }
      }
      setEnrichMap(map)
      setIsEnriched(true)
      // Switch sort to composite_score desc when enrichment lands
      setSortCol('_composite')
      setSortDir('desc')
      setPage(1)
    } catch (err) {
      const msg = err?.response?.data?.detail || err?.message || 'Erro ao enriquecer vulnerabilidades.'
      setEnrichError(msg)
    } finally {
      setEnrichLoading(false)
    }
  }

  const getEnrich = (v) => enrichMap[v.technique_id?.trim().toUpperCase()] || null

  const filtered = useMemo(() => {
    let out = vulns
    if (search) out = out.filter(v =>
      v.name?.toLowerCase().includes(search.toLowerCase()) ||
      v.technique_id?.toLowerCase().includes(search.toLowerCase()) ||
      v.target?.toLowerCase().includes(search.toLowerCase())
    )
    if (severityFilter !== 'all') out = out.filter(v => v.severity === severityFilter)
    if (statusFilter !== 'all') out = out.filter(v => v.status === statusFilter)

    out = [...out].sort((a, b) => {
      let av, bv
      if (sortCol === '_composite') {
        const ea = enrichMap[a.technique_id?.trim().toUpperCase()]
        const eb = enrichMap[b.technique_id?.trim().toUpperCase()]
        av = ea?.composite_score ?? -1
        bv = eb?.composite_score ?? -1
      } else {
        av = a[sortCol]
        bv = b[sortCol]
        if (typeof av === 'string') av = av.toLowerCase()
        if (typeof bv === 'string') bv = bv.toLowerCase()
      }
      return sortDir === 'asc' ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1)
    })
    return out
  }, [vulns, search, severityFilter, statusFilter, sortCol, sortDir, enrichMap])

  const pages = Math.ceil(filtered.length / PAGE_SIZE)
  const pageVulns = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const sort = (col) => {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortCol(col); setSortDir('desc') }
    setPage(1)
  }

  const SortIcon = ({ col }) => sortCol !== col ? null :
    sortDir === 'asc' ? <ChevronUp className="w-3 h-3 inline" /> : <ChevronDown className="w-3 h-3 inline" />

  const exportCSV = () => {
    api.get('/api/bas/vulndb/export', { responseType: 'blob' }).then(r => {
      const url = window.URL.createObjectURL(new Blob([r.data]))
      const a = document.createElement('a'); a.href = url; a.download = 'penteia_vulndb.csv'; a.click()
    }).catch(() => toast('Falha ao exportar CSV', 'error'))
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <Database className="w-6 h-6 text-red-500" />
            Base de Vulnerabilidades
          </h1>
          <p className="text-gray-400 text-sm mt-0.5">Consolidado de todos os findings de todas as simulações BAS</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={handleEnrich}
            disabled={enrichLoading || loading}
            className="flex items-center gap-1.5 px-3 py-2 bg-purple-900/40 hover:bg-purple-800/50 text-purple-300 border border-purple-700/50 rounded-lg text-sm transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {enrichLoading
              ? <span className="w-4 h-4 border-2 border-purple-400 border-t-transparent rounded-full animate-spin" />
              : <Zap className="w-4 h-4" />
            }
            Enriquecer com EPSS/KEV
          </button>
          <button onClick={exportCSV} className="flex items-center gap-1.5 px-3 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded-lg text-sm transition">
            <Download className="w-4 h-4" /> Exportar CSV
          </button>
          <button onClick={load} className="p-2 text-gray-400 hover:text-gray-200 hover:bg-dark-700 rounded transition">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* EPSS/KEV Info Box */}
      <div className="border border-purple-800/50 bg-purple-950/20 rounded-lg px-4 py-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-2 flex-1">
            <Info className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
            <div className="text-sm text-gray-400 space-y-0.5">
              <p>
                <span className="text-purple-300 font-medium">EPSS</span>
                {' '}— Exploit Prediction Scoring System: probabilidade de exploração de um CVE nos próximos 30 dias (
                <span className="text-gray-300">FIRST.org</span>).
                Valores altos indicam risco iminente de exploração real.
              </p>
              <p>
                <span className="text-red-300 font-medium">CISA KEV</span>
                {' '}— Known Exploited Vulnerabilities: lista oficial de vulnerabilidades com exploração ativa confirmada.
                Presença no KEV exige remediação prioritária.
              </p>
              {!isEnriched && (
                <p className="text-gray-500 text-xs mt-1">
                  Clique em "Enriquecer com EPSS/KEV" para adicionar colunas de priorização a CVEs na tabela.
                </p>
              )}
            </div>
          </div>
          {isEnriched && (
            <span className="text-xs px-2 py-1 rounded bg-purple-900/50 text-purple-300 border border-purple-700 whitespace-nowrap flex-shrink-0">
              Enriquecido
            </span>
          )}
        </div>
      </div>

      {/* Enrichment error */}
      {enrichError && (
        <div className="flex items-center gap-2 px-4 py-3 bg-red-950/40 border border-red-700/50 rounded-lg text-red-300 text-sm">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {enrichError}
          <button onClick={() => setEnrichError('')} className="ml-auto text-red-500 hover:text-red-300">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
        {[
          { label: 'Total', value: stats.total || 0, color: 'text-gray-100' },
          { label: 'Critical', value: stats.critical || 0, color: 'text-red-400' },
          { label: 'High', value: stats.high || 0, color: 'text-orange-400' },
          { label: 'Medium', value: stats.medium || 0, color: 'text-yellow-400' },
          { label: 'Low', value: stats.low || 0, color: 'text-blue-400' },
          { label: 'Técnicas únicas', value: stats.unique_techniques || 0, color: 'text-purple-400' },
        ].map(s => (
          <div key={s.label} className="card-dark p-3 text-center">
            <p className="text-gray-500 text-xs mb-1">{s.label}</p>
            <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-2.5 top-2.5 text-gray-500" />
          <input
            className="input-dark pl-8 text-sm w-48"
            placeholder="Buscar técnica, alvo..."
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1) }}
          />
        </div>
        <select className="select-dark text-sm" value={severityFilter} onChange={e => { setSeverityFilter(e.target.value); setPage(1) }}>
          <option value="all">Severidade: Todas</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select className="select-dark text-sm" value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1) }}>
          <option value="all">Status: Todos</option>
          <option value="found">Vulnerável</option>
          <option value="blocked">Bloqueado</option>
        </select>
        <select className="select-dark text-sm" value={daysFilter} onChange={e => setDaysFilter(Number(e.target.value))}>
          <option value={0}>Todo o período</option>
          <option value={7}>Últimos 7 dias</option>
          <option value={30}>Últimos 30 dias</option>
          <option value={90}>Últimos 90 dias</option>
        </select>
        {(search || severityFilter !== 'all' || statusFilter !== 'all') && (
          <button onClick={() => { setSearch(''); setSeverityFilter('all'); setStatusFilter('all') }}
            className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300">
            <X className="w-3 h-3" /> Limpar filtros
          </button>
        )}
        {isEnriched && (
          <span className="flex items-center gap-1 text-xs text-purple-400 ml-auto">
            <Zap className="w-3 h-3" />
            Ordenado por score composto
          </span>
        )}
      </div>

      {/* Table */}
      {loading ? (
        <div className="flex justify-center py-16">
          <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="card-dark p-12 text-center">
          <Shield className="w-10 h-10 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-500">Nenhuma vulnerabilidade encontrada</p>
          <p className="text-gray-600 text-sm mt-1">Execute uma simulação BAS para popular a base</p>
        </div>
      ) : (
        <div className="card-dark overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-dark-600 text-gray-500 text-xs">
                {[
                  { key: 'technique_id', label: 'ID' },
                  { key: 'name', label: 'Técnica' },
                  { key: 'severity', label: 'Severidade' },
                  { key: 'cvss', label: 'CVSS' },
                  { key: 'target', label: 'Alvo' },
                  { key: 'status', label: 'Status' },
                  { key: 'date', label: 'Data' },
                ].map(col => (
                  <th key={col.key} onClick={() => sort(col.key)}
                    className="px-4 py-3 text-left cursor-pointer hover:text-gray-300 select-none whitespace-nowrap">
                    {col.label} <SortIcon col={col.key} />
                  </th>
                ))}
                <th className="px-4 py-3 text-left">Compliance</th>
                {isEnriched && <>
                  <th
                    onClick={() => sort('_composite')}
                    className="px-4 py-3 text-left cursor-pointer hover:text-gray-300 select-none whitespace-nowrap text-purple-400"
                  >
                    EPSS % <SortIcon col="_composite" />
                  </th>
                  <th className="px-4 py-3 text-left text-purple-400 whitespace-nowrap">KEV</th>
                  <th className="px-4 py-3 text-left text-purple-400 whitespace-nowrap">Prioridade</th>
                </>}
              </tr>
            </thead>
            <tbody>
              {pageVulns.map((v, i) => {
                const enrich = getEnrich(v)
                return (
                  <tr key={v.id}
                    onClick={() => setSelected({ ...v, _enrich: enrich })}
                    className={`border-b border-dark-700/50 cursor-pointer hover:bg-dark-700/50 transition ${i % 2 === 0 ? '' : 'bg-dark-800/30'}`}>
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-400">{v.technique_id}</td>
                    <td className="px-4 py-2.5 text-gray-200 max-w-xs truncate">{v.name}</td>
                    <td className="px-4 py-2.5">
                      <span className={`text-xs px-2 py-0.5 rounded border font-medium ${SEV_BADGE[v.severity] || SEV_BADGE['']}`}>{v.severity || '—'}</span>
                    </td>
                    <td className="px-4 py-2.5 font-mono">
                      <span className={`font-bold ${v.cvss >= 9 ? 'text-red-400' : v.cvss >= 7 ? 'text-orange-400' : v.cvss >= 4 ? 'text-yellow-400' : 'text-blue-400'}`}>
                        {v.cvss > 0 ? v.cvss : '—'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-gray-400 font-mono text-xs max-w-[120px] truncate">{v.target}</td>
                    <td className="px-4 py-2.5">
                      <span className={`text-xs px-2 py-0.5 rounded border ${v.status === 'found' ? 'bg-red-900/40 text-red-400 border-red-700' : 'bg-green-900/30 text-green-400 border-green-800'}`}>
                        {v.status === 'found' ? 'Vulnerável' : 'Bloqueado'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-gray-500 text-xs whitespace-nowrap">{v.date?.slice(0, 10)}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {(v.compliance || []).slice(0, 2).map(c => (
                          <span key={c} className="text-[10px] px-1.5 py-0.5 rounded bg-dark-700 text-cyan-400 border border-dark-500">{c}</span>
                        ))}
                        {(v.compliance || []).length > 2 && <span className="text-[10px] text-gray-500">+{(v.compliance || []).length - 2}</span>}
                      </div>
                    </td>
                    {isEnriched && <>
                      <td className="px-4 py-2.5 text-center">
                        <EpssCell epss={enrich?.epss} />
                      </td>
                      <td className="px-4 py-2.5">
                        <KevBadge kev={enrich?.kev} />
                      </td>
                      <td className="px-4 py-2.5">
                        <PriorityBadge priority={enrich?.priority} />
                      </td>
                    </>}
                  </tr>
                )
              })}
            </tbody>
          </table>

          {/* Pagination */}
          {pages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-dark-600 text-sm text-gray-500">
              <span>Mostrando {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, filtered.length)} de {filtered.length}</span>
              <div className="flex gap-1">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                  className="px-3 py-1 rounded bg-dark-700 hover:bg-dark-600 disabled:opacity-40 disabled:cursor-not-allowed transition">
                  Anterior
                </button>
                {Array.from({ length: Math.min(pages, 5) }, (_, i) => {
                  const n = page <= 3 ? i + 1 : i + page - 2
                  return n <= pages ? (
                    <button key={n} onClick={() => setPage(n)}
                      className={`px-3 py-1 rounded transition ${n === page ? 'bg-red-700 text-white' : 'bg-dark-700 hover:bg-dark-600'}`}>
                      {n}
                    </button>
                  ) : null
                })}
                <button onClick={() => setPage(p => Math.min(pages, p + 1))} disabled={page === pages}
                  className="px-3 py-1 rounded bg-dark-700 hover:bg-dark-600 disabled:opacity-40 disabled:cursor-not-allowed transition">
                  Próximo
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Detail Drawer */}
      {selected && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-end md:items-center justify-end p-0 md:p-4" onClick={() => setSelected(null)}>
          <div className="bg-dark-800 border border-dark-600 shadow-2xl w-full md:w-96 h-full md:h-auto md:max-h-[85vh] md:rounded-xl overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between items-start p-5 border-b border-dark-600 sticky top-0 bg-dark-800 z-10">
              <div>
                <p className="text-xs text-gray-500 font-mono">{selected.technique_id}</p>
                <h3 className="text-base font-bold text-gray-100 mt-0.5">{selected.name}</h3>
              </div>
              <button onClick={() => setSelected(null)} className="text-gray-500 hover:text-gray-100 flex-shrink-0">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-5 space-y-4 text-sm">
              <div className="flex gap-2 flex-wrap">
                <span className={`text-xs px-2 py-0.5 rounded border font-medium ${SEV_BADGE[selected.severity] || SEV_BADGE['']}`}>{selected.severity || 'N/A'}</span>
                <span className={`text-xs px-2 py-0.5 rounded border ${selected.status === 'found' ? 'bg-red-900/40 text-red-400 border-red-700' : 'bg-green-900/30 text-green-400 border-green-800'}`}>
                  {selected.status === 'found' ? 'Vulnerável' : 'Bloqueado'}
                </span>
                {selected.cvss > 0 && <span className="text-xs px-2 py-0.5 rounded border bg-dark-700 text-gray-300 border-dark-500">CVSS {selected.cvss}</span>}
                {selected._enrich?.kev && <KevBadge kev={true} />}
              </div>

              {/* EPSS/KEV enrichment panel in drawer */}
              {selected._enrich && (
                <div className="rounded-lg border border-purple-800/40 bg-purple-950/20 p-3 space-y-2">
                  <p className="text-xs font-semibold text-purple-300 flex items-center gap-1">
                    <Zap className="w-3 h-3" /> Priorização EPSS + KEV
                  </p>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <p className="text-gray-500 mb-0.5">EPSS (30 dias)</p>
                      <EpssCell epss={selected._enrich.epss} />
                    </div>
                    <div>
                      <p className="text-gray-500 mb-0.5">CISA KEV</p>
                      <KevBadge kev={selected._enrich.kev} />
                    </div>
                    <div>
                      <p className="text-gray-500 mb-0.5">Score Composto</p>
                      <span className="font-mono font-bold text-gray-200">
                        {selected._enrich.composite_score != null ? selected._enrich.composite_score.toFixed(3) : '—'}
                      </span>
                    </div>
                    <div>
                      <p className="text-gray-500 mb-0.5">Prioridade</p>
                      <PriorityBadge priority={selected._enrich.priority} />
                    </div>
                  </div>
                </div>
              )}

              <div>
                <p className="text-xs text-gray-500 mb-1">Alvo</p>
                <p className="text-gray-300 font-mono">{selected.target}</p>
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-1">Data</p>
                <p className="text-gray-300">{selected.date?.slice(0, 16).replace('T', ' ')}</p>
              </div>
              {selected.description && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Descrição</p>
                  <p className="text-gray-300 leading-relaxed text-xs">{selected.description}</p>
                </div>
              )}
              {selected.detail && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Evidência</p>
                  <p className="text-gray-300 text-xs leading-relaxed">{selected.detail}</p>
                </div>
              )}
              {selected.remediation && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Remediação</p>
                  <p className="text-gray-300 leading-relaxed text-xs">{selected.remediation}</p>
                </div>
              )}
              {selected.compliance?.length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Frameworks de Compliance</p>
                  <div className="flex flex-wrap gap-1">
                    {selected.compliance.map(c => (
                      <span key={c} className="text-xs px-2 py-0.5 rounded bg-dark-700 text-cyan-400 border border-dark-500">{c}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
