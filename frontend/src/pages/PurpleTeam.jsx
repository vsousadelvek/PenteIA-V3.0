import React, { useState, useEffect, useCallback } from 'react'
import {
  Shield,
  Target,
  CheckCircle,
  XCircle,
  AlertTriangle,
  BarChart2,
  RefreshCw,
  FileText,
  ChevronDown,
  X,
  Loader,
  Save,
} from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

// ─── Constants ────────────────────────────────────────────────────────────────

const DETECTION_SOURCES = ['SIEM', 'EDR', 'NDR', 'SOAR', 'Manual']
const FIDELITY_LEVELS = ['None', 'Low', 'Medium', 'High']

const FIDELITY_COLOR = {
  None: 'text-gray-500',
  Low: 'text-blue-400',
  Medium: 'text-yellow-400',
  High: 'text-green-400',
}

const FIDELITY_BG = {
  None: 'bg-gray-800 text-gray-500',
  Low: 'bg-blue-900/40 text-blue-400 border-blue-700/50',
  Medium: 'bg-yellow-900/40 text-yellow-400 border-yellow-700/50',
  High: 'bg-green-900/40 text-green-400 border-green-700/50',
}

// ─── Row color coding ─────────────────────────────────────────────────────────

function rowBg(row) {
  if (row._detected === true) return 'bg-green-950/20 border-l-2 border-green-600'
  if (row._detected === false) return 'bg-red-950/20 border-l-2 border-red-700'
  return 'bg-dark-800/60 border-l-2 border-dark-600'
}

// ─── Aggregate stats helpers ──────────────────────────────────────────────────

function computeStats(rows) {
  if (!rows || rows.length === 0)
    return { detectionRate: 0, avgConfidence: 0, byTactic: {} }

  const assessed = rows.filter(r => r._detected !== null)
  const detected = rows.filter(r => r._detected === true)
  const detectionRate = assessed.length > 0
    ? Math.round((detected.length / assessed.length) * 100)
    : 0

  // Confidence score: High=100, Medium=66, Low=33, None=0; average over detected
  const fidelityScore = { High: 100, Medium: 66, Low: 33, None: 0 }
  const detectedWithFidelity = detected.filter(r => r._fidelity && r._fidelity !== 'None')
  const avgConfidence = detectedWithFidelity.length > 0
    ? Math.round(
        detectedWithFidelity.reduce((sum, r) => sum + (fidelityScore[r._fidelity] || 0), 0) /
          detectedWithFidelity.length
      )
    : 0

  // Coverage by tactic
  const byTactic = {}
  rows.forEach(r => {
    const tactic = r.tactic || 'Unknown'
    if (!byTactic[tactic]) byTactic[tactic] = { total: 0, detected: 0 }
    byTactic[tactic].total++
    if (r._detected === true) byTactic[tactic].detected++
  })

  return { detectionRate, avgConfidence, byTactic }
}

// ─── TacticBar component ──────────────────────────────────────────────────────

function TacticBar({ tactic, detected, total }) {
  const pct = total > 0 ? Math.round((detected / total) * 100) : 0
  const barColor =
    pct >= 70 ? 'bg-green-500' : pct >= 40 ? 'bg-yellow-500' : 'bg-red-500'

  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-gray-400 w-40 truncate flex-shrink-0" title={tactic}>
        {tactic}
      </span>
      <div className="flex-1 h-2 bg-dark-600 rounded-full overflow-hidden">
        <div
          className={`h-2 rounded-full transition-all duration-500 ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className={`text-xs font-mono w-12 text-right flex-shrink-0 ${
        pct >= 70 ? 'text-green-400' : pct >= 40 ? 'text-yellow-400' : 'text-red-400'
      }`}>
        {pct}%
      </span>
      <span className="text-xs text-gray-600 w-14 text-right flex-shrink-0">
        {detected}/{total}
      </span>
    </div>
  )
}

// ─── TechniqueRow component ───────────────────────────────────────────────────

function TechniqueRow({ row, onUpdate }) {
  const toast = useToast()
  const [saving, setSaving] = useState(false)
  const [local, setLocal] = useState({
    _detected: row._detected,
    _source: row._source || '',
    _fidelity: row._fidelity || 'None',
    _detection_time: row._detection_time || '',
    _notes: row._notes || '',
  })

  // Sync if parent row changes (e.g. after report load)
  useEffect(() => {
    setLocal({
      _detected: row._detected,
      _source: row._source || '',
      _fidelity: row._fidelity || 'None',
      _detection_time: row._detection_time || '',
      _notes: row._notes || '',
    })
  }, [row._detected, row._source, row._fidelity, row._detection_time, row._notes])

  const set = (key, val) => setLocal(prev => ({ ...prev, [key]: val }))

  const handleSave = async () => {
    setSaving(true)
    try {
      await onUpdate(row.technique_id || row.id, local)
      toast('Salvo com sucesso', 'success')
    } catch (e) {
      toast(e.response?.data?.detail || 'Erro ao salvar', 'error')
    } finally {
      setSaving(false)
    }
  }

  const detectedNull = local._detected === null || local._detected === undefined
  const detectedTrue = local._detected === true
  const detectedFalse = local._detected === false

  const effectiveBg =
    detectedTrue
      ? 'bg-green-950/20 border-l-2 border-green-600'
      : detectedFalse
      ? 'bg-red-950/20 border-l-2 border-red-700'
      : 'bg-dark-800/60 border-l-2 border-dark-600'

  return (
    <tr className={`group text-xs transition ${effectiveBg}`}>
      {/* Technique ID */}
      <td className="px-3 py-2.5 font-mono text-gray-400 whitespace-nowrap">
        {row.technique_id || row.id || '-'}
      </td>

      {/* Name */}
      <td className="px-3 py-2.5 text-gray-300 max-w-[180px]">
        <span title={row.name} className="line-clamp-2 leading-snug">{row.name || '-'}</span>
      </td>

      {/* Tactic */}
      <td className="px-3 py-2.5 text-gray-500 whitespace-nowrap">
        {row.tactic || '-'}
      </td>

      {/* BAS Status */}
      <td className="px-3 py-2.5 whitespace-nowrap">
        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
          row.bas_status === 'found'
            ? 'bg-red-900/50 text-red-400'
            : row.bas_status === 'blocked'
            ? 'bg-green-900/50 text-green-400'
            : 'bg-gray-800 text-gray-500'
        }`}>
          {row.bas_status === 'found'
            ? 'Vulneravel'
            : row.bas_status === 'blocked'
            ? 'Bloqueado'
            : row.bas_status || 'N/A'}
        </span>
      </td>

      {/* Detected toggle */}
      <td className="px-3 py-2.5 whitespace-nowrap">
        <div className="flex items-center gap-1">
          <button
            onClick={() => set('_detected', true)}
            title="Detectado"
            className={`p-1 rounded transition ${detectedTrue ? 'bg-green-700 text-white' : 'text-gray-600 hover:text-green-400'}`}
          >
            <CheckCircle className="w-4 h-4" />
          </button>
          <button
            onClick={() => set('_detected', false)}
            title="Nao detectado"
            className={`p-1 rounded transition ${detectedFalse ? 'bg-red-700 text-white' : 'text-gray-600 hover:text-red-400'}`}
          >
            <XCircle className="w-4 h-4" />
          </button>
          <button
            onClick={() => set('_detected', null)}
            title="Nao avaliado"
            className={`p-1 rounded transition ${detectedNull ? 'bg-gray-700 text-gray-300' : 'text-gray-700 hover:text-gray-400'}`}
          >
            <AlertTriangle className="w-4 h-4" />
          </button>
        </div>
      </td>

      {/* Detection Source */}
      <td className="px-3 py-2.5">
        <select
          value={local._source}
          onChange={e => set('_source', e.target.value)}
          className="bg-dark-700 border border-dark-500 rounded text-gray-300 text-xs px-2 py-1 focus:outline-none focus:border-purple-600 w-28"
        >
          <option value="">—</option>
          {DETECTION_SOURCES.map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </td>

      {/* Alert Fidelity */}
      <td className="px-3 py-2.5">
        <select
          value={local._fidelity}
          onChange={e => set('_fidelity', e.target.value)}
          className={`border rounded text-xs px-2 py-1 focus:outline-none focus:border-purple-600 w-24 ${
            FIDELITY_BG[local._fidelity] || 'bg-dark-700 border-dark-500 text-gray-300'
          } bg-dark-700 border`}
        >
          {FIDELITY_LEVELS.map(l => (
            <option key={l} value={l}>{l}</option>
          ))}
        </select>
      </td>

      {/* Detection Time */}
      <td className="px-3 py-2.5">
        <div className="flex items-center gap-1">
          <input
            type="number"
            min="0"
            value={local._detection_time}
            onChange={e => set('_detection_time', e.target.value)}
            placeholder="seg"
            className="bg-dark-700 border border-dark-500 rounded text-gray-300 text-xs px-2 py-1 w-20 focus:outline-none focus:border-purple-600"
          />
          <span className="text-gray-600 text-[10px]">s</span>
        </div>
      </td>

      {/* Notes */}
      <td className="px-3 py-2.5">
        <input
          type="text"
          value={local._notes}
          onChange={e => set('_notes', e.target.value)}
          placeholder="Observacoes..."
          className="bg-dark-700 border border-dark-500 rounded text-gray-300 text-xs px-2 py-1 w-40 focus:outline-none focus:border-purple-600"
        />
      </td>

      {/* Save button */}
      <td className="px-3 py-2.5">
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-1 px-3 py-1.5 bg-purple-700 hover:bg-purple-600 text-white rounded text-xs transition disabled:opacity-50 whitespace-nowrap"
        >
          {saving
            ? <Loader className="w-3 h-3 animate-spin" />
            : <Save className="w-3 h-3" />}
          Salvar
        </button>
      </td>
    </tr>
  )
}

// ─── Recommendations panel ────────────────────────────────────────────────────

function RecommendationsPanel({ report, onClose }) {
  if (!report) return null

  const recs = report.recommendations || []
  const gaps = report.coverage_gaps || []
  const controls = report.missing_controls || []

  return (
    <div className="card-dark border border-purple-700/50 bg-purple-900/10 p-6 space-y-5 slide-in">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-purple-400" />
          <h3 className="text-lg font-bold text-gray-100">Relatorio Purple Team</h3>
          {report.generated_at && (
            <span className="text-xs text-gray-500">
              {new Date(report.generated_at).toLocaleString('pt-BR')}
            </span>
          )}
        </div>
        <button onClick={onClose} className="text-gray-500 hover:text-gray-200 transition">
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Summary metrics */}
      {report.summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Taxa de Deteccao', value: `${report.summary.detection_rate ?? 0}%`, color: 'text-purple-400' },
            { label: 'Tecnicas Avaliadas', value: report.summary.total_techniques ?? 0, color: 'text-gray-300' },
            { label: 'Detectadas', value: report.summary.detected ?? 0, color: 'text-green-400' },
            { label: 'Gaps', value: report.summary.gaps ?? 0, color: 'text-red-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-dark-700 rounded-lg p-3 text-center">
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
              <p className="text-xs text-gray-500 mt-1">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Coverage gaps */}
      {gaps.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-red-400 mb-2 flex items-center gap-1">
            <XCircle className="w-4 h-4" /> Gaps de Cobertura ({gaps.length})
          </h4>
          <div className="space-y-1.5">
            {gaps.map((g, i) => (
              <div key={i} className="flex items-start gap-3 p-2.5 rounded bg-red-950/20 border border-red-800/30">
                <span className="font-mono text-gray-500 text-[10px] w-20 shrink-0 mt-0.5">
                  {g.technique_id || ''}
                </span>
                <div className="flex-1">
                  <p className="text-gray-300 text-xs font-medium">{g.name || g.technique_id}</p>
                  {g.tactic && <p className="text-gray-600 text-[10px] mt-0.5">{g.tactic}</p>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      {recs.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-yellow-400 mb-2 flex items-center gap-1">
            <AlertTriangle className="w-4 h-4" /> Recomendacoes ({recs.length})
          </h4>
          <div className="space-y-2">
            {recs.map((rec, i) => (
              <div key={i} className="flex gap-3 p-3 rounded bg-yellow-900/10 border border-yellow-800/30">
                <span className="text-yellow-600 text-xs font-bold flex-shrink-0 mt-0.5">{i + 1}.</span>
                <div className="flex-1">
                  {typeof rec === 'string' ? (
                    <p className="text-yellow-200/80 text-xs leading-relaxed">{rec}</p>
                  ) : (
                    <>
                      {rec.title && (
                        <p className="text-yellow-300 text-xs font-semibold mb-0.5">{rec.title}</p>
                      )}
                      {rec.description && (
                        <p className="text-yellow-200/70 text-xs leading-relaxed">{rec.description}</p>
                      )}
                      {rec.priority && (
                        <span className={`mt-1 inline-block text-[10px] px-1.5 py-0.5 rounded ${
                          rec.priority === 'High'
                            ? 'bg-red-900/40 text-red-400'
                            : rec.priority === 'Medium'
                            ? 'bg-yellow-900/40 text-yellow-400'
                            : 'bg-blue-900/40 text-blue-400'
                        }`}>
                          Prioridade: {rec.priority}
                        </span>
                      )}
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Missing controls */}
      {controls.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-blue-400 mb-2 flex items-center gap-1">
            <Shield className="w-4 h-4" /> Controles Faltantes ({controls.length})
          </h4>
          <div className="flex flex-wrap gap-2">
            {controls.map((c, i) => (
              <span key={i} className="text-xs px-2 py-1 rounded bg-blue-900/20 text-blue-300 border border-blue-800/40">
                {typeof c === 'string' ? c : (c.name || c.id || JSON.stringify(c))}
              </span>
            ))}
          </div>
        </div>
      )}

      {recs.length === 0 && gaps.length === 0 && controls.length === 0 && (
        <p className="text-gray-500 text-sm text-center py-4">
          Nenhuma recomendacao encontrada. Otima cobertura de deteccao!
        </p>
      )}
    </div>
  )
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function PurpleTeam() {
  const toast = useToast()

  // State
  const [simulations, setSimulations] = useState([])
  const [selectedSimId, setSelectedSimId] = useState('')
  const [session, setSession] = useState(null)
  const [rows, setRows] = useState([])
  const [loadingSims, setLoadingSims] = useState(true)
  const [loadingSession, setLoadingSession] = useState(false)
  const [generatingReport, setGeneratingReport] = useState(false)
  const [report, setReport] = useState(null)
  const [tacticFilter, setTacticFilter] = useState('all')

  // Load simulations on mount
  useEffect(() => {
    const fetchSims = async () => {
      setLoadingSims(true)
      try {
        const res = await api.get('/api/bas/simulations')
        const completed = (res.data.simulations || []).filter(
          s => s.status === 'completed'
        )
        setSimulations(completed)
      } catch (e) {
        toast('Erro ao carregar simulacoes: ' + (e.response?.data?.detail || e.message), 'error')
      } finally {
        setLoadingSims(false)
      }
    }
    fetchSims()
  }, [])

  // Load purple team session when sim selected
  const loadSession = useCallback(async (simId) => {
    if (!simId) {
      setSession(null)
      setRows([])
      setReport(null)
      return
    }
    setLoadingSession(true)
    setReport(null)
    try {
      const res = await api.get(`/api/purple/${simId}`)
      const data = res.data
      setSession(data)

      // Normalise technique rows — merge server-saved assessment fields
      const techniques = (data.techniques || []).map(t => ({
        ...t,
        _detected: t.detected ?? null,
        _source: t.detection_source || '',
        _fidelity: t.alert_fidelity || 'None',
        _detection_time: t.detection_time != null ? String(t.detection_time) : '',
        _notes: t.notes || '',
      }))
      setRows(techniques)
    } catch (e) {
      toast(
        'Erro ao carregar sessao Purple Team: ' + (e.response?.data?.detail || e.message),
        'error'
      )
      setSession(null)
      setRows([])
    } finally {
      setLoadingSession(false)
    }
  }, [])

  const handleSimChange = (e) => {
    const id = e.target.value
    setSelectedSimId(id)
    loadSession(id)
  }

  const handleRefresh = () => {
    if (selectedSimId) loadSession(selectedSimId)
  }

  // Update a single technique row
  const handleUpdate = useCallback(async (techniqueId, localState) => {
    await api.post(`/api/purple/${selectedSimId}/update`, {
      technique_id: techniqueId,
      detected: localState._detected,
      detection_source: localState._source || null,
      alert_fidelity: localState._fidelity || 'None',
      detection_time: localState._detection_time !== ''
        ? Number(localState._detection_time)
        : null,
      notes: localState._notes || '',
    })

    // Update local rows state so stats re-compute
    setRows(prev =>
      prev.map(r =>
        (r.technique_id || r.id) === techniqueId
          ? {
              ...r,
              _detected: localState._detected,
              _source: localState._source,
              _fidelity: localState._fidelity,
              _detection_time: localState._detection_time,
              _notes: localState._notes,
            }
          : r
      )
    )
  }, [selectedSimId])

  // Generate report
  const handleGenerateReport = async () => {
    if (!selectedSimId) return
    setGeneratingReport(true)
    try {
      const res = await api.get(`/api/purple/${selectedSimId}/report`)
      setReport(res.data)
      toast('Relatorio gerado com sucesso', 'success')
      // Scroll report into view
      setTimeout(() => {
        document.getElementById('purple-report')?.scrollIntoView({ behavior: 'smooth' })
      }, 100)
    } catch (e) {
      toast(
        'Erro ao gerar relatorio: ' + (e.response?.data?.detail || e.message),
        'error'
      )
    } finally {
      setGeneratingReport(false)
    }
  }

  // Compute stats from current rows
  const stats = computeStats(rows)

  // Unique tactics for filter
  const tactics = ['all', ...Array.from(new Set(rows.map(r => r.tactic).filter(Boolean))).sort()]

  const filteredRows = tacticFilter === 'all'
    ? rows
    : rows.filter(r => r.tactic === tacticFilter)

  // Detection rate color
  const rateColor =
    stats.detectionRate >= 70
      ? 'text-green-400'
      : stats.detectionRate >= 40
      ? 'text-yellow-400'
      : 'text-red-400'

  const rateBarColor =
    stats.detectionRate >= 70
      ? 'bg-green-500'
      : stats.detectionRate >= 40
      ? 'bg-yellow-500'
      : 'bg-red-500'

  return (
    <div className="space-y-8">

      {/* Header */}
      <div className="slide-in">
        <div className="flex items-center gap-3 mb-1">
          <Shield className="w-8 h-8 text-purple-400" />
          <h1 className="text-3xl font-bold text-gray-100">Purple Team</h1>
        </div>
        <p className="text-gray-400 ml-11">
          Scoring de confianca de deteccao para resultados BAS — avalie a efetividade do seu SOC em detectar ataques simulados.
        </p>
      </div>

      {/* Info banner */}
      <div className="card-dark p-5 bg-purple-900/10 border-l-4 border-purple-600">
        <div className="flex items-start gap-3">
          <Target className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-gray-300 font-semibold mb-1">O que e o Purple Team?</p>
            <p className="text-sm text-gray-400 leading-relaxed">
              Combines Red Team (simulacao de ataque via BAS) com Blue Team (deteccao via SIEM/EDR).
              Para cada tecnica executada, avalie se foi detectada, qual ferramenta detectou,
              a fidelidade do alerta e o tempo de resposta. O resultado e um score de confianca de deteccao por tatica MITRE ATT&CK.
            </p>
          </div>
        </div>
      </div>

      {/* Simulation selector */}
      <div className="card-dark p-6">
        <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
          <h2 className="text-lg font-bold text-gray-100 flex items-center gap-2">
            <BarChart2 className="w-5 h-5 text-purple-400" />
            Selecionar Simulacao BAS
          </h2>
          {selectedSimId && (
            <button
              onClick={handleRefresh}
              disabled={loadingSession}
              className="flex items-center gap-1 text-xs px-3 py-1.5 bg-dark-700 hover:bg-dark-600 border border-dark-500 text-gray-400 rounded transition disabled:opacity-50"
            >
              <RefreshCw className={`w-3 h-3 ${loadingSession ? 'animate-spin' : ''}`} />
              Atualizar
            </button>
          )}
        </div>

        {loadingSims ? (
          <div className="flex items-center gap-2 text-gray-500 text-sm">
            <Loader className="w-4 h-4 animate-spin" />
            Carregando simulacoes...
          </div>
        ) : simulations.length === 0 ? (
          <div className="text-center py-8 border border-dashed border-dark-600 rounded-lg">
            <AlertTriangle className="w-8 h-8 text-gray-600 mx-auto mb-2" />
            <p className="text-gray-500 text-sm">Nenhuma simulacao BAS concluida encontrada.</p>
            <p className="text-gray-600 text-xs mt-1">
              Execute uma simulacao na pagina BAS antes de usar o Purple Team.
            </p>
          </div>
        ) : (
          <div className="flex items-center gap-3 flex-wrap">
            <select
              value={selectedSimId}
              onChange={handleSimChange}
              className="select-dark flex-1 min-w-[280px] max-w-lg"
            >
              <option value="">-- Selecione uma simulacao concluida --</option>
              {simulations.map(s => (
                <option key={s.id} value={s.id}>
                  {s.playbook_name || s.playbook_id || 'Simulacao'} — {s.target} — {
                    s.date ? new Date(s.date).toLocaleDateString('pt-BR') : s.id.slice(0, 8)
                  }
                </option>
              ))}
            </select>
            {session && (
              <span className="text-xs text-purple-400 bg-purple-900/20 border border-purple-700/40 px-2 py-1 rounded">
                {rows.length} tecnicas carregadas
              </span>
            )}
          </div>
        )}
      </div>

      {/* Loading session spinner */}
      {loadingSession && (
        <div className="flex items-center justify-center py-16">
          <div className="w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
        </div>
      )}

      {/* Main content — only when session loaded */}
      {!loadingSession && session && rows.length > 0 && (
        <>
          {/* Tactic filter */}
          {tactics.length > 2 && (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs text-gray-500">Filtrar por tatica:</span>
              {tactics.map(t => (
                <button
                  key={t}
                  onClick={() => setTacticFilter(t)}
                  className={`text-xs px-2.5 py-1 rounded transition ${
                    tacticFilter === t
                      ? 'bg-purple-700 text-white'
                      : 'bg-dark-700 text-gray-400 hover:bg-dark-600'
                  }`}
                >
                  {t === 'all' ? 'Todas' : t}
                </button>
              ))}
            </div>
          )}

          {/* Techniques table */}
          <div className="card-dark overflow-hidden">
            <div className="p-4 border-b border-dark-600 flex items-center justify-between flex-wrap gap-3">
              <h3 className="text-base font-bold text-gray-100">
                Tecnicas ({filteredRows.length}
                {tacticFilter !== 'all' ? ` em "${tacticFilter}"` : ''})
              </h3>
              <div className="flex items-center gap-4 text-xs">
                <span className="flex items-center gap-1 text-green-400">
                  <span className="w-2 h-2 rounded-full bg-green-500 inline-block" />
                  Detectada ({rows.filter(r => r._detected === true).length})
                </span>
                <span className="flex items-center gap-1 text-red-400">
                  <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
                  Nao detectada ({rows.filter(r => r._detected === false).length})
                </span>
                <span className="flex items-center gap-1 text-gray-500">
                  <span className="w-2 h-2 rounded-full bg-gray-600 inline-block" />
                  Nao avaliada ({rows.filter(r => r._detected == null).length})
                </span>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr className="bg-dark-700 text-left">
                    {[
                      'Technique ID',
                      'Nome',
                      'Tatica',
                      'BAS Status',
                      'Detectado',
                      'Fonte',
                      'Fidelidade',
                      'Tempo (s)',
                      'Observacoes',
                      '',
                    ].map(h => (
                      <th
                        key={h}
                        className="px-3 py-2.5 text-xs font-semibold text-gray-500 uppercase tracking-wide whitespace-nowrap border-b border-dark-600"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-600/50">
                  {filteredRows.map((row, idx) => (
                    <TechniqueRow
                      key={row.technique_id || row.id || idx}
                      row={row}
                      onUpdate={handleUpdate}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Aggregate stats panel */}
          <div className="card-dark p-6 space-y-6">
            <div className="flex items-center gap-2 mb-1">
              <BarChart2 className="w-5 h-5 text-purple-400" />
              <h3 className="text-base font-bold text-gray-100">Metricas Agregadas</h3>
            </div>

            {/* Top metrics */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {/* Detection Rate */}
              <div className="bg-dark-700 rounded-xl p-5 text-center border border-dark-600">
                <p className={`text-5xl font-black ${rateColor}`}>
                  {stats.detectionRate}%
                </p>
                <p className="text-xs text-gray-500 mt-2 font-medium uppercase tracking-wide">
                  Taxa de Deteccao
                </p>
                <div className="w-full bg-dark-600 rounded-full h-2 mt-3">
                  <div
                    className={`h-2 rounded-full transition-all duration-700 ${rateBarColor}`}
                    style={{ width: `${stats.detectionRate}%` }}
                  />
                </div>
                <p className="text-xs text-gray-600 mt-2">
                  {rows.filter(r => r._detected === true).length} de{' '}
                  {rows.filter(r => r._detected !== null).length} avaliadas
                </p>
              </div>

              {/* Avg Confidence */}
              <div className="bg-dark-700 rounded-xl p-5 text-center border border-dark-600">
                <p className={`text-5xl font-black ${
                  stats.avgConfidence >= 66
                    ? 'text-green-400'
                    : stats.avgConfidence >= 33
                    ? 'text-yellow-400'
                    : 'text-red-400'
                }`}>
                  {stats.avgConfidence}%
                </p>
                <p className="text-xs text-gray-500 mt-2 font-medium uppercase tracking-wide">
                  Confianca Media
                </p>
                <div className="w-full bg-dark-600 rounded-full h-2 mt-3">
                  <div
                    className={`h-2 rounded-full transition-all duration-700 ${
                      stats.avgConfidence >= 66
                        ? 'bg-green-500'
                        : stats.avgConfidence >= 33
                        ? 'bg-yellow-500'
                        : 'bg-red-500'
                    }`}
                    style={{ width: `${stats.avgConfidence}%` }}
                  />
                </div>
                <p className="text-xs text-gray-600 mt-2">
                  Baseado na fidelidade dos alertas
                </p>
              </div>

              {/* Assessed count */}
              <div className="bg-dark-700 rounded-xl p-5 text-center border border-dark-600">
                <p className="text-5xl font-black text-purple-400">
                  {rows.filter(r => r._detected !== null).length}
                  <span className="text-xl text-gray-600">/{rows.length}</span>
                </p>
                <p className="text-xs text-gray-500 mt-2 font-medium uppercase tracking-wide">
                  Tecnicas Avaliadas
                </p>
                <div className="w-full bg-dark-600 rounded-full h-2 mt-3">
                  <div
                    className="h-2 rounded-full transition-all duration-700 bg-purple-500"
                    style={{
                      width: rows.length > 0
                        ? `${Math.round((rows.filter(r => r._detected !== null).length / rows.length) * 100)}%`
                        : '0%',
                    }}
                  />
                </div>
                <p className="text-xs text-gray-600 mt-2">
                  {rows.filter(r => r._detected == null).length} ainda nao avaliadas
                </p>
              </div>
            </div>

            {/* Coverage by Tactic */}
            {Object.keys(stats.byTactic).length > 0 && (
              <div className="bg-dark-700 rounded-xl p-5 border border-dark-600">
                <h4 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
                  <Target className="w-4 h-4 text-purple-400" />
                  Cobertura por Tatica MITRE ATT&CK
                </h4>
                <div className="space-y-2.5">
                  {Object.entries(stats.byTactic)
                    .sort(([, a], [, b]) => {
                      const pctA = a.total > 0 ? a.detected / a.total : 0
                      const pctB = b.total > 0 ? b.detected / b.total : 0
                      return pctA - pctB // ascending: worst coverage first
                    })
                    .map(([tactic, { detected, total }]) => (
                      <TacticBar
                        key={tactic}
                        tactic={tactic}
                        detected={detected}
                        total={total}
                      />
                    ))}
                </div>
              </div>
            )}

            {/* Quick breakdown by detection source */}
            {rows.filter(r => r._source).length > 0 && (
              <div className="bg-dark-700 rounded-xl p-5 border border-dark-600">
                <h4 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-purple-400" />
                  Deteccoes por Ferramenta
                </h4>
                <div className="flex flex-wrap gap-3">
                  {DETECTION_SOURCES.map(src => {
                    const count = rows.filter(r => r._detected === true && r._source === src).length
                    if (count === 0) return null
                    return (
                      <div key={src} className="flex items-center gap-2 bg-dark-600 rounded-lg px-3 py-2">
                        <span className="text-xs font-semibold text-purple-300">{src}</span>
                        <span className="text-sm font-bold text-gray-100">{count}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </div>

          {/* Generate report button */}
          <div className="flex justify-end">
            <button
              onClick={handleGenerateReport}
              disabled={generatingReport}
              className="flex items-center gap-2 px-5 py-3 bg-purple-700 hover:bg-purple-600 text-white rounded-lg font-semibold transition disabled:opacity-50 shadow-lg shadow-purple-900/30"
            >
              {generatingReport
                ? <Loader className="w-5 h-5 animate-spin" />
                : <FileText className="w-5 h-5" />}
              {generatingReport ? 'Gerando Relatorio...' : 'Gerar Relatorio'}
            </button>
          </div>

          {/* Recommendations panel */}
          {report && (
            <div id="purple-report">
              <RecommendationsPanel report={report} onClose={() => setReport(null)} />
            </div>
          )}
        </>
      )}

      {/* Empty state when sim selected but no rows */}
      {!loadingSession && session && rows.length === 0 && (
        <div className="card-dark p-12 text-center">
          <AlertTriangle className="w-10 h-10 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">Nenhuma tecnica encontrada nessa sessao Purple Team.</p>
          <p className="text-gray-600 text-sm mt-1">
            O backend pode ter retornado uma lista de tecnicas vazia. Verifique a simulacao BAS selecionada.
          </p>
        </div>
      )}

    </div>
  )
}
