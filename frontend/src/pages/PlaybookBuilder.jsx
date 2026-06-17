import React, { useState, useEffect, useRef, useCallback } from 'react'
import {
  Search, X, Play, Save, GripVertical, ChevronDown, AlertTriangle,
  BookOpen, Layers, Plus, Loader, Target, Zap, ShieldAlert,
  ClipboardList, Info,
} from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const FALLBACK_TECHNIQUES = [
  { id: 'T1059',       name: 'Command and Scripting Interpreter', tactic: 'EXECUTION',          severity: 'high'     },
  { id: 'T1055',       name: 'Process Injection',                  tactic: 'EXECUTION',          severity: 'critical' },
  { id: 'T1003',       name: 'OS Credential Dumping',              tactic: 'CREDENTIAL_ACCESS',  severity: 'critical' },
  { id: 'T1021',       name: 'Remote Services',                    tactic: 'LATERAL_MOVEMENT',   severity: 'high'     },
  { id: 'T1078',       name: 'Valid Accounts',                     tactic: 'INITIAL_ACCESS',     severity: 'high'     },
  { id: 'T1486',       name: 'Data Encrypted for Impact',          tactic: 'IMPACT',             severity: 'critical' },
  { id: 'T1566',       name: 'Phishing',                           tactic: 'INITIAL_ACCESS',     severity: 'high'     },
  { id: 'T1190',       name: 'Exploit Public-Facing Application',  tactic: 'INITIAL_ACCESS',     severity: 'critical' },
  { id: 'T1070',       name: 'Indicator Removal',                  tactic: 'DEFENSE_EVASION',    severity: 'medium'   },
  { id: 'T1041',       name: 'Exfiltration Over C2 Channel',       tactic: 'EXFILTRATION',       severity: 'high'     },
  { id: 'BR-PIX-001',  name: 'Pix Transaction Hijacking',          tactic: 'IMPACT',             severity: 'critical' },
  { id: 'BR-MALW-001', name: 'Grandoreiro Banking Trojan',         tactic: 'EXECUTION',          severity: 'critical' },
  { id: 'BR-DREX-001', name: 'DREX Smart Contract Exploit',        tactic: 'IMPACT',             severity: 'critical' },
  { id: 'BR-NFE-001',  name: 'NF-e XML Injection via SEFAZ',       tactic: 'INITIAL_ACCESS',     severity: 'critical' },
  { id: 'BR-GOVBR-001',name: 'Gov.br OAuth2 Token Hijacking',      tactic: 'CREDENTIAL_ACCESS',  severity: 'critical' },
]

const ALL_TACTICS = [
  'EXECUTION',
  'INITIAL_ACCESS',
  'CREDENTIAL_ACCESS',
  'LATERAL_MOVEMENT',
  'IMPACT',
  'DEFENSE_EVASION',
  'EXFILTRATION',
]

const TACTIC_LABEL = {
  EXECUTION:          'Execução',
  INITIAL_ACCESS:     'Acesso Inicial',
  CREDENTIAL_ACCESS:  'Credenciais',
  LATERAL_MOVEMENT:   'Mov. Lateral',
  IMPACT:             'Impacto',
  DEFENSE_EVASION:    'Evasão',
  EXFILTRATION:       'Exfiltração',
}

const TACTIC_COLOR = {
  EXECUTION:          'bg-red-900/50 text-red-300 border-red-700/50',
  INITIAL_ACCESS:     'bg-orange-900/50 text-orange-300 border-orange-700/50',
  CREDENTIAL_ACCESS:  'bg-yellow-900/50 text-yellow-300 border-yellow-700/50',
  LATERAL_MOVEMENT:   'bg-purple-900/50 text-purple-300 border-purple-700/50',
  IMPACT:             'bg-pink-900/50 text-pink-300 border-pink-700/50',
  DEFENSE_EVASION:    'bg-cyan-900/50 text-cyan-300 border-cyan-700/50',
  EXFILTRATION:       'bg-blue-900/50 text-blue-300 border-blue-700/50',
}

const SEV_COLOR = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-blue-400',
}

const SEV_LABEL = {
  critical: 'Crítica',
  high:     'Alta',
  medium:   'Média',
  low:      'Baixa',
}

const SEV_DOT = {
  critical: 'bg-red-400',
  high:     'bg-orange-400',
  medium:   'bg-yellow-400',
  low:      'bg-blue-400',
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tacticBadge(tactic) {
  const cls = TACTIC_COLOR[tactic] || 'bg-dark-700 text-gray-400 border-dark-600'
  return (
    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${cls} leading-none`}>
      {TACTIC_LABEL[tactic] || tactic}
    </span>
  )
}

function sevBadge(severity) {
  const sev = (severity || '').toLowerCase()
  return (
    <span className={`flex items-center gap-1 text-[10px] font-semibold ${SEV_COLOR[sev] || 'text-gray-400'}`}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${SEV_DOT[sev] || 'bg-gray-500'}`} />
      {SEV_LABEL[sev] || severity}
    </span>
  )
}

// Compute canvas-level severity summary
function computeCanvasSeverity(steps) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  steps.forEach(s => {
    const k = (s.severity || '').toLowerCase()
    if (k in counts) counts[k]++
  })
  if (counts.critical > 0) return 'critical'
  if (counts.high > 0)     return 'high'
  if (counts.medium > 0)   return 'medium'
  return 'low'
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

// Library technique card (left panel)
function LibraryCard({ technique, onDragStart, onAdd, alreadyAdded }) {
  return (
    <div
      draggable
      onDragStart={e => onDragStart(e, technique)}
      className={`group relative flex flex-col gap-1.5 p-3 rounded-lg border cursor-grab active:cursor-grabbing transition-all select-none
        ${alreadyAdded
          ? 'border-dark-500 bg-dark-800/40 opacity-50'
          : 'border-dark-600 bg-dark-800 hover:border-orange-700/60 hover:bg-dark-700'
        }`}
      title={alreadyAdded ? 'Já adicionada ao playbook' : 'Arraste para o canvas ou clique em +'}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 mb-1">
            <span className="font-mono text-[10px] text-gray-500 flex-shrink-0">{technique.id}</span>
            {alreadyAdded && (
              <span className="text-[9px] text-green-500 font-bold">ADICIONADA</span>
            )}
          </div>
          <p className="text-xs font-semibold text-gray-200 leading-snug">{technique.name}</p>
        </div>
        <button
          onClick={() => !alreadyAdded && onAdd(technique)}
          disabled={alreadyAdded}
          className={`flex-shrink-0 w-6 h-6 rounded flex items-center justify-center transition
            ${alreadyAdded
              ? 'text-gray-600 cursor-not-allowed'
              : 'text-gray-500 hover:text-orange-400 hover:bg-orange-900/20'
            }`}
          title="Adicionar ao canvas"
        >
          <Plus className="w-3.5 h-3.5" />
        </button>
      </div>
      <div className="flex items-center gap-2 flex-wrap">
        {tacticBadge(technique.tactic)}
        {sevBadge(technique.severity)}
      </div>
      {/* Drag handle indicator */}
      <div className="absolute right-1.5 bottom-1.5 text-dark-500 group-hover:text-dark-400 transition pointer-events-none">
        <GripVertical className="w-3 h-3" />
      </div>
    </div>
  )
}

// Canvas step card (center panel)
function CanvasCard({ step, index, total, onRemove, onDragStart, onDragOver, onDrop, isDragOver }) {
  return (
    <div
      draggable
      onDragStart={e => onDragStart(e, index)}
      onDragOver={e => { e.preventDefault(); onDragOver(index) }}
      onDrop={e => { e.preventDefault(); onDrop(index) }}
      className={`group flex items-center gap-3 p-3 rounded-lg border transition-all select-none cursor-grab active:cursor-grabbing
        ${isDragOver
          ? 'border-orange-500 bg-orange-900/10 scale-[1.01] shadow-lg shadow-orange-900/20'
          : 'border-dark-600 bg-dark-800 hover:border-dark-500'
        }`}
    >
      {/* Step number */}
      <div className="flex-shrink-0 w-7 h-7 rounded-full bg-dark-700 border border-dark-500 flex items-center justify-center">
        <span className="text-xs font-bold text-gray-400">{index + 1}</span>
      </div>

      {/* Drag handle */}
      <GripVertical className="w-4 h-4 text-dark-500 group-hover:text-dark-400 flex-shrink-0 transition" />

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <span className="font-mono text-[10px] text-gray-500">{step.id}</span>
          {tacticBadge(step.tactic)}
          {sevBadge(step.severity)}
        </div>
        <p className="text-xs font-semibold text-gray-200 truncate">{step.name}</p>
      </div>

      {/* Remove */}
      <button
        onClick={() => onRemove(index)}
        className="flex-shrink-0 w-6 h-6 rounded flex items-center justify-center text-dark-500 hover:text-red-400 hover:bg-red-900/20 transition opacity-0 group-hover:opacity-100"
        title="Remover do playbook"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function PlaybookBuilder() {
  const toast = useToast()

  // Library state
  const [techniques, setTechniques] = useState([])
  const [loadingLib, setLoadingLib] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [tacticFilter, setTacticFilter] = useState('ALL')

  // Canvas state
  const [steps, setSteps] = useState([])
  const [dragOverIndex, setDragOverIndex] = useState(null)
  const canvasDragSrc = useRef(null)   // index being dragged within canvas
  const libDragTech = useRef(null)     // technique being dragged from library

  // Details / form state
  const [playbookName, setPlaybookName] = useState('')
  const [playbookDesc, setPlaybookDesc] = useState('')
  const [playbookSev, setPlaybookSev] = useState('high')
  const [saving, setSaving] = useState(false)
  const [showRunModal, setShowRunModal] = useState(false)
  const [runTarget, setRunTarget] = useState('')
  const [running, setRunning] = useState(false)

  // Load techniques from API, fall back to constants
  useEffect(() => {
    setLoadingLib(true)
    api.get('/api/bas/techniques')
      .then(res => {
        const data = res.data
        const list = Array.isArray(data) ? data : (data.techniques || [])
        if (list.length > 0) {
          setTechniques(list)
        } else {
          setTechniques(FALLBACK_TECHNIQUES)
        }
      })
      .catch(() => {
        setTechniques(FALLBACK_TECHNIQUES)
      })
      .finally(() => setLoadingLib(false))
  }, [])

  // Pre-fill severity selector when steps change
  useEffect(() => {
    if (steps.length > 0) {
      setPlaybookSev(computeCanvasSeverity(steps))
    }
  }, [steps])

  // ---------------------------------------------------------------------------
  // Filtering
  // ---------------------------------------------------------------------------

  const filteredTechniques = techniques.filter(t => {
    const q = searchQuery.toLowerCase().trim()
    const matchQuery = !q
      || t.id.toLowerCase().includes(q)
      || t.name.toLowerCase().includes(q)
    const matchTactic = tacticFilter === 'ALL' || t.tactic === tacticFilter
    return matchQuery && matchTactic
  })

  const addedIds = new Set(steps.map(s => s.id))

  // ---------------------------------------------------------------------------
  // Library drag handlers
  // ---------------------------------------------------------------------------

  const handleLibDragStart = useCallback((e, technique) => {
    libDragTech.current = technique
    canvasDragSrc.current = null
    e.dataTransfer.effectAllowed = 'copy'
    // Store as JSON for cross-panel detection
    e.dataTransfer.setData('application/penteia-technique', JSON.stringify(technique))
  }, [])

  // ---------------------------------------------------------------------------
  // Canvas drag handlers (reorder)
  // ---------------------------------------------------------------------------

  const handleCanvasDragStart = useCallback((e, index) => {
    canvasDragSrc.current = index
    libDragTech.current = null
    e.dataTransfer.effectAllowed = 'move'
    e.dataTransfer.setData('application/penteia-canvas-index', String(index))
  }, [])

  const handleCanvasDragOver = useCallback((targetIndex) => {
    setDragOverIndex(targetIndex)
  }, [])

  const handleCanvasDrop = useCallback((targetIndex) => {
    setDragOverIndex(null)

    // Drop from library
    if (libDragTech.current !== null) {
      const tech = libDragTech.current
      libDragTech.current = null
      if (addedIds.has(tech.id)) {
        toast('Técnica já está no playbook', 'warning')
        return
      }
      setSteps(prev => {
        const next = [...prev]
        next.splice(targetIndex + 1, 0, tech)
        return next
      })
      return
    }

    // Reorder within canvas
    const srcIndex = canvasDragSrc.current
    canvasDragSrc.current = null
    if (srcIndex === null || srcIndex === targetIndex) return
    setSteps(prev => {
      const next = [...prev]
      const [moved] = next.splice(srcIndex, 1)
      const insertAt = srcIndex < targetIndex ? targetIndex : targetIndex
      next.splice(insertAt, 0, moved)
      return next
    })
  }, [addedIds, toast])

  // Drop on the canvas background (empty area)
  const handleCanvasBgDragOver = useCallback((e) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'copy'
  }, [])

  const handleCanvasBgDrop = useCallback((e) => {
    e.preventDefault()
    setDragOverIndex(null)
    if (libDragTech.current !== null) {
      const tech = libDragTech.current
      libDragTech.current = null
      if (addedIds.has(tech.id)) {
        toast('Técnica já está no playbook', 'warning')
        return
      }
      setSteps(prev => [...prev, tech])
    }
    canvasDragSrc.current = null
  }, [addedIds, toast])

  // ---------------------------------------------------------------------------
  // Canvas mutations
  // ---------------------------------------------------------------------------

  const addTechnique = useCallback((technique) => {
    if (addedIds.has(technique.id)) {
      toast('Técnica já está no playbook', 'warning')
      return
    }
    setSteps(prev => [...prev, technique])
  }, [addedIds, toast])

  const removeStep = useCallback((index) => {
    setSteps(prev => prev.filter((_, i) => i !== index))
  }, [])

  const clearCanvas = useCallback(() => {
    if (steps.length === 0) return
    setSteps([])
    toast('Canvas limpo', 'info')
  }, [steps.length, toast])

  // ---------------------------------------------------------------------------
  // Save playbook
  // ---------------------------------------------------------------------------

  const handleSave = async () => {
    if (!playbookName.trim()) {
      toast('Digite um nome para o playbook', 'warning')
      return
    }
    if (steps.length === 0) {
      toast('Adicione ao menos uma técnica ao playbook', 'warning')
      return
    }
    setSaving(true)
    try {
      await api.post('/api/bas/playbooks', {
        name: playbookName.trim(),
        description: playbookDesc.trim(),
        severity: playbookSev.charAt(0).toUpperCase() + playbookSev.slice(1),
        technique_ids: steps.map(s => s.id),
        techniques: steps.length,
      })
      toast(`Playbook "${playbookName}" salvo com sucesso!`, 'success')
    } catch (err) {
      toast('Erro ao salvar: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setSaving(false)
    }
  }

  // ---------------------------------------------------------------------------
  // Run playbook
  // ---------------------------------------------------------------------------

  const handleRun = async () => {
    if (!runTarget.trim()) {
      toast('Informe o alvo', 'warning')
      return
    }
    if (!playbookName.trim()) {
      toast('Salve o playbook antes de executar', 'warning')
      return
    }
    setRunning(true)
    try {
      // First save to get an ID, then run
      const saveRes = await api.post('/api/bas/playbooks', {
        name: playbookName.trim(),
        description: playbookDesc.trim(),
        severity: playbookSev.charAt(0).toUpperCase() + playbookSev.slice(1),
        technique_ids: steps.map(s => s.id),
        techniques: steps.length,
      })
      const pbId = saveRes.data?.id || saveRes.data?.playbook?.id
      if (pbId) {
        await api.post('/api/bas/run-playbook', {
          playbook_id: pbId,
          target: runTarget.trim(),
          technique_ids: steps.map(s => s.id),
        })
      } else {
        // Fallback: try run-playbook directly without ID
        await api.post('/api/bas/run-playbook', {
          name: playbookName.trim(),
          target: runTarget.trim(),
          technique_ids: steps.map(s => s.id),
        })
      }
      setShowRunModal(false)
      setRunTarget('')
      toast('Simulação iniciada! Acompanhe em BAS > Histórico.', 'success')
    } catch (err) {
      toast('Erro ao executar: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setRunning(false)
    }
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="slide-in">
        <div className="flex items-center gap-3 mb-1">
          <BookOpen className="w-7 h-7 text-orange-500" />
          <h1 className="text-3xl font-bold text-gray-100">Playbook Builder</h1>
        </div>
        <p className="text-gray-400 text-sm">
          Construa playbooks de ataque arrastando e soltando técnicas MITRE ATT&amp;CK — incluindo ameaças brasileiras (Pix, DREX, Gov.br).
        </p>
      </div>

      {/* Warning */}
      <div className="flex items-start gap-2 px-4 py-3 rounded-lg bg-red-900/20 border border-red-700/40 text-red-400 text-xs">
        <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
        <span>
          <strong>Aviso Legal:</strong> Execute simulações apenas em sistemas com autorização explícita.
          Nunca use em ambientes de terceiros sem permissão.
        </span>
      </div>

      {/* Three-panel layout */}
      <div className="grid grid-cols-1 xl:grid-cols-[300px_1fr_280px] gap-4 min-h-[600px]">

        {/* ================================================================
            LEFT PANEL — Technique Library
        ================================================================ */}
        <div className="card-dark flex flex-col overflow-hidden">
          {/* Panel header */}
          <div className="p-4 border-b border-dark-600">
            <div className="flex items-center gap-2 mb-3">
              <Layers className="w-4 h-4 text-orange-400" />
              <h2 className="font-bold text-gray-100 text-sm">Biblioteca de Técnicas</h2>
              {!loadingLib && (
                <span className="ml-auto text-[10px] text-gray-500 bg-dark-700 px-1.5 py-0.5 rounded">
                  {filteredTechniques.length}/{techniques.length}
                </span>
              )}
            </div>

            {/* Search */}
            <div className="relative mb-2">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Buscar por ID ou nome..."
                className="input-dark w-full pl-8 text-xs"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Tactic filter */}
            <div className="relative">
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500 pointer-events-none" />
              <select
                value={tacticFilter}
                onChange={e => setTacticFilter(e.target.value)}
                className="select-dark w-full text-xs appearance-none pr-8"
              >
                <option value="ALL">Todas as Táticas</option>
                {ALL_TACTICS.map(t => (
                  <option key={t} value={t}>{TACTIC_LABEL[t] || t}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Technique list */}
          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            {loadingLib ? (
              <div className="flex items-center justify-center py-12">
                <Loader className="w-5 h-5 animate-spin text-orange-500" />
              </div>
            ) : filteredTechniques.length === 0 ? (
              <div className="text-center py-10">
                <Search className="w-8 h-8 text-dark-500 mx-auto mb-2" />
                <p className="text-gray-500 text-xs">Nenhuma técnica encontrada</p>
              </div>
            ) : (
              filteredTechniques.map(tech => (
                <LibraryCard
                  key={tech.id}
                  technique={tech}
                  onDragStart={handleLibDragStart}
                  onAdd={addTechnique}
                  alreadyAdded={addedIds.has(tech.id)}
                />
              ))
            )}
          </div>

          {/* Tip */}
          <div className="px-3 pb-3 pt-2 border-t border-dark-600">
            <p className="text-[10px] text-gray-600 flex items-center gap-1">
              <Info className="w-3 h-3 flex-shrink-0" />
              Arraste ou clique <Plus className="w-2.5 h-2.5 inline" /> para adicionar ao canvas
            </p>
          </div>
        </div>

        {/* ================================================================
            CENTER PANEL — Playbook Canvas
        ================================================================ */}
        <div className="card-dark flex flex-col overflow-hidden">
          {/* Panel header */}
          <div className="flex items-center justify-between p-4 border-b border-dark-600">
            <div className="flex items-center gap-2">
              <ClipboardList className="w-4 h-4 text-orange-400" />
              <h2 className="font-bold text-gray-100 text-sm">Canvas do Playbook</h2>
              {steps.length > 0 && (
                <span className="text-[10px] text-gray-500 bg-dark-700 px-1.5 py-0.5 rounded">
                  {steps.length} {steps.length === 1 ? 'passo' : 'passos'}
                </span>
              )}
            </div>
            {steps.length > 0 && (
              <button
                onClick={clearCanvas}
                className="text-xs text-gray-500 hover:text-red-400 flex items-center gap-1 transition"
              >
                <X className="w-3.5 h-3.5" /> Limpar
              </button>
            )}
          </div>

          {/* Canvas drop area */}
          <div
            className="flex-1 overflow-y-auto p-4"
            onDragOver={handleCanvasBgDragOver}
            onDrop={handleCanvasBgDrop}
            onDragLeave={() => setDragOverIndex(null)}
          >
            {steps.length === 0 ? (
              /* Empty state */
              <div
                className="flex flex-col items-center justify-center h-full min-h-[300px] border-2 border-dashed border-dark-600 rounded-xl text-center p-8 transition-colors"
                onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('border-orange-600/50', 'bg-orange-900/5') }}
                onDragLeave={e => { e.currentTarget.classList.remove('border-orange-600/50', 'bg-orange-900/5') }}
              >
                <div className="w-14 h-14 rounded-full bg-dark-700 flex items-center justify-center mb-4">
                  <Target className="w-7 h-7 text-dark-500" />
                </div>
                <p className="text-gray-500 font-medium mb-1">Canvas vazio</p>
                <p className="text-gray-600 text-sm">
                  Arraste técnicas aqui para construir seu playbook
                </p>
                <p className="text-gray-600 text-xs mt-1">ou clique em <Plus className="w-3 h-3 inline" /> na biblioteca</p>
              </div>
            ) : (
              /* Steps list */
              <div className="space-y-2">
                {steps.map((step, index) => (
                  <CanvasCard
                    key={`${step.id}-${index}`}
                    step={step}
                    index={index}
                    total={steps.length}
                    onRemove={removeStep}
                    onDragStart={handleCanvasDragStart}
                    onDragOver={handleCanvasDragOver}
                    onDrop={handleCanvasDrop}
                    isDragOver={dragOverIndex === index}
                  />
                ))}

                {/* Drop zone at end */}
                <div
                  className={`h-10 rounded-lg border-2 border-dashed flex items-center justify-center text-xs transition-colors
                    ${dragOverIndex === steps.length
                      ? 'border-orange-500 bg-orange-900/10 text-orange-400'
                      : 'border-dark-600 text-dark-600'
                    }`}
                  onDragOver={e => { e.preventDefault(); setDragOverIndex(steps.length) }}
                  onDrop={e => { e.preventDefault(); handleCanvasBgDrop(e) }}
                >
                  {dragOverIndex === steps.length ? 'Soltar aqui' : '+ Zona de soltura'}
                </div>
              </div>
            )}
          </div>

          {/* Canvas footer stats */}
          {steps.length > 0 && (
            <div className="p-3 border-t border-dark-600 bg-dark-800/50">
              <div className="flex items-center gap-3 flex-wrap text-xs">
                <span className="text-gray-500">{steps.length} técnica{steps.length !== 1 ? 's' : ''}</span>
                {['critical','high','medium','low'].map(sev => {
                  const count = steps.filter(s => (s.severity||'').toLowerCase() === sev).length
                  return count > 0 ? (
                    <span key={sev} className={`font-semibold ${SEV_COLOR[sev]}`}>
                      {count} {SEV_LABEL[sev]}
                    </span>
                  ) : null
                })}
                <span className="ml-auto text-gray-600 text-[10px]">
                  Arraste entre passos para reordenar
                </span>
              </div>
            </div>
          )}
        </div>

        {/* ================================================================
            RIGHT PANEL — Playbook Details
        ================================================================ */}
        <div className="card-dark flex flex-col">
          <div className="p-4 border-b border-dark-600">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-orange-400" />
              <h2 className="font-bold text-gray-100 text-sm">Detalhes do Playbook</h2>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {/* Name */}
            <div>
              <label className="block text-xs font-medium text-gray-300 mb-1.5">
                Nome do Playbook <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={playbookName}
                onChange={e => setPlaybookName(e.target.value)}
                placeholder="ex: Ransomware Full-Chain"
                className="input-dark w-full text-sm"
                maxLength={120}
              />
            </div>

            {/* Description */}
            <div>
              <label className="block text-xs font-medium text-gray-300 mb-1.5">
                Descrição <span className="text-gray-500 font-normal">(opcional)</span>
              </label>
              <textarea
                value={playbookDesc}
                onChange={e => setPlaybookDesc(e.target.value)}
                placeholder="Descreva o objetivo, escopo e contexto deste playbook..."
                rows={4}
                className="input-dark w-full text-xs resize-none"
                maxLength={500}
              />
              {playbookDesc.length > 400 && (
                <p className="text-[10px] text-gray-600 text-right mt-0.5">{playbookDesc.length}/500</p>
              )}
            </div>

            {/* Severity */}
            <div>
              <label className="block text-xs font-medium text-gray-300 mb-1.5">
                Severidade Geral
              </label>
              <div className="grid grid-cols-2 gap-1.5">
                {['critical','high','medium','low'].map(sev => (
                  <button
                    key={sev}
                    onClick={() => setPlaybookSev(sev)}
                    className={`flex items-center gap-1.5 px-2.5 py-2 rounded border text-xs font-semibold transition
                      ${playbookSev === sev
                        ? `border-current ${SEV_COLOR[sev]} bg-dark-700`
                        : 'border-dark-600 text-gray-500 hover:border-dark-500 hover:text-gray-400'
                      }`}
                  >
                    <span className={`w-2 h-2 rounded-full flex-shrink-0 ${SEV_DOT[sev]}`} />
                    {SEV_LABEL[sev]}
                  </button>
                ))}
              </div>
            </div>

            {/* Summary */}
            {steps.length > 0 && (
              <div className="rounded-lg bg-dark-700 border border-dark-600 p-3 space-y-2 text-xs">
                <p className="font-semibold text-gray-300 mb-2">Resumo</p>
                <div className="flex justify-between text-gray-400">
                  <span>Total de passos</span>
                  <span className="font-bold text-gray-200">{steps.length}</span>
                </div>
                {/* Tactic breakdown */}
                {[...new Set(steps.map(s => s.tactic))].map(tactic => {
                  const count = steps.filter(s => s.tactic === tactic).length
                  return (
                    <div key={tactic} className="flex justify-between text-gray-500">
                      <span>{TACTIC_LABEL[tactic] || tactic}</span>
                      <span>{count}</span>
                    </div>
                  )
                })}
                <div className="border-t border-dark-600 pt-2 mt-1">
                  <div className="flex flex-wrap gap-1">
                    {steps.map(s => (
                      <span key={s.id} className="font-mono text-[9px] px-1 py-0.5 rounded bg-dark-600 text-gray-500">
                        {s.id}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Validation hints */}
            {(steps.length === 0 || !playbookName.trim()) && (
              <div className="rounded-lg bg-blue-900/10 border border-blue-800/30 p-3 text-xs text-blue-300/70 space-y-1">
                <p className="font-semibold text-blue-400 mb-1 flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5" /> Para salvar o playbook:
                </p>
                {!playbookName.trim() && <p>• Defina um nome</p>}
                {steps.length === 0 && <p>• Adicione ao menos 1 técnica</p>}
              </div>
            )}
          </div>

          {/* Action buttons */}
          <div className="p-4 border-t border-dark-600 space-y-2">
            <button
              onClick={handleSave}
              disabled={saving || !playbookName.trim() || steps.length === 0}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-orange-700 hover:bg-orange-600 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg font-semibold text-sm transition"
            >
              {saving ? (
                <><Loader className="w-4 h-4 animate-spin" /> Salvando...</>
              ) : (
                <><Save className="w-4 h-4" /> Salvar Playbook</>
              )}
            </button>

            <button
              onClick={() => {
                if (!playbookName.trim()) { toast('Defina um nome antes de executar', 'warning'); return }
                if (steps.length === 0) { toast('Adicione técnicas ao playbook', 'warning'); return }
                setShowRunModal(true)
              }}
              disabled={running}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-red-800 hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg font-semibold text-sm transition"
            >
              <Zap className="w-4 h-4" />
              Executar Agora
            </button>
          </div>
        </div>
      </div>

      {/* ================================================================
          RUN MODAL
      ================================================================ */}
      {showRunModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="card-dark w-full max-w-md">
            <div className="flex justify-between items-center p-5 border-b border-dark-600">
              <div>
                <h2 className="text-lg font-bold text-gray-100 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-red-400" /> Executar Playbook
                </h2>
                <p className="text-xs text-gray-400 mt-0.5">
                  Playbook: <span className="text-orange-400">{playbookName}</span>
                  <span className="text-gray-600 mx-1">—</span>
                  {steps.length} técnica{steps.length !== 1 ? 's' : ''}
                </p>
              </div>
              <button
                onClick={() => { setShowRunModal(false); setRunTarget('') }}
                className="text-gray-500 hover:text-gray-100 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Host / IP Alvo <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={runTarget}
                  onChange={e => setRunTarget(e.target.value)}
                  placeholder="ex: 192.168.1.10 ou servidor.local"
                  className="input-dark w-full"
                  autoFocus
                  onKeyDown={e => e.key === 'Enter' && handleRun()}
                />
              </div>

              {/* Technique preview */}
              <div className="rounded-lg bg-dark-700 border border-dark-600 p-3 max-h-48 overflow-y-auto">
                <p className="text-xs font-semibold text-gray-400 mb-2">
                  Técnicas que serão executadas ({steps.length}):
                </p>
                <div className="space-y-1">
                  {steps.map((s, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <span className="text-gray-600 w-4 text-right flex-shrink-0">{i + 1}.</span>
                      <span className="font-mono text-gray-500 text-[10px] flex-shrink-0">{s.id}</span>
                      <span className="text-gray-300 truncate">{s.name}</span>
                      {sevBadge(s.severity)}
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex items-start gap-2 p-3 rounded bg-red-900/20 border border-red-700/40 text-xs text-red-400">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>Execute apenas em sistemas com autorização explícita para teste.</span>
              </div>
            </div>

            <div className="flex justify-end gap-2 p-5 border-t border-dark-600">
              <button
                onClick={() => { setShowRunModal(false); setRunTarget('') }}
                className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded-lg text-sm transition"
              >
                Cancelar
              </button>
              <button
                onClick={handleRun}
                disabled={running || !runTarget.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-semibold transition"
              >
                {running ? (
                  <><Loader className="w-4 h-4 animate-spin" /> Executando...</>
                ) : (
                  <><Play className="w-4 h-4" /> Iniciar Simulação</>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
