import React, { useState, useEffect, useCallback } from 'react'
import {
  Terminal, Shield, Play, Eye, AlertTriangle, FileText, Cpu, Network,
  Key, Loader, ChevronDown, CheckCircle,
} from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

// ─── Constants ───────────────────────────────────────────────────────────────

const MODES = [
  {
    id: 'simulated',
    label: 'Simulado',
    labelEn: 'Simulated',
    icon: Shield,
    color: 'text-green-400',
    border: 'border-green-600',
    bg: 'bg-green-900/20',
    activeBg: 'bg-green-900/30',
    badge: 'bg-green-900/50 text-green-300 border-green-700/50',
    description: 'Execução segura em ambiente isolado — sem impacto real',
  },
  {
    id: 'observation',
    label: 'Observação',
    labelEn: 'Observation',
    icon: Eye,
    color: 'text-blue-400',
    border: 'border-blue-600',
    bg: 'bg-blue-900/20',
    activeBg: 'bg-blue-900/30',
    badge: 'bg-blue-900/50 text-blue-300 border-blue-700/50',
    description: 'Read-only — coleta dados sem executar ações destrutivas',
  },
  {
    id: 'authorized',
    label: 'Autorizado',
    labelEn: 'Authorized',
    icon: Key,
    color: 'text-red-400',
    border: 'border-red-600',
    bg: 'bg-red-900/20',
    activeBg: 'bg-red-900/30',
    badge: 'bg-red-900/50 text-red-300 border-red-700/50',
    description: 'Execução real com impacto — requer token de autorização',
  },
]

const TECHNIQUES = [
  {
    id: 'T1003',
    name: 'Credential Dumping',
    nameShort: 'Cred. Dump',
    tactic: 'Credential Access',
    icon: Key,
    color: 'text-red-400',
    iconBg: 'bg-red-900/30',
    border: 'border-red-800/40',
    hoverBorder: 'hover:border-red-600/60',
    description: 'Extrai credenciais da memória, SAM, NTDS ou LSA Secrets',
    risk: 'critical',
  },
  {
    id: 'T1082',
    name: 'System Discovery',
    nameShort: 'Discovery',
    tactic: 'Discovery',
    icon: Cpu,
    color: 'text-blue-400',
    iconBg: 'bg-blue-900/30',
    border: 'border-blue-800/40',
    hoverBorder: 'hover:border-blue-600/60',
    description: 'Enumera hostname, OS, arquitetura, usuários e processos',
    risk: 'low',
  },
  {
    id: 'T1547',
    name: 'Persistence',
    nameShort: 'Persistence',
    tactic: 'Persistence',
    icon: Shield,
    color: 'text-orange-400',
    iconBg: 'bg-orange-900/30',
    border: 'border-orange-800/40',
    hoverBorder: 'hover:border-orange-600/60',
    description: 'Cria mecanismos para sobreviver a reboots via registro e serviços',
    risk: 'high',
  },
  {
    id: 'T1021',
    name: 'Lateral Movement',
    nameShort: 'Lateral Mov.',
    tactic: 'Lateral Movement',
    icon: Network,
    color: 'text-purple-400',
    iconBg: 'bg-purple-900/30',
    border: 'border-purple-800/40',
    hoverBorder: 'hover:border-purple-600/60',
    description: 'Movimenta-se lateralmente via RDP, SMB, WMI, PsExec',
    risk: 'high',
  },
  {
    id: 'T1041',
    name: 'Exfiltration',
    nameShort: 'Exfiltration',
    tactic: 'Exfiltration',
    icon: FileText,
    color: 'text-yellow-400',
    iconBg: 'bg-yellow-900/30',
    border: 'border-yellow-800/40',
    hoverBorder: 'hover:border-yellow-600/60',
    description: 'Exfiltra dados via C2, DNS tunneling ou canais encobertos',
    risk: 'critical',
  },
  {
    id: 'T1059',
    name: 'Execution',
    nameShort: 'Execution',
    tactic: 'Execution',
    icon: Terminal,
    color: 'text-cyan-400',
    iconBg: 'bg-cyan-900/30',
    border: 'border-cyan-800/40',
    hoverBorder: 'hover:border-cyan-600/60',
    description: 'Executa comandos via PowerShell, cmd, bash ou scripts',
    risk: 'medium',
  },
]

const RISK_BADGE = {
  critical: 'bg-red-900/60 text-red-300 border border-red-700/40',
  high:     'bg-orange-900/60 text-orange-300 border border-orange-700/40',
  medium:   'bg-yellow-900/60 text-yellow-300 border border-yellow-700/40',
  low:      'bg-blue-900/60 text-blue-300 border border-blue-700/40',
}

const RISK_LABEL = { critical: 'CRÍTICO', high: 'ALTO', medium: 'MÉDIO', low: 'BAIXO' }

// ─── JSON Highlighter ─────────────────────────────────────────────────────────

function JsonHighlight({ data }) {
  const json = JSON.stringify(data, null, 2)

  const highlighted = json
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g, (match) => {
      let cls = 'text-purple-300' // number
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? 'text-cyan-300' : 'text-green-300'
      } else if (/true|false/.test(match)) {
        cls = 'text-yellow-300'
      } else if (/null/.test(match)) {
        cls = 'text-gray-500'
      }
      return `<span class="${cls}">${match}</span>`
    })

  return (
    <pre
      className="text-xs font-mono leading-relaxed overflow-auto text-gray-300 whitespace-pre-wrap break-words"
      dangerouslySetInnerHTML={{ __html: highlighted }}
    />
  )
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function ModeBadge({ mode, real }) {
  if (real) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold tracking-wide bg-red-900/70 text-red-300 border border-red-600/60 shadow-lg shadow-red-900/30">
        <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
        Real Execution&#x2122;
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold tracking-wide bg-green-900/50 text-green-300 border border-green-700/50">
      <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
      Simulado
    </span>
  )
}

function EvidenceSection({ title, icon: Icon, children, colorClass = 'text-cyan-400' }) {
  const [open, setOpen] = useState(true)
  return (
    <div className="border border-dark-600 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 bg-dark-700/80 hover:bg-dark-700 transition"
      >
        <div className="flex items-center gap-2">
          <Icon className={`w-4 h-4 ${colorClass}`} />
          <span className="text-sm font-semibold text-gray-200">{title}</span>
        </div>
        <ChevronDown className={`w-4 h-4 text-gray-500 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="p-4 bg-dark-800/60">
          {children}
        </div>
      )}
    </div>
  )
}

function KVRow({ label, value, mono = false }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1.5 border-b border-dark-600/50 last:border-0">
      <span className="text-xs text-gray-500 flex-shrink-0 w-32">{label}</span>
      <span className={`text-xs text-gray-200 flex-1 text-right ${mono ? 'font-mono' : ''}`}>{value ?? '—'}</span>
    </div>
  )
}

function HistoryRow({ item, selected, onClick }) {
  const tech = TECHNIQUES.find(t => t.id === item.technique_id)
  const TechIcon = tech?.icon ?? Terminal
  return (
    <button
      onClick={onClick}
      className={`w-full text-left flex items-center gap-3 p-3 rounded-lg border transition ${
        selected
          ? 'border-cyan-600/60 bg-cyan-900/20'
          : 'border-dark-600 bg-dark-700/50 hover:border-dark-500 hover:bg-dark-700'
      }`}
    >
      <div className={`p-1.5 rounded ${tech?.iconBg ?? 'bg-dark-600'}`}>
        <TechIcon className={`w-3.5 h-3.5 ${tech?.color ?? 'text-gray-400'}`} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-semibold text-gray-200 truncate">{item.technique_id} — {item.target || 'N/A'}</p>
        <p className="text-[10px] text-gray-500 truncate">{item.mode} · {item.timestamp ? new Date(item.timestamp).toLocaleString('pt-BR') : '—'}</p>
      </div>
      {item.status === 'success' ? (
        <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
      ) : (
        <span className="w-2 h-2 rounded-full bg-red-500 flex-shrink-0" />
      )}
    </button>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function RealExecution() {
  const toast = useToast()

  // Mode
  const [mode, setMode] = useState('simulated')
  const [authToken, setAuthToken] = useState('')

  // Technique selection
  const [selectedTech, setSelectedTech] = useState(null)
  const [playbookTechs, setPlaybookTechs] = useState([])

  // Target
  const [target, setTarget] = useState('')

  // Execution state
  const [executing, setExecuting] = useState(false)
  const [executingPlaybook, setExecutingPlaybook] = useState(false)

  // Evidence panel
  const [evidence, setEvidence] = useState(null)

  // History
  const [history, setHistory] = useState([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const [selectedHistoryId, setSelectedHistoryId] = useState(null)
  const [historyEvidenceLoading, setHistoryEvidenceLoading] = useState(false)

  const currentMode = MODES.find(m => m.id === mode)
  const isReal = mode === 'authorized'

  // ── Data fetching ────────────────────────────────────────────────────────

  const fetchHistory = useCallback(async () => {
    try {
      const res = await api.get('/api/execution/history')
      setHistory(res.data.history ?? res.data ?? [])
    } catch (err) {
      console.error('Erro ao buscar histórico:', err)
    } finally {
      setHistoryLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchHistory()
  }, [fetchHistory])

  // ── Handlers ─────────────────────────────────────────────────────────────

  const handleExecuteTechnique = async () => {
    if (!selectedTech) {
      toast('Selecione uma técnica para executar', 'warning')
      return
    }
    if (!target.trim()) {
      toast('Informe o alvo (IP, hostname ou URL)', 'warning')
      return
    }
    if (mode === 'authorized' && !authToken.trim()) {
      toast('Insira o token de autorização para modo Real', 'warning')
      return
    }

    setExecuting(true)
    setEvidence(null)

    try {
      const payload = {
        technique_id: selectedTech,
        target: target.trim(),
        mode,
        ...(mode === 'authorized' && { auth_token: authToken.trim() }),
      }
      const res = await api.post('/api/execution/technique', payload)
      setEvidence(res.data)
      toast('Técnica executada com sucesso', 'success')
      await fetchHistory()
    } catch (err) {
      const msg = err.response?.data?.detail || err.message
      toast('Erro na execução: ' + msg, 'error')
    } finally {
      setExecuting(false)
    }
  }

  const handleExecutePlaybook = async () => {
    if (playbookTechs.length === 0) {
      toast('Selecione ao menos uma técnica para o playbook', 'warning')
      return
    }
    if (!target.trim()) {
      toast('Informe o alvo (IP, hostname ou URL)', 'warning')
      return
    }
    if (mode === 'authorized' && !authToken.trim()) {
      toast('Insira o token de autorização para modo Real', 'warning')
      return
    }

    setExecutingPlaybook(true)
    setEvidence(null)

    try {
      const payload = {
        techniques: playbookTechs,
        target: target.trim(),
        mode,
        ...(mode === 'authorized' && { auth_token: authToken.trim() }),
      }
      const res = await api.post('/api/execution/playbook', payload)
      setEvidence(res.data)
      toast(`Playbook executado — ${playbookTechs.length} técnicas`, 'success')
      setPlaybookTechs([])
      await fetchHistory()
    } catch (err) {
      const msg = err.response?.data?.detail || err.message
      toast('Erro no playbook: ' + msg, 'error')
    } finally {
      setExecutingPlaybook(false)
    }
  }

  const handleHistoryClick = async (item) => {
    setSelectedHistoryId(item.id)
    setHistoryEvidenceLoading(true)
    setEvidence(null)
    try {
      const res = await api.get(`/api/execution/evidence/${item.id}`)
      setEvidence(res.data)
    } catch (err) {
      toast('Erro ao carregar evidência: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setHistoryEvidenceLoading(false)
    }
  }

  const togglePlaybookTech = (techId) => {
    setPlaybookTechs(prev =>
      prev.includes(techId) ? prev.filter(t => t !== techId) : [...prev, techId]
    )
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-8">

      {/* Header */}
      <div className="slide-in flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 rounded-lg bg-red-900/30 border border-red-800/40">
              <Terminal className="w-6 h-6 text-red-400" />
            </div>
            <h1 className="text-4xl font-bold text-gray-100">Real Execution Engine</h1>
          </div>
          <p className="text-gray-400 max-w-2xl">
            Motor de execução real de técnicas MITRE ATT&amp;CK — o diferencial que separa o PenteIA das
            plataformas puramente de simulação. Coleta evidências forenses reais do sistema alvo.
          </p>
        </div>
        <ModeBadge real={isReal} />
      </div>

      {/* Authorized warning banner */}
      {mode === 'authorized' && (
        <div className="flex items-start gap-3 p-4 rounded-lg bg-red-950/40 border border-red-600/60 shadow-lg shadow-red-900/20">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-red-300 font-bold text-sm mb-1">
              ATENÇÃO: Requer autorização de pentest documentada
            </p>
            <p className="text-red-400/80 text-xs leading-relaxed">
              O modo Autorizado executa técnicas com impacto real no sistema alvo. Você deve possuir
              autorização formal e documentada (Termo de Autorização de Teste de Intrusão) antes de
              prosseguir. O uso sem autorização é crime (Lei 12.737/2012 — Lei Carolina Dieckmann).
            </p>
          </div>
        </div>
      )}

      {/* ─── Mode Selector ─────────────────────────────────────────────── */}
      <div className="card-dark p-6">
        <h2 className="text-lg font-bold text-gray-100 mb-1">Modo de Execução</h2>
        <p className="text-gray-500 text-sm mb-4">Selecione o nível de impacto da execução</p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {MODES.map((m) => {
            const MIcon = m.icon
            const active = mode === m.id
            return (
              <button
                key={m.id}
                onClick={() => setMode(m.id)}
                className={`relative text-left p-4 rounded-lg border-2 transition-all ${
                  active
                    ? `${m.border} ${m.activeBg} shadow-md`
                    : 'border-dark-600 bg-dark-700/50 hover:border-dark-500 hover:bg-dark-700'
                }`}
              >
                {active && (
                  <span className="absolute top-3 right-3">
                    <CheckCircle className={`w-4 h-4 ${m.color}`} />
                  </span>
                )}
                <div className="flex items-center gap-2 mb-2">
                  <MIcon className={`w-5 h-5 ${active ? m.color : 'text-gray-500'}`} />
                  <span className={`font-bold text-sm ${active ? 'text-gray-100' : 'text-gray-400'}`}>
                    {m.label}
                  </span>
                </div>
                <p className={`text-xs leading-relaxed ${active ? 'text-gray-300' : 'text-gray-600'}`}>
                  {m.description}
                </p>
                {active && (
                  <span className={`mt-3 inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full border ${m.badge}`}>
                    {m.labelEn.toUpperCase()}
                  </span>
                )}
              </button>
            )
          })}
        </div>

        {/* Auth token input for authorized mode */}
        {mode === 'authorized' && (
          <div className="mt-4 flex items-center gap-3 p-3 bg-red-950/30 border border-red-800/40 rounded-lg">
            <Key className="w-4 h-4 text-red-400 flex-shrink-0" />
            <input
              type="password"
              value={authToken}
              onChange={e => setAuthToken(e.target.value)}
              placeholder="Token de autorização de pentest..."
              className="flex-1 bg-transparent border-0 outline-none text-sm text-red-200 placeholder-red-800 font-mono"
            />
            {authToken && (
              <CheckCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
            )}
          </div>
        )}
      </div>

      {/* ─── Technique Grid + Target + Execution ───────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

        {/* Technique Selector */}
        <div className="xl:col-span-2 card-dark p-6">
          <div className="flex items-center justify-between mb-1">
            <h2 className="text-lg font-bold text-gray-100">Técnicas MITRE ATT&amp;CK</h2>
            <div className="flex items-center gap-2">
              {playbookTechs.length > 0 && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-900/40 text-cyan-300 border border-cyan-800/40">
                  {playbookTechs.length} no playbook
                </span>
              )}
            </div>
          </div>
          <p className="text-gray-500 text-sm mb-4">
            Clique para selecionar a técnica principal — ou marque várias para o Playbook
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {TECHNIQUES.map((tech) => {
              const TIcon = tech.icon
              const isSelected = selectedTech === tech.id
              const inPlaybook = playbookTechs.includes(tech.id)
              return (
                <div
                  key={tech.id}
                  className={`relative rounded-lg border-2 p-4 transition-all cursor-pointer group ${
                    isSelected
                      ? `${tech.border.replace('/40', '')} ${tech.iconBg}`
                      : inPlaybook
                        ? 'border-cyan-700/60 bg-cyan-900/10'
                        : `border-dark-600 bg-dark-700/50 ${tech.hoverBorder} hover:bg-dark-700`
                  }`}
                  onClick={() => setSelectedTech(isSelected ? null : tech.id)}
                >
                  {/* Playbook toggle */}
                  <button
                    onClick={e => { e.stopPropagation(); togglePlaybookTech(tech.id) }}
                    className={`absolute top-2 right-2 w-5 h-5 rounded border flex items-center justify-center transition ${
                      inPlaybook
                        ? 'bg-cyan-600 border-cyan-500 text-white'
                        : 'border-dark-500 text-transparent group-hover:border-dark-400'
                    }`}
                    title="Adicionar ao playbook"
                  >
                    {inPlaybook && <CheckCircle className="w-3 h-3" />}
                  </button>

                  <div className={`inline-flex p-2 rounded-lg mb-3 ${tech.iconBg}`}>
                    <TIcon className={`w-5 h-5 ${tech.color}`} />
                  </div>

                  <div className="mb-2">
                    <p className="text-xs font-mono text-gray-500 mb-0.5">{tech.id}</p>
                    <p className="text-sm font-bold text-gray-100 leading-tight">{tech.name}</p>
                    <p className="text-[10px] text-gray-500 mt-0.5">{tech.tactic}</p>
                  </div>

                  <p className="text-xs text-gray-500 leading-relaxed mb-3">{tech.description}</p>

                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${RISK_BADGE[tech.risk]}`}>
                    {RISK_LABEL[tech.risk]}
                  </span>

                  {isSelected && (
                    <div className="absolute inset-0 rounded-lg ring-2 ring-inset ring-white/10 pointer-events-none" />
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Target + Execute */}
        <div className="space-y-4">

          {/* Target */}
          <div className="card-dark p-5">
            <h2 className="text-sm font-bold text-gray-100 mb-3 flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              Alvo
            </h2>
            <input
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder="IP, hostname ou URL..."
              className="input-dark w-full font-mono text-sm"
              onKeyDown={e => e.key === 'Enter' && !executing && handleExecuteTechnique()}
            />
            <p className="text-[10px] text-gray-600 mt-2">Ex: 192.168.1.10, server.local, https://target.com</p>
          </div>

          {/* Execute Technique */}
          <div className="card-dark p-5 space-y-3">
            <h2 className="text-sm font-bold text-gray-100 flex items-center gap-2">
              <Play className="w-4 h-4 text-green-400" />
              Executar Técnica
            </h2>

            {selectedTech ? (
              <div className="flex items-center gap-2 p-2 rounded bg-dark-700 border border-dark-600 text-xs">
                {(() => {
                  const t = TECHNIQUES.find(t => t.id === selectedTech)
                  const TI = t?.icon ?? Terminal
                  return (
                    <>
                      <TI className={`w-3.5 h-3.5 ${t?.color ?? 'text-gray-400'}`} />
                      <span className="font-mono text-gray-400">{selectedTech}</span>
                      <span className="text-gray-300">{t?.name}</span>
                    </>
                  )
                })()}
              </div>
            ) : (
              <p className="text-xs text-gray-600 italic">Nenhuma técnica selecionada</p>
            )}

            <button
              onClick={handleExecuteTechnique}
              disabled={executing || !selectedTech || !target.trim()}
              className={`w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg font-semibold text-sm transition ${
                isReal
                  ? 'bg-red-700 hover:bg-red-600 text-white disabled:opacity-40 disabled:cursor-not-allowed'
                  : 'bg-green-800 hover:bg-green-700 text-white disabled:opacity-40 disabled:cursor-not-allowed'
              }`}
            >
              {executing ? (
                <><Loader className="w-4 h-4 animate-spin" /> Executando...</>
              ) : (
                <><Play className="w-4 h-4" /> Executar Técnica</>
              )}
            </button>
          </div>

          {/* Playbook Mode */}
          <div className="card-dark p-5 space-y-3">
            <h2 className="text-sm font-bold text-gray-100 flex items-center gap-2">
              <FileText className="w-4 h-4 text-purple-400" />
              Modo Playbook
            </h2>
            <p className="text-xs text-gray-500">
              Marque o checkbox nas técnicas acima para montar seu playbook sequencial.
            </p>

            {playbookTechs.length > 0 ? (
              <div className="space-y-1">
                {playbookTechs.map((id, idx) => {
                  const t = TECHNIQUES.find(t => t.id === id)
                  const TI = t?.icon ?? Terminal
                  return (
                    <div key={id} className="flex items-center gap-2 text-xs text-gray-400">
                      <span className="text-gray-600 w-4 text-right font-mono">{idx + 1}.</span>
                      <TI className={`w-3 h-3 ${t?.color ?? ''}`} />
                      <span className="font-mono text-gray-500">{id}</span>
                      <span className="text-gray-400 truncate">{t?.nameShort}</span>
                    </div>
                  )
                })}
              </div>
            ) : (
              <p className="text-xs text-gray-600 italic">Nenhuma técnica no playbook</p>
            )}

            <button
              onClick={handleExecutePlaybook}
              disabled={executingPlaybook || playbookTechs.length === 0 || !target.trim()}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg font-semibold text-sm bg-purple-800 hover:bg-purple-700 text-white transition disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {executingPlaybook ? (
                <><Loader className="w-4 h-4 animate-spin" /> Executando Playbook...</>
              ) : (
                <><Play className="w-4 h-4" /> Executar Playbook ({playbookTechs.length})</>
              )}
            </button>
          </div>

        </div>
      </div>

      {/* ─── Evidence Panel ─────────────────────────────────────────────── */}
      {(evidence || historyEvidenceLoading) && (
        <div className="card-dark p-6 border border-cyan-800/30 shadow-xl shadow-cyan-900/10">
          <div className="flex items-center justify-between mb-5">
            <h2 className="text-xl font-bold text-gray-100 flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-900/30 border border-cyan-800/40">
                <FileText className="w-5 h-5 text-cyan-400" />
              </div>
              Evidências Forenses
              <ModeBadge real={isReal} />
            </h2>
            {evidence?.execution_id && (
              <span className="font-mono text-[10px] text-gray-600">
                ID: {evidence.execution_id}
              </span>
            )}
          </div>

          {historyEvidenceLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader className="w-6 h-6 text-cyan-400 animate-spin" />
              <span className="ml-3 text-gray-400 text-sm">Carregando evidências...</span>
            </div>
          ) : (
            <div className="space-y-4">

              {/* System Context */}
              {evidence?.system_context && (
                <EvidenceSection title="Contexto do Sistema" icon={Cpu} colorClass="text-cyan-400">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <KVRow label="Hostname" value={evidence.system_context.hostname} mono />
                      <KVRow label="OS" value={evidence.system_context.os} />
                      <KVRow label="Arquitetura" value={evidence.system_context.arch} mono />
                      <KVRow label="Versão" value={evidence.system_context.version} />
                      <KVRow label="Usuário" value={evidence.system_context.current_user} mono />
                      <KVRow label="IP" value={evidence.system_context.ip_address} mono />
                    </div>
                    <div>
                      <KVRow label="Domínio" value={evidence.system_context.domain} mono />
                      <KVRow label="Uptime" value={evidence.system_context.uptime} />
                      <KVRow label="Privilegiado" value={evidence.system_context.is_admin ? 'Sim' : 'Não'} />
                      <KVRow label="AV Detectado" value={evidence.system_context.antivirus} />
                      <KVRow label="Firewall" value={evidence.system_context.firewall_status} />
                    </div>
                  </div>
                </EvidenceSection>
              )}

              {/* Technique Evidence + Artifacts */}
              {evidence?.technique_evidence && (
                <EvidenceSection title="Evidências da Técnica" icon={Shield} colorClass="text-orange-400">
                  <div className="space-y-4">
                    <div>
                      <KVRow label="Técnica" value={`${evidence.technique_evidence.technique_id} — ${evidence.technique_evidence.technique_name}`} />
                      <KVRow label="Status" value={evidence.technique_evidence.status} />
                      <KVRow label="Duração" value={evidence.technique_evidence.duration_ms != null ? `${evidence.technique_evidence.duration_ms}ms` : undefined} />
                      <KVRow label="Exit Code" value={evidence.technique_evidence.exit_code?.toString()} mono />
                    </div>

                    {/* Artifacts */}
                    {evidence.technique_evidence.artifacts?.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">Artefatos Coletados</p>
                        <div className="space-y-2">
                          {evidence.technique_evidence.artifacts.map((artifact, i) => (
                            <div key={i} className="rounded-lg bg-dark-900/60 border border-dark-600 p-3">
                              <div className="flex items-center gap-2 mb-2">
                                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-orange-900/40 text-orange-300 border border-orange-800/40 font-mono">
                                  {artifact.type ?? 'artifact'}
                                </span>
                                {artifact.name && (
                                  <span className="text-xs font-mono text-gray-400">{artifact.name}</span>
                                )}
                              </div>
                              {artifact.content && (
                                <pre className="text-xs font-mono text-gray-300 whitespace-pre-wrap break-words leading-relaxed max-h-48 overflow-auto">
                                  {typeof artifact.content === 'string'
                                    ? artifact.content
                                    : JSON.stringify(artifact.content, null, 2)}
                                </pre>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Raw output */}
                    {evidence.technique_evidence.output && (
                      <div>
                        <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">Output Bruto</p>
                        <div className="rounded-lg bg-dark-900/80 border border-dark-600 p-3 max-h-64 overflow-auto">
                          <pre className="text-xs font-mono text-green-300 whitespace-pre-wrap break-words leading-relaxed">
                            {evidence.technique_evidence.output}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                </EvidenceSection>
              )}

              {/* Process List */}
              {evidence?.process_list?.length > 0 && (
                <EvidenceSection title={`Lista de Processos (${evidence.process_list.length})`} icon={Cpu} colorClass="text-purple-400">
                  <div className="overflow-auto max-h-64">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-dark-600">
                          <th className="text-left py-2 pr-4 text-gray-500 font-semibold w-20">PID</th>
                          <th className="text-left py-2 pr-4 text-gray-500 font-semibold">Nome</th>
                          <th className="text-left py-2 pr-4 text-gray-500 font-semibold hidden sm:table-cell">Usuário</th>
                          <th className="text-right py-2 text-gray-500 font-semibold hidden md:table-cell">CPU%</th>
                          <th className="text-right py-2 pl-4 text-gray-500 font-semibold hidden md:table-cell">MEM (MB)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {evidence.process_list.map((proc, i) => (
                          <tr key={i} className="border-b border-dark-600/40 hover:bg-dark-700/30 transition">
                            <td className="py-1.5 pr-4 font-mono text-gray-500">{proc.pid}</td>
                            <td className="py-1.5 pr-4 font-mono text-gray-200">{proc.name}</td>
                            <td className="py-1.5 pr-4 text-gray-400 hidden sm:table-cell">{proc.user ?? '—'}</td>
                            <td className="py-1.5 text-right text-gray-400 hidden md:table-cell">
                              {proc.cpu_percent != null ? `${proc.cpu_percent.toFixed(1)}%` : '—'}
                            </td>
                            <td className="py-1.5 pl-4 text-right font-mono text-gray-400 hidden md:table-cell">
                              {proc.memory_mb != null ? proc.memory_mb.toFixed(1) : '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </EvidenceSection>
              )}

              {/* Network Connections */}
              {evidence?.network_connections?.length > 0 && (
                <EvidenceSection title={`Conexões de Rede (${evidence.network_connections.length})`} icon={Network} colorClass="text-blue-400">
                  <div className="overflow-auto max-h-64">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-dark-600">
                          <th className="text-left py-2 pr-4 text-gray-500 font-semibold">Protocolo</th>
                          <th className="text-left py-2 pr-4 text-gray-500 font-semibold">Local</th>
                          <th className="text-left py-2 pr-4 text-gray-500 font-semibold">Remoto</th>
                          <th className="text-left py-2 pr-4 text-gray-500 font-semibold hidden sm:table-cell">Estado</th>
                          <th className="text-left py-2 text-gray-500 font-semibold hidden md:table-cell">PID/Processo</th>
                        </tr>
                      </thead>
                      <tbody>
                        {evidence.network_connections.map((conn, i) => (
                          <tr key={i} className="border-b border-dark-600/40 hover:bg-dark-700/30 transition">
                            <td className="py-1.5 pr-4 font-mono text-cyan-400 font-bold">{conn.protocol?.toUpperCase() ?? '—'}</td>
                            <td className="py-1.5 pr-4 font-mono text-gray-300">{conn.local_addr}:{conn.local_port}</td>
                            <td className="py-1.5 pr-4 font-mono text-gray-400">{conn.remote_addr ? `${conn.remote_addr}:${conn.remote_port}` : '—'}</td>
                            <td className="py-1.5 pr-4 hidden sm:table-cell">
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                conn.state === 'ESTABLISHED' ? 'bg-green-900/40 text-green-400' :
                                conn.state === 'LISTEN'      ? 'bg-blue-900/40 text-blue-400' :
                                conn.state === 'TIME_WAIT'   ? 'bg-yellow-900/40 text-yellow-400' :
                                'bg-dark-700 text-gray-500'
                              }`}>
                                {conn.state ?? '—'}
                              </span>
                            </td>
                            <td className="py-1.5 text-gray-500 font-mono hidden md:table-cell">
                              {conn.pid ? `${conn.pid}` : ''}{conn.process ? ` (${conn.process})` : ''}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </EvidenceSection>
              )}

              {/* Raw JSON */}
              <EvidenceSection title="Evidência Completa (JSON)" icon={Terminal} colorClass="text-gray-400">
                <div className="rounded-lg bg-dark-900/80 border border-dark-600 p-4 max-h-96 overflow-auto">
                  <JsonHighlight data={evidence} />
                </div>
              </EvidenceSection>

            </div>
          )}
        </div>
      )}

      {/* ─── Execution History ───────────────────────────────────────────── */}
      <div className="card-dark p-6">
        <div className="flex items-center justify-between mb-1">
          <h2 className="text-lg font-bold text-gray-100 flex items-center gap-2">
            <FileText className="w-4 h-4 text-gray-400" />
            Histórico de Execuções
          </h2>
          <button
            onClick={fetchHistory}
            className="text-xs text-gray-500 hover:text-gray-300 transition flex items-center gap-1"
          >
            <Loader className="w-3 h-3" /> Atualizar
          </button>
        </div>
        <p className="text-gray-500 text-sm mb-4">Clique em uma execução para carregar suas evidências forenses</p>

        {historyLoading ? (
          <div className="flex items-center gap-3 py-8 justify-center">
            <Loader className="w-5 h-5 text-gray-500 animate-spin" />
            <span className="text-gray-500 text-sm">Carregando histórico...</span>
          </div>
        ) : history.length === 0 ? (
          <div className="text-center py-10 border border-dashed border-dark-600 rounded-lg">
            <Terminal className="w-8 h-8 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-500 text-sm">Nenhuma execução registrada ainda.</p>
            <p className="text-gray-600 text-xs mt-1">Execute uma técnica acima para começar.</p>
          </div>
        ) : (
          <div className="space-y-2 max-h-80 overflow-auto pr-1">
            {history.map(item => (
              <HistoryRow
                key={item.id}
                item={item}
                selected={selectedHistoryId === item.id}
                onClick={() => handleHistoryClick(item)}
              />
            ))}
          </div>
        )}
      </div>

    </div>
  )
}
