import React, { useState, useEffect, useCallback } from 'react'
import {
  Monitor, Cpu, Globe, User, Clock, Play, Trash2,
  RefreshCw, Terminal, ChevronDown, ChevronRight, AlertTriangle,
  CheckCircle, XCircle, Loader2, Copy, Server, Wifi, WifiOff,
} from 'lucide-react'
import api from '../api'

// ── CVSS helpers ─────────────────────────────────────────────────────────────
const CVSS_CLS = s =>
  s >= 9.0 ? 'bg-red-900/40 text-red-300 border border-red-700/50'
  : s >= 7.0 ? 'bg-orange-900/40 text-orange-300 border border-orange-700/50'
  : s >= 4.0 ? 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50'
  : s > 0    ? 'bg-blue-900/40 text-blue-300 border border-blue-700/50'
  :            'bg-dark-600 text-gray-400'

const CVSS_LABEL = s =>
  s >= 9.0 ? 'Critical' : s >= 7.0 ? 'High' : s >= 4.0 ? 'Medium' : s > 0 ? 'Low' : '-'

// ── Technique catalog ─────────────────────────────────────────────────────────
const AGENT_TECHNIQUES = [
  { id: 'T1082', name: 'System Information Discovery',  desc: 'OS, hostname, usuário, versão Python, env vars',        cvss: 5.3 },
  { id: 'T1087', name: 'Account Discovery',             desc: 'Enumera usuários locais e grupos privilegiados',         cvss: 5.3 },
  { id: 'T1548', name: 'Privilege Escalation Vectors',  desc: 'SUID, sudo NOPASSWD, capabilities, Windows privs',      cvss: 7.8 },
  { id: 'T1552', name: 'Credential Hunting',            desc: 'SSH keys, .env, AWS creds, histórico, env vars',        cvss: 8.8 },
  { id: 'T1053', name: 'Persistence Mechanisms',        desc: 'Cron, systemd, Windows Run keys, startup folder',       cvss: 6.5 },
  { id: 'T1016', name: 'Network Reconnaissance',        desc: 'ARP, interfaces, gateway, portas abertas localhost',    cvss: 5.3 },
  { id: 'T1057', name: 'Process Discovery',             desc: 'Processos suspeitos (Mimikatz, Cobalt, Meterpreter…)',  cvss: 6.5 },
  { id: 'T1083', name: 'Sensitive File Discovery',      desc: 'SSH keys, cloud credentials, configs, /etc/shadow',     cvss: 7.5 },
]

// ── Status badge ──────────────────────────────────────────────────────────────
const StatusBadge = ({ status }) => {
  const cfg = {
    active: { cls: 'text-green-400',  Icon: Wifi,     label: 'Online' },
    idle:   { cls: 'text-yellow-400', Icon: Clock,    label: 'Idle'   },
    lost:   { cls: 'text-red-400',    Icon: WifiOff,  label: 'Perdido'},
  }[status] || { cls: 'text-gray-400', Icon: WifiOff, label: status }
  const { cls, Icon, label } = cfg
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${cls}`}>
      <Icon className="w-3 h-3" /> {label}
    </span>
  )
}

// ── Result card (expandable) ──────────────────────────────────────────────────
const ResultCard = ({ r }) => {
  const [open, setOpen] = useState(false)
  const found  = r.status === 'found'
  const failed = r.status === 'failed'
  const score  = r.cvss_score ?? 0
  const Icon   = found ? AlertTriangle : failed ? XCircle : CheckCircle
  const iconCls= found ? 'text-red-400' : failed ? 'text-gray-500' : 'text-green-400'

  return (
    <div className={`rounded-lg border ${found ? 'border-red-800/50 bg-red-950/10' : 'border-dark-600 bg-dark-700/40'}`}>
      <button
        className="w-full flex items-start gap-3 p-3 text-left"
        onClick={() => setOpen(v => !v)}
      >
        <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${iconCls}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-gray-500">{r.technique}</span>
            <span className="text-sm font-medium text-gray-200 truncate">{r.name || r.technique}</span>
            {score > 0 && (
              <span className={`text-xs px-1.5 py-0.5 rounded font-semibold ${CVSS_CLS(score)}`}>
                {CVSS_LABEL(score)} {score.toFixed(1)}
              </span>
            )}
          </div>
          {r.detail && <p className="text-xs text-gray-400 mt-0.5 truncate">{r.detail}</p>}
        </div>
        {open ? <ChevronDown className="w-4 h-4 text-gray-500 shrink-0" /> : <ChevronRight className="w-4 h-4 text-gray-500 shrink-0" />}
      </button>

      {open && (
        <div className="px-3 pb-3 space-y-2 border-t border-dark-600 pt-2">
          {r.compliance?.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {r.compliance.map(c => (
                <span key={c} className="text-xs px-2 py-0.5 bg-dark-600 text-gray-400 rounded">{c}</span>
              ))}
            </div>
          )}
          {r.remediation && (
            <div className="bg-dark-600/60 rounded p-2">
              <p className="text-xs text-gray-300 leading-relaxed">{r.remediation}</p>
            </div>
          )}
          {r.data && (
            <details className="text-xs">
              <summary className="cursor-pointer text-gray-500 hover:text-gray-300">Dados brutos</summary>
              <pre className="mt-1 p-2 bg-dark-900 rounded text-gray-400 overflow-x-auto max-h-48 text-[11px]">
                {JSON.stringify(r.data, null, 2)}
              </pre>
            </details>
          )}
        </div>
      )}
    </div>
  )
}

// ── Deploy instructions ───────────────────────────────────────────────────────
const DeployInstructions = ({ token, userId, c2 }) => {
  const [copied, setCopied] = useState(false)
  const cmd = `python3 penteia_agent.py --c2 ${c2} --token ${token} --user-id ${userId} --once`
  const copyCmd = () => {
    navigator.clipboard.writeText(cmd)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div className="bg-dark-700 border border-dark-600 rounded-lg p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Terminal className="w-4 h-4 text-red-400" />
        <span className="text-sm font-semibold text-gray-200">Implantar Agente no Alvo</span>
      </div>
      <p className="text-xs text-gray-400">
        Copie <code className="text-red-300 bg-dark-800 px-1 rounded">penteia_agent.py</code> para o alvo e execute o comando abaixo.
        Use <code className="text-red-300 bg-dark-800 px-1 rounded">--once</code> para scan único, ou sem ele para modo poll contínuo.
      </p>
      <div className="bg-dark-900 rounded p-3 flex items-start gap-2">
        <code className="text-xs text-green-400 font-mono flex-1 break-all">{cmd}</code>
        <button onClick={copyCmd} className="shrink-0 p-1 hover:bg-dark-700 rounded" title="Copiar">
          <Copy className={`w-4 h-4 ${copied ? 'text-green-400' : 'text-gray-500'}`} />
        </button>
      </div>
      <p className="text-xs text-gray-500">
        Requisitos: Python 3.6+ (stdlib apenas). Autorize o uso no sistema alvo antes de executar.
      </p>
    </div>
  )
}

// ── Agent card ────────────────────────────────────────────────────────────────
const AgentCard = ({ agent, onExecute, onDelete, onViewResults, loading }) => {
  const [selected, setSelected] = useState(new Set(AGENT_TECHNIQUES.map(t => t.id)))
  const [expanded, setExpanded] = useState(false)
  const toggle = id => setSelected(s => {
    const n = new Set(s)
    n.has(id) ? n.delete(id) : n.add(id)
    return n
  })

  const secsAgo = agent.last_seen_secs
  const lastSeenLabel = secsAgo < 60 ? `${secsAgo}s atrás`
    : secsAgo < 3600 ? `${Math.floor(secsAgo / 60)}min atrás`
    : `${Math.floor(secsAgo / 3600)}h atrás`

  return (
    <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="p-4 flex items-start gap-3">
        <div className="w-10 h-10 bg-dark-700 border border-dark-600 rounded-lg flex items-center justify-center shrink-0">
          <Monitor className="w-5 h-5 text-red-400" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="font-bold text-gray-100">{agent.hostname}</h3>
            <StatusBadge status={agent.status} />
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-0.5 mt-1">
            <span className="text-xs text-gray-400 flex items-center gap-1">
              <Globe className="w-3 h-3" /> {agent.ip || 'IP desconhecido'}
            </span>
            <span className="text-xs text-gray-400 flex items-center gap-1">
              <Cpu className="w-3 h-3" /> {agent.os_info || 'OS desconhecido'}
            </span>
            <span className="text-xs text-gray-400 flex items-center gap-1">
              <User className="w-3 h-3" /> {agent.username || '-'}
            </span>
            <span className="text-xs text-gray-400 flex items-center gap-1">
              <Clock className="w-3 h-3" /> {lastSeenLabel}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={() => onViewResults(agent.id)}
            className="p-2 text-gray-400 hover:text-blue-400 hover:bg-dark-700 rounded transition"
            title="Ver resultados"
          >
            <Server className="w-4 h-4" />
          </button>
          <button
            onClick={() => onDelete(agent.id)}
            className="p-2 text-gray-400 hover:text-red-400 hover:bg-dark-700 rounded transition"
            title="Remover agente"
          >
            <Trash2 className="w-4 h-4" />
          </button>
          <button
            onClick={() => setExpanded(v => !v)}
            className="p-2 text-gray-400 hover:text-gray-100 hover:bg-dark-700 rounded transition"
          >
            {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Expanded: technique selection + execute */}
      {expanded && (
        <div className="border-t border-dark-700 p-4 space-y-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Técnicas</span>
            <div className="flex gap-2">
              <button onClick={() => setSelected(new Set(AGENT_TECHNIQUES.map(t => t.id)))}
                className="text-xs text-gray-500 hover:text-gray-300">Selecionar todas</button>
              <button onClick={() => setSelected(new Set())}
                className="text-xs text-gray-500 hover:text-gray-300">Limpar</button>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {AGENT_TECHNIQUES.map(t => (
              <label key={t.id}
                className={`flex items-start gap-2 p-2 rounded cursor-pointer border transition ${
                  selected.has(t.id)
                    ? 'border-red-700/40 bg-red-950/10'
                    : 'border-dark-600 bg-dark-700/30 opacity-60'
                }`}
              >
                <input type="checkbox" checked={selected.has(t.id)} onChange={() => toggle(t.id)}
                  className="mt-0.5 accent-red-500" />
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] font-mono text-gray-500">{t.id}</span>
                    <span className={`text-[10px] px-1 rounded ${CVSS_CLS(t.cvss)}`}>{t.cvss}</span>
                  </div>
                  <p className="text-xs font-medium text-gray-300 leading-tight">{t.name}</p>
                  <p className="text-[11px] text-gray-500 leading-tight">{t.desc}</p>
                </div>
              </label>
            ))}
          </div>
          <button
            onClick={() => onExecute(agent.id, [...selected])}
            disabled={loading || selected.size === 0}
            className="w-full flex items-center justify-center gap-2 py-2.5 bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white rounded-lg text-sm font-semibold transition"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            Executar {selected.size} técnica{selected.size !== 1 ? 's' : ''} no agente
          </button>
        </div>
      )}
    </div>
  )
}

// ── Results modal ─────────────────────────────────────────────────────────────
const ResultsModal = ({ agentId, onClose }) => {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!agentId) return
    setLoading(true)
    api.get(`/api/agents/${agentId}/results`)
      .then(r => setData(r.data))
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [agentId])

  const results = data?.results ?? []
  const found  = results.filter(r => r.status === 'found')
  const totalCvss = results.reduce((s, r) => s + (r.cvss_score || 0), 0)
  const foundCvss = found.reduce((s, r) => s + (r.cvss_score || 0), 0)
  const riskPct   = totalCvss > 0 ? ((foundCvss / totalCvss) * 100).toFixed(1) : '0.0'

  return (
    <div className="fixed inset-0 bg-black/70 z-[100] flex items-center justify-center p-4">
      <div className="bg-dark-800 border border-dark-600 rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between p-5 border-b border-dark-600">
          <div>
            <h2 className="text-lg font-bold text-gray-100">
              Resultados — {data?.agent?.hostname ?? agentId}
            </h2>
            {data?.agent && (
              <p className="text-xs text-gray-400">{data.agent.ip} · {data.agent.os_info}</p>
            )}
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-100 text-xl">✕</button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-16">
            <Loader2 className="w-6 h-6 animate-spin text-red-500" />
          </div>
        ) : results.length === 0 ? (
          <div className="p-8 text-center text-gray-500">Nenhum resultado ainda. Execute as técnicas primeiro.</div>
        ) : (
          <div className="flex-1 overflow-y-auto p-5 space-y-3">
            {/* Summary */}
            <div className="grid grid-cols-3 gap-3 mb-4">
              <div className="bg-dark-700 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-red-400">{riskPct}%</p>
                <p className="text-xs text-gray-400">Risco CVSS</p>
              </div>
              <div className="bg-dark-700 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-orange-400">{found.length}</p>
                <p className="text-xs text-gray-400">Vulnerável</p>
              </div>
              <div className="bg-dark-700 rounded-lg p-3 text-center">
                <p className="text-2xl font-bold text-green-400">{results.length - found.length}</p>
                <p className="text-xs text-gray-400">Bloqueado</p>
              </div>
            </div>
            {results.map((r, i) => <ResultCard key={r.task_id ?? i} r={r} />)}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Agents() {
  const [agents, setAgents]       = useState([])
  const [loading, setLoading]     = useState(true)
  const [executing, setExecuting] = useState(null)
  const [viewAgentId, setViewAgentId] = useState(null)
  const [showDeploy, setShowDeploy] = useState(false)

  const token  = localStorage.getItem('token') ?? ''
  const userId = (() => {
    try {
      return JSON.parse(atob(token.split('.')[1])).sub ?? ''
    } catch { return '' }
  })()
  const c2 = `${window.location.protocol}//${window.location.hostname}:8000`

  const fetchAgents = useCallback(() => {
    setLoading(true)
    api.get('/api/agents')
      .then(r => setAgents(r.data.agents ?? []))
      .catch(() => setAgents([]))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    fetchAgents()
    const iv = setInterval(fetchAgents, 15000)
    return () => clearInterval(iv)
  }, [fetchAgents])

  const handleExecute = async (agentId, techniques) => {
    setExecuting(agentId)
    try {
      await api.post(`/api/agents/${agentId}/execute`, { techniques })
    } finally {
      setExecuting(null)
    }
  }

  const handleDelete = async (agentId) => {
    if (!window.confirm('Remover este agente e todos os seus resultados?')) return
    await api.delete(`/api/agents/${agentId}`)
    fetchAgents()
  }

  const critical = agents.filter(a => a.status === 'active').length
  const lost     = agents.filter(a => a.status === 'lost').length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <Monitor className="w-7 h-7 text-red-500" />
            Agentes (Análise Interna)
          </h1>
          <p className="text-sm text-gray-400 mt-1">Avalia o servidor por dentro — descobre vulnerabilidades que só aparecem com acesso local</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowDeploy(v => !v)}
            className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-gray-300 rounded-lg text-sm transition">
            <Terminal className="w-4 h-4" />
            {showDeploy ? 'Ocultar deploy' : 'Como implantar'}
          </button>
          <button onClick={fetchAgents}
            className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-gray-300 rounded-lg text-sm transition">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Atualizar
          </button>
        </div>
      </div>

      {/* O que é */}
      <div className="card-dark p-6 bg-blue-900/10 border-l-4 border-blue-600">
        <div className="flex items-center gap-2 mb-3">
          <Terminal className="w-5 h-5 text-blue-400" />
          <h2 className="text-lg font-bold text-gray-100">O que é um Agente?</h2>
        </div>
        <p className="text-gray-300 text-sm mb-4 leading-relaxed">
          O BAS testa o servidor <strong className="text-gray-100">de fora</strong> (pela rede).
          O Agente testa <strong className="text-gray-100">de dentro</strong> — ele roda no próprio servidor ou computador alvo
          e descobre problemas que não são visíveis externamente, como arquivos com senhas expostas, usuários com permissões excessivas
          ou formas de um invasor já dentro se tornar administrador.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
          {[
            { n: '1', t: 'Copie o agente pro alvo', d: 'Baixe o arquivo penteia_agent.py e copie para o servidor autorizado via SCP, FTP ou qualquer outro método.' },
            { n: '2', t: 'Execute com um comando', d: 'Rode o comando Python exibido no botão "Como implantar". O agente se conecta automaticamente e aparece aqui.' },
            { n: '3', t: 'Veja o que foi encontrado', d: 'Clique em "Ver resultados" no card do agente. Você verá tudo que foi descoberto com score de risco e instruções de correção.' },
          ].map(({ n, t, d }) => (
            <div key={n} className="flex gap-3 p-3 rounded bg-dark-700 border border-dark-600">
              <span className="text-blue-400 font-black text-xl w-6 flex-shrink-0">{n}</span>
              <div>
                <div className="font-semibold text-gray-100 text-xs mb-1">{t}</div>
                <div className="text-gray-400 text-xs leading-relaxed">{d}</div>
              </div>
            </div>
          ))}
        </div>
        <div className="mt-3 border-t border-dark-600 pt-3">
          <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">O que o agente verifica?</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
            {[
              { id: 'T1082', label: 'Informações do Sistema', desc: 'OS, usuário, versão, variáveis de ambiente' },
              { id: 'T1087', label: 'Usuários e Grupos',      desc: 'Quem tem acesso e quais privilégios' },
              { id: 'T1548', label: 'Escalada de Privilégio', desc: 'Caminhos para virar administrador' },
              { id: 'T1552', label: 'Senhas Expostas',        desc: 'Histórico, .env, chaves SSH, variáveis' },
              { id: 'T1053', label: 'Persistência',           desc: 'Tarefas agendadas, serviços automáticos' },
              { id: 'T1016', label: 'Rede Interna',           desc: 'Outros hosts, portas abertas, gateway' },
              { id: 'T1057', label: 'Processos Suspeitos',    desc: 'Ferramentas de ataque rodando' },
              { id: 'T1083', label: 'Arquivos Sensíveis',     desc: 'Credenciais, configs, chaves de API' },
            ].map(t => (
              <div key={t.id} className="p-2 rounded bg-dark-700 border border-dark-600">
                <p className="font-semibold text-gray-300 text-[11px]">{t.label}</p>
                <p className="text-gray-500 text-[10px] mt-0.5">{t.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Total de agentes', value: agents.length, cls: 'text-gray-100' },
          { label: 'Online',           value: critical,       cls: 'text-green-400' },
          { label: 'Idle / Sem comunicar', value: agents.filter(a => a.status === 'idle').length, cls: 'text-yellow-400' },
          { label: 'Perdidos',         value: lost,           cls: 'text-red-400' },
        ].map(s => (
          <div key={s.label} className="bg-dark-800 border border-dark-700 rounded-lg p-4 text-center">
            <p className={`text-2xl font-bold ${s.cls}`}>{s.value}</p>
            <p className="text-xs text-gray-500 mt-0.5">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Deploy instructions */}
      {showDeploy && (
        <DeployInstructions token={token} userId={userId} c2={c2} />
      )}

      {/* Agent list */}
      {loading && agents.length === 0 ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="w-6 h-6 animate-spin text-red-500" />
        </div>
      ) : agents.length === 0 ? (
        <div className="bg-dark-800 border border-dashed border-dark-600 rounded-xl p-12 text-center space-y-3">
          <Monitor className="w-10 h-10 text-gray-600 mx-auto" />
          <p className="text-gray-400 font-medium">Nenhum agente registrado</p>
          <p className="text-sm text-gray-600">
            Implante <code className="text-gray-400">penteia_agent.py</code> em um alvo autorizado e ele aparecerá aqui automaticamente.
          </p>
          <button onClick={() => setShowDeploy(true)}
            className="mt-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-semibold transition">
            Ver instruções de deploy
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {agents.map(a => (
            <AgentCard
              key={a.id}
              agent={a}
              onExecute={handleExecute}
              onDelete={handleDelete}
              onViewResults={setViewAgentId}
              loading={executing === a.id}
            />
          ))}
        </div>
      )}

      {/* Results modal */}
      {viewAgentId && (
        <ResultsModal agentId={viewAgentId} onClose={() => setViewAgentId(null)} />
      )}
    </div>
  )
}
