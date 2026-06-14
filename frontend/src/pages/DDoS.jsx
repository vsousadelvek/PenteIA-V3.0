import React, { useState, useEffect, useCallback } from 'react'
import {
  AlertTriangle, Zap, Play, Square, Loader, Server, CheckCircle, XCircle,
  Activity, Plus, Trash2, Globe, Cpu, Clock, TrendingUp, Wifi
} from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

const METHODS = [
  { value: 'syn_flood',         label: 'SYN Flood',         layer: 'Layer 4 TCP', desc: 'Enche a fila de conexões TCP com pacotes SYN (raw socket / fallback connect flood)' },
  { value: 'udp_flood',         label: 'UDP Flood',         layer: 'Layer 4 UDP', desc: 'Satura bandwidth com pacotes UDP de payload variável — multi-threaded' },
  { value: 'http_flood',        label: 'HTTP Flood',        layer: 'Layer 7',     desc: 'Requisições GET com UA/paths aleatórios que exaurem conexões da aplicação' },
  { value: 'http_flood_async',  label: 'HTTP Async',        layer: 'Layer 7 ⚡',  desc: 'Flood HTTP via asyncio — até 2000 workers concorrentes no executor local' },
  { value: 'slowloris',         label: 'Slowloris',         layer: 'Layer 7',     desc: 'Abre centenas de conexões semi-abertas e as mantém vivas — esgota pool de threads' },
  { value: 'dns_amplification', label: 'DNS Amplification', layer: 'Layer 3',     desc: 'Queries DNS ANY/TXT — ideal para testar servidores DNS e medir throughput' },
  { value: 'icmp_flood',        label: 'ICMP Flood',        layer: 'Layer 3',     desc: 'Ping flood com ICMP Echo Request raw. Requer admin; fallback automático para UDP' },
  { value: 'serverless_flood',  label: 'Serverless Flood',  layer: 'Layer 7 λ',   desc: 'POST com body JSON aleatório para endpoints de API / serverless functions' },
]

const EMPTY_VPS = () => ({ host: '', port: 22, user: '', password: '', id: Date.now() + Math.random() })
const TERMINAL  = new Set(['completed', 'stopped', 'error', 'not_found', 'port_closed'])

function fmt(n)  { return (n || 0).toLocaleString() }
function fmtRate(n, unit) { return n > 0 ? `${n} ${unit}` : null }

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusBadge({ status }) {
  const map = {
    running:     'bg-blue-900/50 text-blue-300 border-blue-700/50',
    completed:   'bg-green-900/50 text-green-300 border-green-700/50',
    stopped:     'bg-gray-800 text-gray-400 border-gray-700/50',
    error:       'bg-red-900/50 text-red-300 border-red-700/50',
    not_found:   'bg-gray-800 text-gray-500 border-gray-700/50',
    port_closed: 'bg-yellow-900/50 text-yellow-400 border-yellow-700/50',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded border capitalize ${map[status] || 'bg-dark-700 text-gray-400 border-dark-600'}`}>
      {status || '…'}
    </span>
  )
}

function MetricPill({ value, label, color = 'text-gray-300' }) {
  if (!value && value !== 0) return null
  return (
    <span className={`text-xs font-mono ${color}`}>
      {value} <span className="text-gray-600">{label}</span>
    </span>
  )
}

function TestProgressBar({ elapsed, duration }) {
  if (!duration || !elapsed) return null
  const pct = Math.min(100, (elapsed / duration) * 100)
  return (
    <div className="w-full h-1 bg-dark-700 rounded-full overflow-hidden mt-1.5">
      <div
        className="h-full bg-red-600 transition-all duration-1000"
        style={{ width: `${pct}%` }}
      />
    </div>
  )
}

function TestCard({ id, meta, status, isActive, onStop }) {
  const s = status || {}
  const methodLabel = METHODS.find(m => m.value === meta?.method)?.label || meta?.method || '—'
  const remaining = meta?.duration && s.elapsed
    ? Math.max(0, meta.duration - s.elapsed)
    : null

  return (
    <div className="p-3 rounded bg-dark-800 border border-dark-700 group">
      <div className="flex items-start gap-3">
        {/* Status dot */}
        <div className={`w-2 h-2 rounded-full flex-shrink-0 mt-1.5 ${
          isActive && s.status !== 'error' ? 'bg-red-500 animate-pulse' :
          s.status === 'completed' ? 'bg-green-500' :
          s.status === 'error' ? 'bg-red-500' : 'bg-gray-600'
        }`} />

        <div className="flex-1 min-w-0">
          {/* Target + tags */}
          <div className="flex items-center gap-2 flex-wrap text-sm">
            <span className="text-gray-200 font-mono font-medium">{meta?.target || '—'}</span>
            {meta?.via === 'ssh_proxy' && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-indigo-900/50 text-indigo-300 border border-indigo-700/50">SSH</span>
            )}
            {meta?.via === 'local' && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-emerald-900/50 text-emerald-300 border border-emerald-700/50">Local</span>
            )}
            <span className="text-gray-500 text-xs">{methodLabel}</span>
          </div>

          {/* Métricas em tempo real */}
          {(s.packets_sent > 0 || s.requests_sent > 0 || s.connections > 0) && (
            <div className="flex items-center gap-3 mt-1.5 flex-wrap">
              {s.packets_sent  > 0 && <MetricPill value={fmt(s.packets_sent)}  label="pkts"  color="text-blue-400" />}
              {s.requests_sent > 0 && <MetricPill value={fmt(s.requests_sent)} label="hits"  color="text-green-400" />}
              {s.connections   > 0 && <MetricPill value={fmt(s.connections)}   label="conn"  color="text-purple-400" />}
              {s.errors_count  > 0 && <MetricPill value={fmt(s.errors_count)}  label="erros" color="text-red-400" />}
            </div>
          )}

          {/* Taxas */}
          {(s.pps > 0 || s.rps > 0 || s.mbps > 0) && (
            <div className="flex items-center gap-3 mt-1 flex-wrap">
              {s.pps  > 0 && <MetricPill value={`${s.pps}`}  label="pps"  color="text-yellow-400" />}
              {s.rps  > 0 && <MetricPill value={`${s.rps}`}  label="rps"  color="text-cyan-400" />}
              {s.mbps > 0 && <MetricPill value={`${s.mbps}`} label="Mbps" color="text-orange-400" />}
              {s.elapsed  > 0 && (
                <span className="text-xs text-gray-600 font-mono flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {Math.round(s.elapsed)}s
                  {remaining !== null && remaining > 0 && (
                    <span className="text-gray-700"> / -{Math.round(remaining)}s</span>
                  )}
                </span>
              )}
            </div>
          )}

          {/* Progress bar (duração) */}
          {isActive && meta?.duration && s.elapsed > 0 && (
            <TestProgressBar elapsed={s.elapsed} duration={meta.duration} />
          )}

          {/* Output SSH/local */}
          {s.output && !s.error && (
            <pre className="mt-1.5 text-xs text-gray-500 bg-dark-900 rounded p-2 overflow-x-auto max-h-28 whitespace-pre-wrap break-all">{s.output}</pre>
          )}

          {/* Erro */}
          {s.status === 'error' && s.error && (
            <div className="text-xs text-red-400 mt-1 break-all">{s.error}</div>
          )}

          {/* ID */}
          <div className="text-xs text-gray-700 font-mono mt-0.5">{id}</div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <StatusBadge status={s.status} />
          {isActive && (
            <button onClick={() => onStop(id)} title="Parar teste"
              className="p-1.5 rounded hover:bg-red-900/30 text-red-500 hover:text-red-300 transition opacity-0 group-hover:opacity-100">
              <Square className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function MultiVPSSection({ vpsList, setVpsList }) {
  const addVps    = () => setVpsList(l => [...l, EMPTY_VPS()])
  const removeVps = (id) => setVpsList(l => l.filter(v => v.id !== id))
  const updateVps = (id, field, value) => setVpsList(l => l.map(v => v.id === id ? { ...v, [field]: value } : v))

  return (
    <div className="card-dark p-6 border border-purple-600/40">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-purple-400" />
          <h2 className="text-lg font-bold text-gray-100">Multi-VPS Pool</h2>
          <span className="text-xs text-gray-500">Ataque distribuído por múltiplos IPs</span>
        </div>
        <button onClick={addVps}
          className="flex items-center gap-1 text-xs px-3 py-1.5 rounded bg-purple-700/40 hover:bg-purple-700/70 text-purple-300 border border-purple-600/40 transition">
          <Plus className="w-3.5 h-3.5" /> Adicionar VPS
        </button>
      </div>

      {vpsList.length === 0 ? (
        <p className="text-sm text-gray-600 text-center py-4">Nenhum VPS configurado. Adicione VPS para ataques distribuídos.</p>
      ) : (
        <div className="space-y-2">
          {vpsList.map((vps, idx) => (
            <div key={vps.id} className="flex items-center gap-2 p-3 rounded bg-dark-800 border border-dark-700">
              <span className="text-xs text-gray-600 w-5 shrink-0">#{idx + 1}</span>
              <input value={vps.host} onChange={e => updateVps(vps.id, 'host', e.target.value)}
                placeholder="IP / host" className="input-dark text-sm flex-1 min-w-0" />
              <input value={vps.port} type="number" onChange={e => updateVps(vps.id, 'port', parseInt(e.target.value) || 22)}
                className="input-dark text-sm w-16 shrink-0" />
              <input value={vps.user} onChange={e => updateVps(vps.id, 'user', e.target.value)}
                placeholder="usuário" className="input-dark text-sm w-24 shrink-0" />
              <input value={vps.password} type="password" onChange={e => updateVps(vps.id, 'password', e.target.value)}
                placeholder="senha" className="input-dark text-sm w-28 shrink-0" />
              <button onClick={() => removeVps(vps.id)} className="p-1 text-red-500 hover:text-red-300 transition shrink-0">
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function PoolStatusDisplay({ poolStatus }) {
  if (!poolStatus) return null
  return (
    <div className="card-dark p-4 border border-purple-600/30 mt-2">
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-semibold text-purple-300">Pool Attack</span>
        <span className={`text-xs px-2 py-0.5 rounded border ${poolStatus.status === 'running' ? 'bg-blue-900/50 text-blue-300 border-blue-700/50' : 'bg-green-900/50 text-green-300 border-green-700/50'}`}>
          {poolStatus.status}
        </span>
      </div>
      <div className="flex gap-4 text-sm mb-3">
        <span className="text-green-400 font-mono">{fmt(poolStatus.total_requests)} hits</span>
        <span className="text-red-400 font-mono">{fmt(poolStatus.total_errors)} erros</span>
      </div>
      <div className="space-y-1">
        {(poolStatus.nodes || []).map((n, i) => (
          <div key={i} className="flex items-center gap-3 text-xs font-mono">
            <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${n.status === 'running' ? 'bg-blue-400' : n.status === 'port_closed' ? 'bg-yellow-500' : 'bg-green-500'}`} />
            <span className="text-gray-400 w-32 truncate">{n.vps_host}</span>
            <span className="text-green-400 w-20">{fmt(n.requests)} hits</span>
            <span className="text-red-400 w-16">{fmt(n.errors)} err</span>
            <span className={n.status === 'port_closed' ? 'text-yellow-400' : 'text-gray-500'}>{n.status}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function SSHProxySection({ proxy, setProxy, onTest, onDiag }) {
  const [testing, setTesting]       = useState(false)
  const [diagLoading, setDiagLoading] = useState(false)
  const [connStatus, setConnStatus] = useState(null)
  const [connInfo, setConnInfo]     = useState(null)
  const [diag, setDiag]             = useState(null)

  const handleTest = async () => {
    if (!proxy.ssh_host || !proxy.ssh_user) return
    setTesting(true); setConnStatus(null); setDiag(null)
    try {
      const res = await onTest(proxy)
      setConnStatus('ok'); setConnInfo(res)
    } catch (err) {
      setConnStatus('error'); setConnInfo({ error: err.response?.data?.detail || err.message })
    } finally { setTesting(false) }
  }

  const handleDiag = async () => {
    if (!proxy.ssh_host || !proxy.ssh_user) return
    setDiagLoading(true); setDiag(null)
    try {
      const res = await onDiag(proxy)
      setDiag(res)
    } catch (err) {
      setDiag({ error: err.response?.data?.detail || err.message })
    } finally { setDiagLoading(false) }
  }

  return (
    <div className="card-dark p-6 border border-indigo-600/40">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Server className="w-5 h-5 text-indigo-400" />
          <h2 className="text-lg font-bold text-gray-100">Proxy SSH</h2>
          <span className="text-xs text-gray-500">O tráfego parte do VPS, não da sua máquina</span>
        </div>
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <span className="text-sm text-gray-400">Ativo</span>
          <div
            onClick={() => { setProxy(p => ({ ...p, use_ssh_proxy: !p.use_ssh_proxy, use_local: !p.use_ssh_proxy ? false : p.use_local })); setConnStatus(null) }}
            className={`relative w-11 h-6 rounded-full transition-colors ${proxy.use_ssh_proxy ? 'bg-indigo-600' : 'bg-dark-600'}`}
          >
            <div className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform ${proxy.use_ssh_proxy ? 'translate-x-5' : ''}`} />
          </div>
        </label>
      </div>

      {proxy.use_ssh_proxy && (
        <div className="space-y-3">
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-400 mb-1">Host / IP do VPS</label>
              <input type="text" value={proxy.ssh_host}
                onChange={e => { setProxy(p => ({ ...p, ssh_host: e.target.value })); setConnStatus(null) }}
                placeholder="1.2.3.4 ou myvps.com" className="input-dark w-full text-sm" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Porta SSH</label>
              <input type="number" value={proxy.ssh_port}
                onChange={e => setProxy(p => ({ ...p, ssh_port: e.target.value }))}
                onBlur={e => { const v = parseInt(e.target.value); setProxy(p => ({ ...p, ssh_port: (!isNaN(v) && v >= 1 && v <= 65535) ? v : 22 })) }}
                min="1" max="65535" placeholder="22" className="input-dark w-full text-sm" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Usuário</label>
              <input type="text" value={proxy.ssh_user}
                onChange={e => { setProxy(p => ({ ...p, ssh_user: e.target.value })); setConnStatus(null) }}
                placeholder="root" className="input-dark w-full text-sm" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Senha</label>
              <input type="password" value={proxy.ssh_pass}
                onChange={e => { setProxy(p => ({ ...p, ssh_pass: e.target.value })); setConnStatus(null) }}
                placeholder="••••••••" className="input-dark w-full text-sm" />
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center gap-3 flex-wrap">
              <button onClick={handleTest} disabled={testing || !proxy.ssh_host || !proxy.ssh_user}
                className="flex items-center gap-2 px-4 py-2 rounded bg-indigo-700 hover:bg-indigo-600 text-white text-sm disabled:opacity-50 transition">
                {testing ? <Loader className="w-4 h-4 animate-spin" /> : <Server className="w-4 h-4" />}
                {testing ? 'Conectando...' : 'Testar Conexão'}
              </button>
              <button onClick={handleDiag} disabled={diagLoading || !proxy.ssh_host || !proxy.ssh_user}
                className="flex items-center gap-2 px-4 py-2 rounded bg-dark-600 hover:bg-dark-500 text-gray-300 text-sm disabled:opacity-50 transition border border-dark-500">
                {diagLoading ? <Loader className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />}
                {diagLoading ? 'Verificando...' : 'Diagnóstico VPS'}
              </button>
              {connStatus === 'ok' && connInfo && (
                <div className="flex items-center gap-2 text-green-400 text-sm">
                  <CheckCircle className="w-4 h-4 flex-shrink-0" />
                  <span>{connInfo.os} — {connInfo.python}</span>
                </div>
              )}
              {connStatus === 'error' && connInfo && (
                <div className="flex items-center gap-2 text-red-400 text-sm">
                  <XCircle className="w-4 h-4 flex-shrink-0" />
                  <span>{connInfo.error}</span>
                </div>
              )}
            </div>

            {diag && !diag.error && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm mt-1">
                <div className="bg-dark-800 rounded p-3">
                  <p className="text-gray-500 text-xs mb-1">CPU</p>
                  <p className="text-gray-100 font-bold">{diag.cpu_cores} cores</p>
                  <p className="text-gray-400 text-xs">load {diag.load_avg}</p>
                </div>
                <div className="bg-dark-800 rounded p-3">
                  <p className="text-gray-500 text-xs mb-1">Memória</p>
                  <p className={`font-bold ${diag.mem_pct > 85 ? 'text-red-400' : diag.mem_pct > 60 ? 'text-yellow-400' : 'text-green-400'}`}>{diag.mem_pct}%</p>
                  <p className="text-gray-400 text-xs">{diag.mem_used_mb}MB / {diag.mem_total_mb}MB</p>
                </div>
                <div className="bg-dark-800 rounded p-3">
                  <p className="text-gray-500 text-xs mb-1">Disco</p>
                  <p className={`font-bold ${parseInt(diag.disk_pct) > 90 ? 'text-red-400' : parseInt(diag.disk_pct) > 70 ? 'text-yellow-400' : 'text-green-400'}`}>{diag.disk_pct}</p>
                  <p className="text-gray-400 text-xs">{diag.disk_avail} livre</p>
                </div>
                <div className="bg-dark-800 rounded p-3">
                  <p className="text-gray-500 text-xs mb-1">Uptime</p>
                  <p className="text-gray-100 text-xs">{diag.uptime?.match(/up\s+[^,]+/)?.[0] || '—'}</p>
                </div>
              </div>
            )}
            {diag?.error && (
              <div className="flex items-center gap-2 text-red-400 text-sm">
                <XCircle className="w-4 h-4 flex-shrink-0" /><span>{diag.error}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}


// ── Page principal ────────────────────────────────────────────────────────────

export default function DDoS() {
  const toast = useToast()
  const [targetMode, setTargetMode] = useState('ip')
  const [form, setForm] = useState({
    target_host: '127.0.0.1', target_ports: '80',
    domain: '',
    method: 'http_flood', duration: 30, pps: 500, threads: 8,
    payload_size: 512, connections: 300,
    endpoints: '',
  })
  const [proxy, setProxy] = useState({
    use_ssh_proxy: false, use_local: false,
    ssh_host: '', ssh_port: 22, ssh_user: '', ssh_pass: '',
  })
  const [vpsList, setVpsList] = useState(() => {
    try { return JSON.parse(localStorage.getItem('ddos_vps_list')) || [] } catch { return [] }
  })
  const [poolStatus, setPoolStatus]   = useState(null)
  const [activePoolId, setActivePoolId] = useState(null)
  const [poolLoading, setPoolLoading] = useState(false)
  const [loading, setLoading]         = useState(false)

  const [activeTests, setActiveTests] = useState(() => {
    try { return JSON.parse(localStorage.getItem('ddos_active_tests')) || [] } catch { return [] }
  })
  const [testStatuses, setTestStatuses] = useState({})

  const addTest = useCallback((id, meta) => {
    setActiveTests(prev => {
      const next = [...prev, { id, ...meta }]
      localStorage.setItem('ddos_active_tests', JSON.stringify(next))
      return next
    })
  }, [])

  const removeActive = useCallback((id) => {
    setActiveTests(prev => {
      const next = prev.filter(t => t.id !== id)
      if (next.length === 0) localStorage.removeItem('ddos_active_tests')
      else localStorage.setItem('ddos_active_tests', JSON.stringify(next))
      return next
    })
  }, [])

  // Polling de testes ativos
  useEffect(() => {
    if (activeTests.length === 0) return
    const ids = activeTests.map(t => t.id)
    const interval = setInterval(async () => {
      for (const id of ids) {
        try {
          const res = await api.get(`/api/ddos/status/${id}`)
          const s   = res.data
          setTestStatuses(prev => ({ ...prev, [id]: s }))
          if (TERMINAL.has(s.status) || s.status === 'not_found') removeActive(id)
        } catch (err) {
          if (err.response?.status === 404 || err.response?.status === 500) removeActive(id)
        }
      }
    }, 1500)
    return () => clearInterval(interval)
  }, [activeTests, removeActive])

  useEffect(() => {
    localStorage.setItem('ddos_vps_list', JSON.stringify(vpsList))
  }, [vpsList])

  // Polling do pool
  useEffect(() => {
    if (!activePoolId) return
    const interval = setInterval(async () => {
      try {
        const res = await api.get(`/api/ddos/pool/status/${activePoolId}`)
        setPoolStatus(res.data)
        if (res.data.status !== 'running') setActivePoolId(null)
      } catch { setActivePoolId(null) }
    }, 2000)
    return () => clearInterval(interval)
  }, [activePoolId])

  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleStart = async () => {
    if (proxy.use_ssh_proxy && !proxy.ssh_host) {
      toast('Informe o host do VPS para usar proxy SSH.', 'error'); return
    }

    let host, ports
    if (targetMode === 'domain') {
      host = form.domain.trim()
      if (!host) { toast('Informe o domínio alvo.', 'error'); return }
      ports = [80, 443, 8080, 8443, 8000, 8888]
    } else {
      host  = form.target_host.trim()
      if (!host) { toast('Informe o host/IP alvo.', 'error'); return }
      ports = form.target_ports.split(/[,\s]+/).map(p => parseInt(p.trim())).filter(p => !isNaN(p) && p >= 1 && p <= 65535)
      if (ports.length === 0) { toast('Informe ao menos uma porta válida (1–65535).', 'error'); return }
    }

    setLoading(true)
    try {
      let closedPorts = []
      await Promise.all(ports.map(async port => {
        const payload = {
          ...form,
          target_host: host, target_port: port,
          ...proxy, endpoints: form.endpoints,
        }
        const res         = await api.post('/api/ddos/start', payload)
        const testId      = res.data.test_id
        const initStatus  = res.data.status === 'port_closed' ? 'port_closed' : 'running'
        if (initStatus === 'port_closed') closedPorts.push(port)
        const viaLabel = proxy.use_local ? 'local' : proxy.use_ssh_proxy && proxy.ssh_host ? 'ssh_proxy' : 'direct'
        addTest(testId, {
          via: viaLabel, target: `${host}:${port}`,
          method: form.method, startedAt: new Date().toISOString(),
          duration: form.duration,
        })
        setTestStatuses(prev => ({
          ...prev, [testId]: { status: initStatus, via: viaLabel, error: res.data.error || '' }
        }))
      }))

      const via    = proxy.use_local ? ' (local nativo)' : proxy.use_ssh_proxy && proxy.ssh_host ? ` via SSH (${proxy.ssh_host})` : ''
      const active = ports.length - closedPorts.length
      if (closedPorts.length > 0) toast(`${closedPorts.length} porta(s) fechada(s): ${closedPorts.join(', ')}`, 'warning')
      if (active > 0) toast(`${active} teste(s) iniciado(s)${via}`, 'success')
    } catch (err) {
      const detail = err.response?.data?.detail || err.response?.data || err.message
      toast('Erro: ' + detail, 'error')
    } finally { setLoading(false) }
  }

  const handleStop = async (testId) => {
    try {
      await api.post(`/api/ddos/stop/${testId}`)
      removeActive(testId)
      setTestStatuses(prev => ({ ...prev, [testId]: { ...(prev[testId] || {}), status: 'stopped' } }))
      toast('Teste parado.', 'info')
    } catch (err) {
      toast('Erro ao parar: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  const handlePoolStart = async () => {
    const validVps = vpsList.filter(v => v.host && v.user)
    if (validVps.length === 0) { toast('Adicione ao menos um VPS configurado.', 'error'); return }

    let host, ports
    if (targetMode === 'domain') {
      host = form.domain.trim(); if (!host) { toast('Informe o domínio alvo.', 'error'); return }
      ports = [80, 443]
    } else {
      host  = form.target_host.trim(); if (!host) { toast('Informe o host/IP alvo.', 'error'); return }
      ports = form.target_ports.split(/[,\s]+/).map(p => parseInt(p)).filter(p => !isNaN(p) && p >= 1 && p <= 65535)
      if (ports.length === 0) { toast('Porta inválida.', 'error'); return }
    }

    setPoolLoading(true); setPoolStatus(null)
    try {
      for (const port of ports) {
        const res = await api.post('/api/ddos/pool/start', {
          target_host: host, target_port: port,
          method: form.method, duration: form.duration,
          pps: form.pps, threads: form.threads,
          vps_list: validVps.map(v => ({ host: v.host, port: v.port, user: v.user, password: v.password })),
          endpoints: form.endpoints,
        })
        setActivePoolId(res.data.pool_id)
        setPoolStatus({ status: 'running', nodes: res.data.nodes, total_requests: 0, total_errors: 0 })
      }
      toast(`Pool iniciado: ${validVps.length} VPS atacando ${host}`, 'success')
    } catch (err) {
      toast('Erro: ' + (err.response?.data?.detail || err.message), 'error')
    } finally { setPoolLoading(false) }
  }

  const handlePoolStop = async () => {
    if (!activePoolId) return
    try {
      await api.post(`/api/ddos/pool/stop/${activePoolId}`)
      setActivePoolId(null)
      toast('Pool parado.', 'info')
    } catch (err) {
      toast('Erro: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  const handleTestProxy  = async (p) => (await api.post('/api/ddos/proxy/test',  { host: p.ssh_host, port: p.ssh_port, user: p.ssh_user, password: p.ssh_pass })).data
  const handleDiagProxy  = async (p) => (await api.post('/api/ddos/proxy/diag',  { host: p.ssh_host, port: p.ssh_port, user: p.ssh_user, password: p.ssh_pass })).data

  const handleClearFinished = () => {
    const activeIds = new Set(activeTests.map(t => t.id))
    setTestStatuses(prev => {
      const next = { ...prev }
      Object.keys(next).forEach(id => { if (!activeIds.has(id)) delete next[id] })
      return next
    })
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  const activeIds     = new Set(activeTests.map(t => t.id))
  const allDisplayIds = [
    ...activeTests.map(t => t.id),
    ...Object.keys(testStatuses).filter(id => !activeIds.has(id)),
  ]
  const hasFinished = allDisplayIds.some(id => !activeIds.has(id) && testStatuses[id])
  const selectedMethod = METHODS.find(m => m.value === form.method)

  const needsEndpoints    = ['serverless_flood'].includes(form.method)
  const needsPayloadSize  = ['udp_flood'].includes(form.method)
  const needsConnections  = ['slowloris'].includes(form.method)

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">Teste DDoS</h1>
        <p className="text-gray-400">Stress test de resiliência — 8 métodos, métricas em tempo real, multi-alvo simultâneo</p>
      </div>

      <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4 flex gap-3">
        <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-red-400 font-semibold">Apenas ambientes controlados e autorizados</p>
          <p className="text-red-300 text-sm">Testes DDoS sem autorização explícita são crime. Use apenas em infraestrutura própria ou com permissão por escrito.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Métodos */}
        <div className="card-dark p-6">
          <h2 className="text-xl font-bold text-gray-100 mb-4">Método de Ataque</h2>
          <div className="space-y-1.5">
            {METHODS.map(m => (
              <button key={m.value}
                onClick={() => setForm(f => ({ ...f, method: m.value }))}
                className={`w-full flex items-start gap-3 p-3 rounded transition text-left ${form.method === m.value ? 'bg-red-900/30 border border-red-600/50' : 'bg-dark-700 border border-transparent hover:border-dark-500'}`}>
                <Zap className={`w-4 h-4 flex-shrink-0 mt-0.5 ${form.method === m.value ? 'text-red-500' : 'text-gray-500'}`} />
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-gray-100 text-sm font-medium">{m.label}</span>
                    <span className="text-gray-500 text-xs">({m.layer})</span>
                  </div>
                  {form.method === m.value && (
                    <p className="text-gray-400 text-xs mt-0.5 leading-snug">{m.desc}</p>
                  )}
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Configuração */}
        <div className="card-dark p-6">
          <h2 className="text-xl font-bold text-gray-100 mb-4">Configuração</h2>
          <div className="space-y-4">
            {/* Toggle IP / Domínio */}
            <div className="flex rounded overflow-hidden border border-dark-600 w-fit">
              <button onClick={() => setTargetMode('ip')}
                className={`px-4 py-1.5 text-sm font-medium transition ${targetMode === 'ip' ? 'bg-red-700 text-white' : 'bg-dark-700 text-gray-400 hover:text-gray-200'}`}>
                IP / Host
              </button>
              <button onClick={() => setTargetMode('domain')}
                className={`px-4 py-1.5 text-sm font-medium transition ${targetMode === 'domain' ? 'bg-red-700 text-white' : 'bg-dark-700 text-gray-400 hover:text-gray-200'}`}>
                Domínio
              </button>
            </div>

            {targetMode === 'ip' ? (
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2">
                  <label className="block text-sm font-medium text-gray-300 mb-2">Host / IP Alvo</label>
                  <input type="text" value={form.target_host}
                    onChange={e => setForm(f => ({ ...f, target_host: e.target.value }))}
                    placeholder="192.168.1.1" className="input-dark w-full" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Porta(s)</label>
                  <input type="text" value={form.target_ports}
                    onChange={e => setForm(f => ({ ...f, target_ports: e.target.value }))}
                    placeholder="80, 443, 8080" className="input-dark w-full" />
                  <p className="text-xs text-gray-500 mt-1">Vírgula para múltiplas</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Duração (s)</label>
                  <input type="number" value={form.duration}
                    onChange={e => setForm(f => ({ ...f, duration: parseInt(e.target.value) || 30 }))}
                    min="5" max="600" className="input-dark w-full" />
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Domínio Alvo</label>
                  <input type="text" value={form.domain}
                    onChange={e => setForm(f => ({ ...f, domain: e.target.value.replace(/^https?:\/\//, '') }))}
                    placeholder="exemplo.com" className="input-dark w-full" />
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {[80, 443, 8080, 8443, 8000, 8888].map(p => (
                      <span key={p} className="text-xs px-2 py-0.5 rounded bg-dark-700 border border-dark-600 text-gray-500 font-mono">{p}</span>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Duração (s)</label>
                  <input type="number" value={form.duration}
                    onChange={e => setForm(f => ({ ...f, duration: parseInt(e.target.value) || 30 }))}
                    min="5" max="600" className="input-dark w-full" />
                </div>
              </div>
            )}

            {/* Intensidade */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  {needsConnections ? 'Conexões' : 'Pkts/Reqs por segundo'}
                </label>
                {needsConnections ? (
                  <input type="number" value={form.connections}
                    onChange={e => setForm(f => ({ ...f, connections: parseInt(e.target.value) || 300 }))}
                    min="10" max="2000" className="input-dark w-full" />
                ) : (
                  <input type="number" value={form.pps}
                    onChange={e => setForm(f => ({ ...f, pps: parseInt(e.target.value) || 500 }))}
                    min="1" max="50000" className="input-dark w-full" />
                )}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Threads</label>
                <input type="number" value={form.threads}
                  onChange={e => setForm(f => ({ ...f, threads: parseInt(e.target.value) || 8 }))}
                  min="1" max="64" className="input-dark w-full" />
              </div>
            </div>

            {/* Campo condicional: payload size para UDP */}
            {needsPayloadSize && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Payload UDP (bytes)
                </label>
                <input type="number" value={form.payload_size}
                  onChange={e => setForm(f => ({ ...f, payload_size: parseInt(e.target.value) || 512 }))}
                  min="64" max="65000" className="input-dark w-full" />
                <p className="text-xs text-gray-500 mt-1">Tamanho máximo do pacote UDP. Valor real é aleatório entre 50% e 100% deste.</p>
              </div>
            )}

            {/* Campo condicional: endpoints para serverless */}
            {needsEndpoints && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Endpoints (CSV)</label>
                <input type="text" value={form.endpoints}
                  onChange={e => setForm(f => ({ ...f, endpoints: e.target.value }))}
                  placeholder="/api/search,/api/products"
                  className="input-dark w-full" />
                <p className="text-xs text-gray-500 mt-1">Deixe vazio para usar /api. Use Recon → Serverless para descobrir.</p>
              </div>
            )}

            <button onClick={handleStart} disabled={loading}
              className="btn-red w-full flex justify-center items-center gap-2 disabled:opacity-50">
              {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {loading ? 'Iniciando...' : 'Iniciar Teste'}
            </button>

            {activeTests.length > 0 && (
              <p className="text-xs text-gray-500 text-center">
                {activeTests.length} teste{activeTests.length > 1 ? 's' : ''} ativo{activeTests.length > 1 ? 's' : ''} — lançar novos em paralelo é suportado
              </p>
            )}
          </div>
        </div>
      </div>

      {/* SSH Proxy */}
      <SSHProxySection proxy={proxy} setProxy={setProxy} onTest={handleTestProxy} onDiag={handleDiagProxy} />

      {/* Executor Nativo */}
      <div className="card-dark p-6 border border-emerald-600/40">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Cpu className="w-5 h-5 text-emerald-400" />
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-gray-100">Executor Nativo</h2>
                <span className="text-xs px-2 py-0.5 rounded bg-emerald-900/50 text-emerald-400 border border-emerald-700/50 font-semibold">GRATUITO</span>
              </div>
              <p className="text-xs text-gray-500 mt-0.5">Flood via asyncio desta máquina — até 2000 workers concorrentes. Sem VPS, sem custo.</p>
            </div>
          </div>
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <span className="text-sm text-gray-400">Ativo</span>
            <div
              onClick={() => setProxy(p => ({ ...p, use_local: !p.use_local, use_ssh_proxy: !p.use_local ? false : p.use_ssh_proxy }))}
              className={`relative w-11 h-6 rounded-full transition-colors ${proxy.use_local ? 'bg-emerald-600' : 'bg-dark-600'}`}
            >
              <div className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform ${proxy.use_local ? 'translate-x-5' : ''}`} />
            </div>
          </label>
        </div>
        {proxy.use_local && (
          <div className="mt-3 flex items-center gap-2 text-sm text-emerald-400">
            <CheckCircle className="w-4 h-4 flex-shrink-0" />
            <span>Ativo — ataques rodarão localmente. Proxy SSH desativado.</span>
          </div>
        )}
      </div>

      {/* Multi-VPS Pool */}
      <MultiVPSSection vpsList={vpsList} setVpsList={setVpsList} />
      {vpsList.filter(v => v.host && v.user).length > 0 && (
        <div className="flex items-center gap-3">
          <button onClick={handlePoolStart} disabled={poolLoading || !!activePoolId}
            className="flex items-center gap-2 px-6 py-2.5 rounded bg-purple-700 hover:bg-purple-600 text-white font-semibold transition disabled:opacity-50">
            {poolLoading ? <Loader className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
            {poolLoading ? 'Iniciando Pool...' : `Atacar com ${vpsList.filter(v => v.host && v.user).length} VPS`}
          </button>
          {activePoolId && (
            <button onClick={handlePoolStop} className="flex items-center gap-2 px-4 py-2.5 rounded bg-red-800 hover:bg-red-700 text-white text-sm transition">
              <Square className="w-4 h-4" /> Parar Pool
            </button>
          )}
        </div>
      )}
      {poolStatus && <PoolStatusDisplay poolStatus={poolStatus} />}

      {/* Lista de testes com métricas em tempo real */}
      {allDisplayIds.length > 0 && (
        <div className="card-dark p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <h2 className="text-xl font-bold text-gray-100">Testes</h2>
              {activeTests.length > 0 && (
                <span className="flex items-center gap-1 text-sm text-blue-400">
                  <Activity className="w-3.5 h-3.5 animate-pulse" />
                  {activeTests.length} rodando
                </span>
              )}
            </div>
            {hasFinished && (
              <button onClick={handleClearFinished} className="text-xs text-gray-500 hover:text-gray-300 transition">
                Limpar finalizados
              </button>
            )}
          </div>

          <div className="space-y-2">
            {allDisplayIds.map(id => {
              const meta    = activeTests.find(t => t.id === id)
              const isActive = activeIds.has(id)
              return (
                <TestCard key={id} id={id} meta={meta}
                  status={testStatuses[id]} isActive={isActive}
                  onStop={handleStop} />
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
