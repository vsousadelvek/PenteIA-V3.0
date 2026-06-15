import React, { useState, useEffect, useRef } from 'react'
import { Shield, Zap, AlertCircle, Activity, Users, Compass, BookOpen, Search, BarChart2, Lock, Eye, FileText, GitBranch, Clock } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts'
import { format } from 'date-fns'
import { ptBR } from 'date-fns/locale'
import StatCard from '../components/StatCard'
import api from '../api'
import { useNavigate } from 'react-router-dom'

const MODULE_INFO = [
  { name: 'Reconhecimento', icon: Search, color: 'cyan', href: '/recon', tip: 'Comece aqui', description: 'Descobre informações sobre o alvo: IPs, portas, serviços e proteção CDN.' },
  { name: 'Teste de Sobrecarga (DDoS)', icon: Zap, color: 'red', href: '/ddos', tip: '6 métodos', description: 'Simula ataques de sobrecarga para verificar resistência do servidor.' },
  { name: 'Simulação de Ataques (BAS)', icon: Compass, color: 'orange', href: '/bas', tip: '150+ técnicas', description: 'Executa técnicas MITRE ATT&CK de forma controlada com agendamento automático.' },
  { name: 'Controle Remoto (C2)', icon: Users, color: 'green', href: '/c2', tip: 'Framework C2', description: 'Simula comunicação de comando e controle com Malleable profiles.' },
  { name: 'Evasão de Defesas', icon: Shield, color: 'purple', href: '/evasion', tip: 'Anti-AV / EDR', description: 'Testa se AV/EDR detecta técnicas avançadas de evasão de defesas.' },
  { name: 'Relatórios', icon: FileText, color: 'blue', href: '/reporting', tip: 'PDF + Compliance', description: 'Gera relatórios profissionais e mapeia achados para LGPD, ISO 27001, PCI DSS.' },
  { name: 'Histórico de Operações', icon: Activity, color: 'yellow', href: '/operations', tip: 'Log completo', description: 'Registro completo de todas as operações com data, hora e resultado.' },
  { name: 'Attack Path (Grafo)', icon: GitBranch, color: 'teal', href: '/bas', tip: 'Novo', description: 'Visualização gráfica do caminho de ataque com todos os vetores explorados.' },
]

const COLOR_MAP = {
  cyan:   { border: 'border-l-4 border-cyan-600/40',   text: 'text-cyan-400',   hover: 'hover:border-cyan-500' },
  red:    { border: 'border-l-4 border-red-600/40',    text: 'text-red-400',    hover: 'hover:border-red-500' },
  orange: { border: 'border-l-4 border-orange-600/40', text: 'text-orange-400', hover: 'hover:border-orange-500' },
  green:  { border: 'border-l-4 border-green-600/40',  text: 'text-green-400',  hover: 'hover:border-green-500' },
  purple: { border: 'border-l-4 border-purple-600/40', text: 'text-purple-400', hover: 'hover:border-purple-500' },
  blue:   { border: 'border-l-4 border-blue-600/40',   text: 'text-blue-400',   hover: 'hover:border-blue-500' },
  yellow: { border: 'border-l-4 border-yellow-600/40', text: 'text-yellow-400', hover: 'hover:border-yellow-500' },
  gray:   { border: 'border-l-4 border-gray-600/40',   text: 'text-gray-400',   hover: 'hover:border-gray-500' },
  teal:   { border: 'border-l-4 border-teal-600/40',   text: 'text-teal-400',   hover: 'hover:border-teal-500' },
}

const ScoreTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-dark-700 border border-dark-500 rounded-lg p-3 text-xs shadow-xl">
      <p className="text-gray-400 mb-1">{label}</p>
      <p className="text-cyan-400 font-bold">Risco: {payload[0]?.value?.toFixed(1)}%</p>
      {payload[1] && <p className="text-green-400">Detecção: {payload[1]?.value?.toFixed(1)}%</p>}
    </div>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [stats, setStats] = useState({ status: 'online', modules: 9, operations: 0 })
  const [simulations, setSimulations] = useState([])
  const [loading, setLoading] = useState(true)
  const [wsStatus, setWsStatus] = useState('disconnected')
  const wsRef = useRef(null)
  const username = localStorage.getItem('username') || 'Pesquisador'

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) return
    const connect = () => {
      try {
        const ws = new WebSocket(`ws://localhost:8000/ws/dashboard`)
        wsRef.current = ws
        ws.onopen = () => setWsStatus('connected')
        ws.onclose = () => { setWsStatus('disconnected'); setTimeout(connect, 5000) }
        ws.onerror = () => ws.close()
        ws.onmessage = (e) => {
          try {
            const msg = JSON.parse(e.data)
            if (msg.type === 'init' && msg.simulations) {
              setSimulations(prev => {
                const map = new Map(prev.map(s => [s.id, s]))
                msg.simulations.forEach(s => map.set(s.id, { ...map.get(s.id), ...s }))
                return Array.from(map.values())
              })
            }
            if (msg.type === 'simulation_update') {
              setSimulations(prev => prev.map(s => s.id === msg.simulation_id ? { ...s, status: msg.status, score: msg.score } : s))
            }
          } catch {}
        }
        ws.onmessage._ping = setInterval(() => { if (ws.readyState === 1) ws.send('ping') }, 25000)
      } catch {}
    }
    connect()
    return () => {
      if (wsRef.current) wsRef.current.close()
    }
  }, [])

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statusRes, simsRes] = await Promise.all([
          api.get('/api/status'),
          api.get('/api/bas/simulations'),
        ])
        setStats({
          status: statusRes.data.status,
          modules: Object.keys(statusRes.data.modules || {}).length,
          operations: statusRes.data.active_operations ?? 0,
        })
        setSimulations(simsRes.data.simulations || [])
      } catch {
        setStats(s => ({ ...s, status: 'offline' }))
      } finally {
        setLoading(false)
      }
    }
    fetchData()
    const interval = setInterval(() => api.get('/api/status').then(r => setStats(s => ({
      ...s, status: r.data.status, operations: r.data.active_operations ?? s.operations
    }))).catch(() => setStats(s => ({ ...s, status: 'offline' }))), 15000)
    return () => clearInterval(interval)
  }, [])

  // Últimas 10 simulações completadas para trending
  const completedSims = simulations
    .filter(s => s.status === 'completed')
    .slice(-10)
    .map(s => ({
      date: format(new Date(s.date), 'dd/MM', { locale: ptBR }),
      risco: parseFloat(s.score?.toFixed(1) || 0),
      detecção: parseFloat((s.results?.detection_coverage_pct || 0).toFixed(1)),
      target: s.target,
      id: s.id,
      critical: (s.results?.techniques || []).filter(t => t.status === 'found' && t.cvss_severity === 'Critical').length,
    }))

  const avgScore = completedSims.length
    ? (completedSims.reduce((a, b) => a + b.risco, 0) / completedSims.length).toFixed(1)
    : 0
  const totalCritical = completedSims.reduce((a, b) => a + (b.critical || 0), 0)
  const latestSims = simulations.filter(s => s.status === 'completed').slice(0, 5)

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-1">
          Bem-vindo, <span className="text-red-500">{username}</span>
        </h1>
        <p className="text-gray-400">Plataforma de testes de segurança — PenteIA v4.0 · Apenas ambientes autorizados</p>
      </div>

      {/* Aviso Legal */}
      <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4 flex gap-3">
        <Lock className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
        <p className="text-red-300 text-sm">
          <strong>Uso exclusivo em ambientes autorizados.</strong> Todos os testes devem ter autorização prévia e por escrito do proprietário do sistema.
        </p>
      </div>

      {/* 4 Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard title="Status da Plataforma" value={stats.status === 'online' ? 'Online' : 'Offline'} icon={Activity} color={stats.status === 'online' ? 'green' : 'red'} />
        <StatCard title="Score Médio de Risco" value={`${avgScore}%`} icon={BarChart2} color="orange" />
        <StatCard title="Vulnerabilidades Críticas" value={totalCritical} icon={AlertCircle} color="red" />
        <StatCard title="Simulações Realizadas" value={completedSims.length} icon={Compass} color="blue" />
      </div>

      {/* Charts row */}
      {completedSims.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Line Chart: Score Trending */}
          <div className="card-dark p-5">
            <h2 className="text-base font-bold text-gray-100 mb-4 flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-cyan-400" />
              Evolução do Score de Risco
            </h2>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={completedSims} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="date" tick={{ fill: '#64748b', fontSize: 11 }} />
                <YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 11 }} />
                <Tooltip content={<ScoreTooltip />} />
                <Line type="monotone" dataKey="risco" stroke="#ef4444" strokeWidth={2} dot={{ fill: '#ef4444', r: 3 }} name="Risco %" />
                <Line type="monotone" dataKey="detecção" stroke="#22c55e" strokeWidth={2} dot={{ fill: '#22c55e', r: 3 }} name="Detecção %" strokeDasharray="4 2" />
              </LineChart>
            </ResponsiveContainer>
            <p className="text-xs text-gray-500 mt-2">— Risco (vermelho) · - - Cobertura de Detecção (verde)</p>
          </div>

          {/* Bar Chart: Últimas simulações score */}
          <div className="card-dark p-5">
            <h2 className="text-base font-bold text-gray-100 mb-4 flex items-center gap-2">
              <Activity className="w-4 h-4 text-orange-400" />
              Histórico Recente de Simulações
            </h2>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={completedSims.slice(-6)} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="date" tick={{ fill: '#64748b', fontSize: 11 }} />
                <YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 11 }} />
                <Tooltip content={<ScoreTooltip />} />
                <Bar dataKey="risco" fill="#ef4444" radius={[3, 3, 0, 0]} name="Risco %" />
                <Bar dataKey="detecção" fill="#22c55e" radius={[3, 3, 0, 0]} name="Detecção %" />
              </BarChart>
            </ResponsiveContainer>
            <p className="text-xs text-gray-500 mt-2">Últimas 6 simulações · vermelho=risco · verde=detecção</p>
          </div>
        </div>
      )}

      {/* Últimas Simulações Table */}
      {latestSims.length > 0 && (
        <div className="card-dark p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-bold text-gray-100 flex items-center gap-2">
              <Clock className="w-4 h-4 text-blue-400" />
              Últimas Simulações
            </h2>
            <a href="/bas" className="text-xs text-cyan-400 hover:text-cyan-300">Ver todas →</a>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-500 border-b border-dark-600">
                  <th className="text-left pb-2 font-medium">Target</th>
                  <th className="text-left pb-2 font-medium">Data</th>
                  <th className="text-center pb-2 font-medium">Score Risco</th>
                  <th className="text-center pb-2 font-medium">Detecção</th>
                  <th className="text-center pb-2 font-medium">Ação</th>
                </tr>
              </thead>
              <tbody>
                {latestSims.map(s => {
                  const score = s.score || 0
                  const det = s.results?.detection_coverage_pct || 0
                  const scoreColor = score >= 60 ? 'text-red-400 bg-red-900/30' : score >= 30 ? 'text-yellow-400 bg-yellow-900/30' : 'text-green-400 bg-green-900/30'
                  return (
                    <tr key={s.id} className="border-b border-dark-700/50 hover:bg-dark-700/30 transition">
                      <td className="py-2.5 text-gray-300 font-mono text-xs">{s.target}</td>
                      <td className="py-2.5 text-gray-400 text-xs">{format(new Date(s.date), 'dd/MM/yyyy HH:mm', { locale: ptBR })}</td>
                      <td className="py-2.5 text-center">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold ${scoreColor}`}>{score.toFixed(1)}%</span>
                      </td>
                      <td className="py-2.5 text-center">
                        <span className={`text-xs font-medium ${det >= 70 ? 'text-green-400' : det >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>{det.toFixed(1)}%</span>
                      </td>
                      <td className="py-2.5 text-center">
                        <button
                          onClick={() => navigate(`/attack-path/${s.id}`)}
                          className="text-xs text-cyan-400 hover:text-cyan-300 border border-cyan-800/50 hover:border-cyan-600 px-2 py-0.5 rounded transition"
                        >
                          Ver Grafo
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Por onde começar */}
      <div className="card-dark p-6 border-l-4 border-blue-600">
        <div className="flex items-center gap-2 mb-5">
          <BookOpen className="w-5 h-5 text-blue-400" />
          <h2 className="text-xl font-bold text-gray-100">Por onde começar?</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { step: '1', title: 'Faça o Reconhecimento', desc: 'Descubra IPs, portas abertas e serviços do alvo antes de qualquer teste.', href: '/recon', color: 'text-blue-400', borderColor: 'border-blue-600/40' },
            { step: '2', title: 'Execute os Testes', desc: 'Use BAS para simular 150+ técnicas MITRE ATT&CK com agendamento automático.', href: '/bas', color: 'text-yellow-400', borderColor: 'border-yellow-600/40' },
            { step: '3', title: 'Gere o Relatório', desc: 'Relatórios em PDF com mapeamento LGPD, ISO 27001 e PCI DSS.', href: '/reporting', color: 'text-green-400', borderColor: 'border-green-600/40' },
          ].map(({ step, title, desc, href, color, borderColor }) => (
            <a key={step} href={href} className={`bg-dark-700 border ${borderColor} rounded-lg p-5 hover:bg-dark-600 transition group`}>
              <div className={`text-4xl font-black ${color} mb-3 group-hover:scale-110 inline-block transition-transform`}>{step}</div>
              <h3 className="font-bold text-gray-100 mb-2">{title}</h3>
              <p className="text-sm text-gray-400 leading-relaxed">{desc}</p>
            </a>
          ))}
        </div>
      </div>

      {/* Módulos da Plataforma */}
      <div>
        <h2 className="text-2xl font-bold text-gray-100 mb-4">Módulos da Plataforma</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {MODULE_INFO.map((mod) => {
            const Icon = mod.icon
            const c = COLOR_MAP[mod.color]
            return (
              <a key={mod.name} href={mod.href} className={`card-dark p-5 ${c.border} ${c.hover} transition group`}>
                <div className="flex items-start justify-between mb-3">
                  <Icon className={`w-6 h-6 ${c.text}`} />
                  <span className="text-xs bg-dark-700 text-gray-400 px-2 py-0.5 rounded border border-dark-600">{mod.tip}</span>
                </div>
                <h3 className={`font-bold text-gray-100 mb-2 group-hover:${c.text} transition text-sm`}>{mod.name}</h3>
                <p className="text-xs text-gray-400 leading-relaxed">{mod.description}</p>
              </a>
            )
          })}
        </div>
      </div>
    </div>
  )
}
