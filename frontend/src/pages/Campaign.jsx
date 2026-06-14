import React, { useState, useEffect, useRef, useCallback } from 'react'
import {
  Play, StopCircle, CheckCircle, XCircle, AlertTriangle,
  Loader, ChevronRight, BarChart2, Shield, Wifi, Info,
  Download, Trash2, Clock, Zap, Target, FileText
} from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

const METHODS = [
  { id: 'http_flood',       label: 'HTTP Flood',        desc: 'Envia milhares de requisições HTTP para saturar o servidor web', color: 'text-red-400',    bg: 'bg-red-950/30' },
  { id: 'slowloris',        label: 'Slowloris',         desc: 'Abre muitas conexões lentas para esgotar os slots disponíveis', color: 'text-orange-400', bg: 'bg-orange-950/30' },
  { id: 'udp_flood',        label: 'UDP Flood',         desc: 'Envia pacotes UDP em massa para saturar a largura de banda',    color: 'text-yellow-400', bg: 'bg-yellow-950/30' },
  { id: 'syn_flood',        label: 'SYN Flood',         desc: 'Explora o handshake TCP para esgotar conexões pendentes',       color: 'text-purple-400', bg: 'bg-purple-950/30' },
  { id: 'dns_amplification',label: 'DNS Amplification', desc: 'Usa servidores DNS para amplificar o tráfego de ataque',       color: 'text-blue-400',   bg: 'bg-blue-950/30' },
  { id: 'icmp_flood',       label: 'ICMP Flood',        desc: 'Envia pings em massa para sobrecarregar a camada de rede',      color: 'text-cyan-400',   bg: 'bg-cyan-950/30' },
]

function EffBar({ value }) {
  const color = value >= 80 ? 'bg-red-500' : value >= 50 ? 'bg-orange-500' : value >= 25 ? 'bg-yellow-500' : 'bg-green-500'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-dark-700 rounded-full h-2">
        <div className={`${color} h-2 rounded-full transition-all duration-700`} style={{ width: `${value}%` }} />
      </div>
      <span className="text-xs font-bold w-8 text-right">{value}%</span>
    </div>
  )
}

function VerdictBadge({ verdict }) {
  const map = {
    'Servidor derrubado':  { color: 'bg-red-900/60 text-red-400 border-red-700/50',      icon: <XCircle className="w-3.5 h-3.5" /> },
    'Servico degradado':   { color: 'bg-orange-900/60 text-orange-400 border-orange-700/50', icon: <AlertTriangle className="w-3.5 h-3.5" /> },
    'Impacto moderado':    { color: 'bg-yellow-900/60 text-yellow-400 border-yellow-700/50', icon: <AlertTriangle className="w-3.5 h-3.5" /> },
    'Servidor resistiu':   { color: 'bg-green-900/60 text-green-400 border-green-700/50',   icon: <CheckCircle className="w-3.5 h-3.5" /> },
  }
  const v = map[verdict] || map['Servidor resistiu']
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border font-semibold ${v.color}`}>
      {v.icon} {verdict}
    </span>
  )
}

export default function Campaign() {
  const toast = useToast()
  const pollRef = useRef(null)

  const [step, setStep] = useState('config') // config | running | done
  const [campaignId, setCampaignId] = useState(null)
  const [campaignState, setCampaignState] = useState(null)
  const [pastCampaigns, setPastCampaigns] = useState([])
  const [viewingPast, setViewingPast] = useState(null)

  const [form, setForm] = useState({
    target_host: 'localhost',
    target_port: 9090,
    duration_per_method: 30,
    threads: 8,
    pps: 200,
    run_recon: true,
    methods: ['http_flood', 'slowloris', 'udp_flood'],
  })

  const fetchPast = useCallback(async () => {
    try {
      const r = await api.get('/api/campaign/list')
      setPastCampaigns((r.data.campaigns || []).reverse())
    } catch { /* silencia */ }
  }, [])

  useEffect(() => { fetchPast() }, [fetchPast])

  const toggleMethod = (id) => {
    setForm(f => ({
      ...f,
      methods: f.methods.includes(id) ? f.methods.filter(m => m !== id) : [...f.methods, id],
    }))
  }

  const startCampaign = async () => {
    if (!form.target_host.trim()) { toast('Informe o host alvo', 'warning'); return }
    if (form.methods.length === 0) { toast('Selecione ao menos um método de ataque', 'warning'); return }
    try {
      const r = await api.post('/api/campaign/start', {
        target_host:        form.target_host.trim(),
        target_port:        Number(form.target_port),
        methods:            form.methods,
        duration_per_method: Number(form.duration_per_method),
        threads:            Number(form.threads),
        pps:                Number(form.pps),
        run_recon:          form.run_recon,
      })
      setCampaignId(r.data.campaign_id)
      setStep('running')
    } catch (e) {
      toast('Erro ao iniciar campanha: ' + (e.response?.data?.detail || e.message), 'error')
    }
  }

  useEffect(() => {
    if (step !== 'running' || !campaignId) return
    const poll = async () => {
      try {
        const r = await api.get(`/api/campaign/status/${campaignId}`)
        setCampaignState(r.data)
        if (r.data.status === 'done' || r.data.status === 'error') {
          clearInterval(pollRef.current)
          setStep('done')
          fetchPast()
        }
      } catch { /* silencia */ }
    }
    poll()
    pollRef.current = setInterval(poll, 2000)
    return () => clearInterval(pollRef.current)
  }, [step, campaignId, fetchPast])

  const reset = () => {
    setStep('config')
    setCampaignId(null)
    setCampaignState(null)
    setViewingPast(null)
  }

  const deleteCampaign = async (id) => {
    try {
      await api.delete(`/api/campaign/${id}`)
      fetchPast()
      if (viewingPast?.id === id) setViewingPast(null)
      toast('Campanha removida', 'info')
    } catch (e) {
      toast('Erro: ' + (e.response?.data?.detail || e.message), 'error')
    }
  }

  const activeReport = viewingPast?.report ?? campaignState?.report
  const activeState  = viewingPast ?? campaignState

  // ── FASE CONFIG ─────────────────────────────────────────────────────────────
  if (step === 'config' && !viewingPast) return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">Campanha Automatizada</h1>
        <p className="text-gray-400">Execute múltiplos testes em sequência, colete métricas e gere um relatório completo automaticamente.</p>
      </div>

      {/* Explicação */}
      <div className="card-dark p-5 border-l-4 border-purple-600 flex gap-3 bg-purple-900/10">
        <Info className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-gray-300 leading-relaxed">
          <strong className="text-purple-400">O que é uma Campanha?</strong><br />
          Em vez de testar cada método de ataque separadamente, a campanha executa <strong>todos os métodos selecionados em sequência</strong>,
          mede o impacto de cada um (latência, erros, disponibilidade) e gera um relatório comparativo automaticamente.
          Ideal para avaliações completas de resiliência.
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Configuração */}
        <div className="lg:col-span-2 space-y-6">
          <div className="card-dark p-6">
            <h2 className="text-xl font-bold text-gray-100 mb-5 flex items-center gap-2">
              <Target className="w-5 h-5 text-red-400" /> Alvo da Campanha
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="sm:col-span-2">
                <label className="block text-xs text-gray-400 mb-1">Host / IP</label>
                <input className="input-dark w-full" value={form.target_host}
                  onChange={e => setForm(f => ({ ...f, target_host: e.target.value }))}
                  placeholder="ex: localhost ou 192.168.1.1" />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Porta</label>
                <input className="input-dark w-full" type="number" value={form.target_port}
                  onChange={e => setForm(f => ({ ...f, target_port: e.target.value }))} />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Duração por método (s)</label>
                <input className="input-dark w-full" type="number" min={10} max={120} value={form.duration_per_method}
                  onChange={e => setForm(f => ({ ...f, duration_per_method: e.target.value }))} />
                <p className="text-xs text-gray-600 mt-1">10 a 120 segundos</p>
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Threads</label>
                <input className="input-dark w-full" type="number" min={1} max={32} value={form.threads}
                  onChange={e => setForm(f => ({ ...f, threads: e.target.value }))} />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Requisições/s (pps)</label>
                <input className="input-dark w-full" type="number" min={50} max={2000} value={form.pps}
                  onChange={e => setForm(f => ({ ...f, pps: e.target.value }))} />
              </div>
            </div>
            <label className="flex items-center gap-2 mt-4 cursor-pointer">
              <input type="checkbox" className="w-4 h-4 accent-purple-500"
                checked={form.run_recon} onChange={e => setForm(f => ({ ...f, run_recon: e.target.checked }))} />
              <span className="text-sm text-gray-300">Executar reconhecimento antes dos ataques</span>
              <span className="text-xs text-gray-500">(detecta headers, baseline de latência e IP real)</span>
            </label>
          </div>

          <div className="card-dark p-6">
            <h2 className="text-xl font-bold text-gray-100 mb-2 flex items-center gap-2">
              <Zap className="w-5 h-5 text-yellow-400" /> Métodos de Ataque
            </h2>
            <p className="text-gray-400 text-sm mb-4">Selecione os métodos que serão executados em sequência.</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {METHODS.map(m => {
                const selected = form.methods.includes(m.id)
                return (
                  <button key={m.id} onClick={() => toggleMethod(m.id)}
                    className={`text-left p-4 rounded-lg border-2 transition ${
                      selected ? 'border-purple-500 bg-purple-900/20' : 'border-dark-600 bg-dark-700 hover:border-dark-500'
                    }`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className={`text-sm font-bold ${selected ? 'text-purple-300' : 'text-gray-200'}`}>{m.label}</span>
                      {selected && <CheckCircle className="w-4 h-4 text-purple-400" />}
                    </div>
                    <p className="text-xs text-gray-500 leading-relaxed">{m.desc}</p>
                  </button>
                )
              })}
            </div>
            {form.methods.length > 0 && (
              <p className="text-sm text-gray-400 mt-4">
                Tempo total estimado:
                <strong className="text-gray-100 ml-1">
                  ~{Math.ceil((form.methods.length * Number(form.duration_per_method) + (form.run_recon ? 15 : 0)) / 60)} min
                  ({form.methods.length * Number(form.duration_per_method)}s de ataque)
                </strong>
              </p>
            )}
          </div>
        </div>

        {/* Painel lateral */}
        <div className="space-y-6">
          <div className="card-dark p-5">
            <h3 className="font-bold text-gray-100 mb-4 text-sm">Resumo da campanha</h3>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Alvo</span>
                <span className="text-gray-100 font-mono">{form.target_host}:{form.target_port}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Métodos</span>
                <span className="text-gray-100">{form.methods.length} selecionados</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Duração</span>
                <span className="text-gray-100">{form.duration_per_method}s por método</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Reconhecimento</span>
                <span className={form.run_recon ? 'text-green-400' : 'text-gray-500'}>
                  {form.run_recon ? 'Ativado' : 'Desativado'}
                </span>
              </div>
            </div>
            <div className="mt-5">
              <div className="text-xs text-gray-500 mb-1">Ordem de execução:</div>
              {form.run_recon && (
                <div className="flex items-center gap-2 text-xs text-gray-400 mb-1">
                  <ChevronRight className="w-3 h-3 text-purple-400" /> Reconhecimento
                </div>
              )}
              {form.methods.map((id, i) => {
                const m = METHODS.find(x => x.id === id)
                return (
                  <div key={id} className="flex items-center gap-2 text-xs mb-1">
                    <ChevronRight className={`w-3 h-3 ${m?.color || 'text-gray-400'}`} />
                    <span className="text-gray-300">{m?.label || id}</span>
                  </div>
                )
              })}
              <div className="flex items-center gap-2 text-xs text-gray-400 mt-1">
                <ChevronRight className="w-3 h-3 text-blue-400" /> Relatório automático
              </div>
            </div>
          </div>

          <button onClick={startCampaign} disabled={form.methods.length === 0}
            className="w-full btn-blue flex items-center justify-center gap-2 py-4 text-base disabled:opacity-40">
            <Play className="w-5 h-5" /> Iniciar Campanha
          </button>

          {/* Campanhas anteriores */}
          {pastCampaigns.length > 0 && (
            <div className="card-dark p-5">
              <h3 className="font-bold text-gray-100 mb-3 text-sm">Campanhas anteriores</h3>
              <div className="space-y-2">
                {pastCampaigns.slice(0, 5).map(c => (
                  <div key={c.id} className="flex items-center justify-between p-2 rounded bg-dark-700">
                    <button className="text-left flex-1" onClick={() => {
                      api.get(`/api/campaign/status/${c.id}`).then(r => setViewingPast(r.data))
                    }}>
                      <p className="text-xs font-mono text-gray-300">{c.target}</p>
                      <p className="text-xs text-gray-500">{c.methods.length} métodos · {c.status}</p>
                    </button>
                    <button onClick={() => deleteCampaign(c.id)} className="text-gray-600 hover:text-red-400 ml-2">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )

  // ── FASE RUNNING ─────────────────────────────────────────────────────────────
  if (step === 'running') {
    const s = campaignState
    const methodsTotal = form.methods.length
    const methodsDone  = s ? s.results.length : 0
    const phasePct = s?.phase === 'report' ? 100
      : s?.phase === 'recon' ? 5
      : methodsTotal > 0 ? Math.round((methodsDone / methodsTotal) * 90 + 5)
      : 0

    return (
      <div className="space-y-8 max-w-3xl mx-auto">
        <div className="slide-in text-center">
          <h1 className="text-3xl font-bold text-gray-100 mb-2">Campanha em Execução</h1>
          <p className="text-gray-400 text-sm">Não feche esta aba. Os resultados aparecem em tempo real abaixo.</p>
        </div>

        <div className="card-dark p-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-semibold text-gray-300">
              {s?.phase_label || 'Iniciando...'}
            </span>
            <span className="text-sm text-gray-400">{phasePct}%</span>
          </div>
          <div className="w-full bg-dark-700 rounded-full h-3 mb-4">
            <div className="bg-purple-600 h-3 rounded-full transition-all duration-500" style={{ width: `${phasePct}%` }} />
          </div>

          {/* Passos */}
          <div className="flex items-center gap-1 flex-wrap">
            {form.run_recon && (
              <span className={`text-xs px-2 py-1 rounded-full border ${
                s?.phase === 'recon' ? 'bg-purple-900/30 border-purple-600 text-purple-300' :
                s?.recon?.baseline_ms ? 'bg-green-900/30 border-green-700 text-green-400' : 'border-dark-600 text-gray-600'
              }`}>Recon</span>
            )}
            {form.methods.map((id, i) => {
              const done = s ? i < s.results.length : false
              const active = s?.current_method === id && s?.status === 'running'
              const m = METHODS.find(x => x.id === id)
              return (
                <span key={id} className={`text-xs px-2 py-1 rounded-full border ${
                  active ? 'bg-yellow-900/30 border-yellow-600 text-yellow-300' :
                  done   ? 'bg-green-900/30 border-green-700 text-green-400' : 'border-dark-600 text-gray-600'
                }`}>
                  {done && <span className="mr-1">✓</span>}{m?.label || id}
                </span>
              )
            })}
            <span className={`text-xs px-2 py-1 rounded-full border ${
              s?.phase === 'report' ? 'bg-blue-900/30 border-blue-600 text-blue-300' : 'border-dark-600 text-gray-600'
            }`}>Relatório</span>
          </div>

          {/* Live probe */}
          {s?.live_probe && (
            <div className={`mt-4 p-3 rounded text-xs font-mono ${s.live_probe.ok ? 'bg-green-950/30 text-green-300' : 'bg-red-950/30 text-red-400'}`}>
              Última sonda ao alvo: {s.live_probe.ok
                ? `HTTP ${s.live_probe.code} em ${s.live_probe.ms}ms`
                : `FALHOU — ${s.live_probe.reason || 'timeout'} (${s.live_probe.ms}ms)`
              } (t+{s.live_probe.elapsed}s)
            </div>
          )}
        </div>

        {/* Resultados parciais */}
        {s?.results?.length > 0 && (
          <div className="card-dark p-6">
            <h2 className="text-lg font-bold text-gray-100 mb-4">Resultados parciais</h2>
            <div className="space-y-3">
              {s.results.map(r => (
                <div key={r.method} className="flex items-center justify-between p-3 rounded bg-dark-700 border border-dark-600">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-bold text-gray-100">{r.method_label}</span>
                      <VerdictBadge verdict={r.verdict} />
                    </div>
                    <EffBar value={r.effectiveness} />
                  </div>
                  <div className="text-right ml-4">
                    <p className="text-xs text-gray-400">Latência pico</p>
                    <p className="text-sm font-mono text-orange-300">{r.peak_latency_ms}ms</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recon parcial */}
        {s?.recon?.baseline_ms && (
          <div className="card-dark p-4 text-sm">
            <h3 className="text-gray-400 mb-2 text-xs font-semibold uppercase tracking-wide">Reconhecimento</h3>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div><span className="text-gray-500">IP: </span><span className="text-gray-100 font-mono">{s.recon.resolved_ip || s.recon.host}</span></div>
              <div><span className="text-gray-500">Servidor: </span><span className="text-gray-100">{s.recon.server_header || 'n/d'}</span></div>
              <div><span className="text-gray-500">Latência base: </span><span className="text-green-300">{s.recon.baseline_ms}ms</span></div>
              <div><span className="text-gray-500">CSP ativo: </span><span className={s.recon.has_csp ? 'text-green-400' : 'text-red-400'}>{s.recon.has_csp ? 'Sim' : 'Não'}</span></div>
            </div>
          </div>
        )}
      </div>
    )
  }

  // ── RELATÓRIO (done ou past) ─────────────────────────────────────────────────
  const rep = activeReport
  if ((step === 'done' || viewingPast) && rep) {
    const bestMethod = METHODS.find(m => m.id === rep.best_method)
    return (
      <div className="space-y-8">
        <div className="slide-in flex items-center justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-3xl font-bold text-gray-100 mb-1">Relatório de Campanha</h1>
            <p className="text-gray-400 text-sm font-mono">{rep.target} · {rep.total_methods} método(s) · {rep.total_duration}s de testes</p>
          </div>
          <button onClick={reset} className="btn-outline-red text-sm flex items-center gap-2">
            <Play className="w-4 h-4" /> Nova campanha
          </button>
        </div>

        {/* Cards de resumo */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="card-dark p-5 border-l-4 border-purple-600">
            <p className="text-xs text-gray-400 mb-1">Métodos testados</p>
            <p className="text-3xl font-bold text-gray-100">{rep.total_methods}</p>
          </div>
          <div className="card-dark p-5 border-l-4 border-red-600">
            <p className="text-xs text-gray-400 mb-1">Método mais efetivo</p>
            <p className="text-lg font-bold text-red-400">{bestMethod?.label || rep.best_label || 'N/A'}</p>
          </div>
          <div className="card-dark p-5 border-l-4 border-orange-600">
            <p className="text-xs text-gray-400 mb-1">Efetividade máxima</p>
            <p className="text-3xl font-bold text-orange-400">{rep.best_eff}%</p>
          </div>
          <div className="card-dark p-5 border-l-4 border-blue-600">
            <p className="text-xs text-gray-400 mb-1">Duração total</p>
            <p className="text-3xl font-bold text-gray-100">{rep.total_duration}s</p>
          </div>
        </div>

        {/* Recon */}
        {rep.recon?.baseline_ms && (
          <div className="card-dark p-6">
            <h2 className="text-xl font-bold text-gray-100 mb-4 flex items-center gap-2">
              <Wifi className="w-5 h-5 text-blue-400" /> Reconhecimento do Alvo
            </h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div className="bg-dark-700 rounded p-3">
                <p className="text-xs text-gray-500 mb-1">IP Resolvido</p>
                <p className="font-mono text-gray-100">{rep.recon.resolved_ip || rep.recon.host}</p>
              </div>
              <div className="bg-dark-700 rounded p-3">
                <p className="text-xs text-gray-500 mb-1">Servidor HTTP</p>
                <p className="text-gray-100">{rep.recon.server_header || 'n/d'}</p>
              </div>
              <div className="bg-dark-700 rounded p-3">
                <p className="text-xs text-gray-500 mb-1">Latência base</p>
                <p className="text-green-300 font-bold">{rep.recon.baseline_ms}ms</p>
              </div>
              <div className="bg-dark-700 rounded p-3">
                <p className="text-xs text-gray-500 mb-1">Proteções HTTP</p>
                <div className="space-y-0.5">
                  <p className={`text-xs ${rep.recon.has_csp ? 'text-green-400' : 'text-red-400'}`}>
                    {rep.recon.has_csp ? '✓' : '✗'} CSP
                  </p>
                  <p className={`text-xs ${rep.recon.has_hsts ? 'text-green-400' : 'text-red-400'}`}>
                    {rep.recon.has_hsts ? '✓' : '✗'} HSTS
                  </p>
                  <p className={`text-xs ${rep.recon.has_ratelimit ? 'text-green-400' : 'text-red-400'}`}>
                    {rep.recon.has_ratelimit ? '✓' : '✗'} Rate Limit header
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Resultados por método */}
        <div className="card-dark p-6">
          <h2 className="text-xl font-bold text-gray-100 mb-4 flex items-center gap-2">
            <BarChart2 className="w-5 h-5 text-purple-400" /> Resultados por Método
          </h2>
          <div className="space-y-4">
            {rep.results.map(r => {
              const mInfo = METHODS.find(m => m.id === r.method)
              const isBest = r.method === rep.best_method
              return (
                <div key={r.method} className={`p-5 rounded-lg border ${isBest ? 'border-red-700/50 bg-red-950/20' : 'border-dark-600 bg-dark-700'}`}>
                  <div className="flex items-center justify-between flex-wrap gap-3 mb-3">
                    <div className="flex items-center gap-2">
                      <span className={`font-bold text-lg ${mInfo?.color || 'text-gray-100'}`}>{r.method_label}</span>
                      {isBest && <span className="text-xs bg-red-900/50 text-red-400 px-2 py-0.5 border border-red-700/50 rounded">Mais efetivo</span>}
                    </div>
                    <VerdictBadge verdict={r.verdict} />
                  </div>
                  <div className="mb-3">
                    <div className="flex justify-between text-xs text-gray-400 mb-1">
                      <span>Efetividade do ataque</span>
                      <span>{r.effectiveness}%</span>
                    </div>
                    <EffBar value={r.effectiveness} />
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
                    <div className="bg-dark-800 rounded p-2">
                      <p className="text-gray-500">Latência base</p>
                      <p className="text-gray-100 font-bold">{r.baseline_ms}ms</p>
                    </div>
                    <div className="bg-dark-800 rounded p-2">
                      <p className="text-gray-500">Latência média</p>
                      <p className={`font-bold ${r.avg_latency_ms > r.baseline_ms * 3 ? 'text-red-400' : 'text-orange-300'}`}>{r.avg_latency_ms}ms</p>
                    </div>
                    <div className="bg-dark-800 rounded p-2">
                      <p className="text-gray-500">Pico de latência</p>
                      <p className="text-red-400 font-bold">{r.peak_latency_ms}ms</p>
                    </div>
                    <div className="bg-dark-800 rounded p-2">
                      <p className="text-gray-500">Sondas falhadas</p>
                      <p className={`font-bold ${r.fail_pct > 50 ? 'text-red-400' : 'text-yellow-400'}`}>{r.fail_pct}%</p>
                    </div>
                    <div className="bg-dark-800 rounded p-2">
                      <p className="text-gray-500">Pacotes enviados</p>
                      <p className="text-gray-100 font-bold">{(r.requests_sent || 0).toLocaleString()}</p>
                    </div>
                  </div>
                  {r.latency_inc_pct > 0 && (
                    <p className="text-xs text-gray-500 mt-2">
                      Aumento de latência: <span className="text-orange-400 font-semibold">{r.latency_inc_pct}%</span> acima da linha de base
                    </p>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Recomendações */}
        {rep.recommendations?.length > 0 && (
          <div className="card-dark p-6">
            <h2 className="text-xl font-bold text-gray-100 mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5 text-green-400" /> Recomendações de Segurança
            </h2>
            <div className="space-y-3">
              {rep.recommendations.map((rec, i) => (
                <div key={i} className="flex gap-3 p-4 rounded bg-dark-700 border border-dark-600">
                  <span className="text-green-400 font-bold text-sm flex-shrink-0">{i + 1}.</span>
                  <p className="text-gray-300 text-sm leading-relaxed">{rec}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        <p className="text-xs text-gray-600 text-center">
          Campanha finalizada em {rep.finished_at ? new Date(rep.finished_at).toLocaleString('pt-BR') : '—'}
          · Ambiente de teste autorizado · PenteIA v4.0
        </p>
      </div>
    )
  }

  // Loading intermediário
  return (
    <div className="flex flex-col items-center justify-center py-24 gap-4">
      <Loader className="w-10 h-10 text-purple-400 animate-spin" />
      <p className="text-gray-400">Aguardando dados da campanha...</p>
    </div>
  )
}
