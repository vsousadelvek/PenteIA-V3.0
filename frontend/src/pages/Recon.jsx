import React, { useState, useRef, useEffect, useCallback } from 'react'
import { Search, AlertTriangle, Loader, X, Globe, ShieldOff, CheckCircle, XCircle, Zap, BookOpen } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

export default function Recon() {
  const toast = useToast()
  const [resolveTarget, setResolveTarget] = useState('localhost')
  const [scanTarget, setScanTarget] = useState('localhost')
  const [scanPorts, setScanPorts] = useState('top')
  const [scanTimeout, setScanTimeout] = useState(1.0)
  const [scanWorkers, setScanWorkers] = useState(50)
  const [resolveResult, setResolveResult] = useState(null)
  const [scanResult, setScanResult] = useState(null)
  const [resolving, setResolving] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [progressTotal, setProgressTotal] = useState(0)
  const abortRef = useRef(null)

  const [ipInfoTarget, setIpInfoTarget] = useState('')
  const [ipInfoResult, setIpInfoResult] = useState(null)
  const [loadingIpInfo, setLoadingIpInfo] = useState(false)

  // CloudFail state
  const [cfDomain, setCfDomain] = useState('')
  const [cfJobId, setCfJobId] = useState(null)
  const [cfJob, setCfJob] = useState(null)
  const [cfLoading, setCfLoading] = useState(false)

  // CDN Bypass state
  const [cdnDomain, setCdnDomain] = useState('')
  const [cdnResult, setCdnResult] = useState(null)
  const [cdnLoading, setCdnLoading] = useState(false)

  // Serverless Recon state
  const [serverlessDomain, setServerlessDomain] = useState('')
  const [serverlessResult, setServerlessResult] = useState(null)
  const [serverlessLoading, setServerlessLoading] = useState(false)

  const resolveDomain = async () => {
    if (!resolveTarget.trim()) { toast('Digite um alvo!', 'warning'); return }
    setResolving(true)
    try {
      const res = await api.post('/api/recon/resolve', { domain: resolveTarget })
      setResolveResult(res.data)
    } catch (err) {
      toast(err.response?.data?.detail || 'Erro ao resolver domínio', 'error')
    } finally {
      setResolving(false)
    }
  }

  const cancelScan = () => {
    if (abortRef.current) { abortRef.current.abort(); abortRef.current = null }
    setScanning(false)
    setProgress(0)
    setProgressTotal(0)
  }

  const scanPortsFn = async () => {
    if (!scanTarget.trim()) { toast('Digite um alvo!', 'warning'); return }
    setScanning(true)
    setScanResult(null)
    setProgress(0)
    setProgressTotal(0)

    let taskId, total
    try {
      const res = await api.post('/api/recon/scan', {
        host: scanTarget,
        ports: scanPorts,
        timeout: scanTimeout,
        workers: scanWorkers,
      })
      taskId = res.data.task_id
      total = res.data.total
      setProgressTotal(total)
    } catch (err) {
      toast(err.response?.data?.detail || 'Erro ao iniciar varredura', 'error')
      setScanning(false)
      return
    }

    // SSE via fetch (EventSource não suporta header Authorization)
    const controller = new AbortController()
    abortRef.current = controller
    const token = localStorage.getItem('token')

    try {
      const resp = await fetch(`/api/recon/scan/stream/${taskId}`, {
        headers: { Authorization: `Bearer ${token}` },
        signal: controller.signal,
      })

      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)

      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop()

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          let msg
          try { msg = JSON.parse(line.slice(6)) } catch { continue }

          if (msg.progress !== undefined) {
            setProgress(msg.progress)
            setProgressTotal(msg.total)
          }
          if (msg.done) {
            if (msg.error) {
              toast(`Erro: ${msg.error}`, 'error')
            } else {
              setScanResult({ host: msg.host, results: msg.results })
            }
            setScanning(false)
            setProgress(0)
            setProgressTotal(0)
            abortRef.current = null
            return
          }
        }
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        toast('Erro ao receber progresso do scan', 'error')
      }
      setScanning(false)
      setProgress(0)
      setProgressTotal(0)
    }
  }

  const lookupIpInfo = async () => {
    if (!ipInfoTarget.trim()) { toast('Digite um IP para consultar', 'warning'); return }
    setLoadingIpInfo(true)
    setIpInfoResult(null)
    try {
      const res = await api.post('/api/recon/ipinfo', { ip: ipInfoTarget.trim() })
      setIpInfoResult(res.data)
    } catch (err) {
      toast(err.response?.data?.detail || 'Erro ao consultar IP', 'error')
    } finally {
      setLoadingIpInfo(false)
    }
  }

  const runCdnCheck = async () => {
    if (!cdnDomain.trim()) { toast('Digite um domínio', 'warning'); return }
    setCdnLoading(true); setCdnResult(null)
    try {
      const res = await api.post('/api/recon/cdn-check', { domain: cdnDomain.trim() })
      setCdnResult(res.data)
    } catch (err) {
      toast(err.response?.data?.detail || 'Erro na análise CDN', 'error')
    } finally { setCdnLoading(false) }
  }

  const runServerlessRecon = async () => {
    if (!serverlessDomain.trim()) { toast('Digite um domínio', 'warning'); return }
    setServerlessLoading(true); setServerlessResult(null)
    try {
      const res = await api.post('/api/recon/serverless', { domain: serverlessDomain.trim(), use_ssl: true })
      setServerlessResult(res.data)
    } catch (err) {
      toast(err.response?.data?.detail || 'Erro no serverless recon', 'error')
    } finally { setServerlessLoading(false) }
  }

  // CloudFail polling
  const stopCfPoll = useRef(null)

  const startCloudfail = async () => {
    if (!cfDomain.trim()) { toast('Digite um domínio', 'warning'); return }
    setCfLoading(true); setCfJob(null)
    try {
      const res = await api.post('/api/recon/cloudfail', { domain: cfDomain.trim() })
      setCfJobId(res.data.job_id)
      setCfJob({ status: 'starting', progress: 0, total: res.data.total, found: [], domain: res.data.domain })
    } catch (err) {
      toast(err.response?.data?.detail || 'Erro ao iniciar CloudFail', 'error')
    } finally { setCfLoading(false) }
  }

  useEffect(() => {
    if (!cfJobId) return
    const interval = setInterval(async () => {
      try {
        const res = await api.get(`/api/recon/cloudfail/${cfJobId}`)
        setCfJob(res.data)
        if (res.data.status === 'completed' || res.data.status === 'error') {
          clearInterval(interval)
        }
      } catch { clearInterval(interval) }
    }, 1500)
    stopCfPoll.current = interval
    return () => clearInterval(interval)
  }, [cfJobId])

  const cfPct = cfJob?.total > 0 ? Math.round((cfJob.progress / cfJob.total) * 100) : 0
  const pct = progressTotal > 0 ? Math.round((progress / progressTotal) * 100) : 0

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">Reconhecimento</h1>
        <p className="text-gray-400">Coleta informações sobre o alvo antes de executar qualquer teste</p>
      </div>

      {/* O que é Reconhecimento */}
      <div className="card-dark p-6 bg-cyan-900/10 border-l-4 border-cyan-600">
        <div className="flex items-center gap-2 mb-3">
          <BookOpen className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-bold text-gray-100">O que é Reconhecimento?</h2>
        </div>
        <p className="text-gray-300 text-sm mb-4 leading-relaxed">
          O reconhecimento é a <strong>primeira etapa de qualquer teste de segurança</strong>. Antes de testar vulnerabilidades,
          você precisa conhecer o alvo: quais serviços ele usa, em quais portas eles rodam, e se há proteções como CDN ou Cloudflare.
          Quanto mais informações você coletar aqui, mais eficientes serão os testes seguintes.
        </p>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-xs">
          {[
            { name: 'Resolução de Domínio', desc: 'Descobre o IP de um domínio' },
            { name: 'Varredura de Portas', desc: 'Vê quais serviços estão abertos' },
            { name: 'Consulta de IP', desc: 'Localiza o servidor geograficamente' },
            { name: 'CDN Bypass', desc: 'Encontra o servidor real por trás de proteções' },
            { name: 'Serverless Endpoints', desc: 'Descobre APIs e funções de backend' },
            { name: 'CloudFail', desc: 'Expõe IPs reais atrás do Cloudflare' },
          ].map(({ name, desc }) => (
            <div key={name} className="p-2 rounded bg-dark-700 border border-dark-600">
              <div className="font-semibold text-gray-200 mb-0.5">{name}</div>
              <div className="text-gray-500">{desc}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4 flex gap-3">
        <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-red-400 font-semibold">Apenas testes autorizados</p>
          <p className="text-red-300 text-sm">Use apenas em hosts que você tem permissão explícita para testar.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Resolução de Domínio */}
        <div className="space-y-4">
          <div className="card-dark border-blue-600/30 p-6">
            <h2 className="text-xl font-bold text-gray-100 mb-4">Resolução de Domínio</h2>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Alvo (Domínio, URL ou IP)
                </label>
                <input
                  type="text"
                  value={resolveTarget}
                  onChange={(e) => setResolveTarget(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && resolveDomain()}
                  placeholder="exemplo.com.br ou 192.168.1.1"
                  className="input-dark w-full"
                />
              </div>
              <button
                onClick={resolveDomain}
                disabled={resolving}
                className="btn-blue w-full flex justify-center items-center gap-2 disabled:opacity-50"
              >
                {resolving ? <Loader className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                {resolving ? 'Resolvendo...' : 'Resolver'}
              </button>
            </div>
          </div>

          {resolveResult && (
            <div className="card-dark border-blue-600/30 p-6">
              <h3 className="font-semibold text-gray-100 mb-4">Resultado</h3>
              {resolveResult.erro ? (
                <div className="text-red-400 text-sm">{resolveResult.erro}</div>
              ) : (
                <div className="space-y-2 text-sm">
                  <div>
                    <span className="text-gray-400">Host:</span>
                    <span className="text-gray-100 ml-2">{resolveResult.host || resolveResult.domain}</span>
                  </div>
                  {resolveResult.ips?.length > 0 ? (
                    <div>
                      <span className="text-gray-400">IP(s) encontrado(s):</span>
                      <div className="ml-2 mt-1 space-y-1">
                        {resolveResult.ips.map((ip, i) => (
                          <div key={i} className="text-green-400 font-mono">{ip}</div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="text-yellow-400 text-sm">Nenhum IP encontrado para este domínio.</div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Varredura de Portas */}
        <div className="space-y-4">
          <div className="card-dark border-yellow-600/30 p-6">
            <h2 className="text-xl font-bold text-gray-100 mb-4">Varredura de Portas</h2>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Alvo (IP ou Domínio)
                </label>
                <input
                  type="text"
                  value={scanTarget}
                  onChange={(e) => setScanTarget(e.target.value)}
                  placeholder="127.0.0.1 ou localhost"
                  className="input-dark w-full"
                  disabled={scanning}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Portas</label>
                <select
                  value={scanPorts}
                  onChange={(e) => setScanPorts(e.target.value)}
                  className="select-dark w-full"
                  disabled={scanning}
                >
                  <option value="top">Top Portas (23 mais comuns)</option>
                  <option value="1-1024">1-1024</option>
                  <option value="1-65535">Todas (1-65535)</option>
                  <option value="80,443">Web (80, 443)</option>
                </select>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1">
                    Tempo de Espera
                    <span className="text-gray-500 font-normal ml-1">(segundos por porta)</span>
                  </label>
                  <input
                    type="number"
                    value={scanTimeout}
                    onChange={(e) => setScanTimeout(parseFloat(e.target.value))}
                    min="0.1" max="10" step="0.1"
                    className="input-dark w-full text-sm"
                    disabled={scanning}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1">
                    Velocidade
                    <span className="text-gray-500 font-normal ml-1">(conexões paralelas)</span>
                  </label>
                  <input
                    type="number"
                    value={scanWorkers}
                    onChange={(e) => setScanWorkers(parseInt(e.target.value))}
                    min="1" max="500"
                    className="input-dark w-full text-sm"
                    disabled={scanning}
                  />
                </div>
              </div>

              {scanning ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs text-gray-400 mb-1">
                    <span>Varrendo portas em segundo plano...</span>
                    <span className="font-mono">{progress} / {progressTotal} ({pct}%)</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-3 overflow-hidden">
                    <div
                      className="h-3 rounded-full bg-yellow-500 transition-all duration-200"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <button
                    onClick={cancelScan}
                    className="w-full flex justify-center items-center gap-2 py-2 px-4 rounded bg-gray-700 hover:bg-gray-600 text-gray-300 text-sm transition-colors"
                  >
                    <X className="w-4 h-4" /> Cancelar
                  </button>
                </div>
              ) : (
                <button
                  onClick={scanPortsFn}
                  className="btn-red w-full flex justify-center items-center gap-2"
                >
                  <Search className="w-4 h-4" />
                  Escanear
                </button>
              )}
            </div>
          </div>

          {scanResult && (
            <div className="card-dark border-yellow-600/30 p-6">
              <h3 className="font-semibold text-gray-100 mb-4">Resultado</h3>
              <div className="space-y-3 text-sm">
                <div>
                  <span className="text-gray-400">Alvo:</span>
                  <span className="text-gray-100 ml-2">{scanResult.host}</span>
                </div>
                <div>
                  <span className="text-gray-400">
                    Portas abertas: <span className="text-gray-100 font-bold">{scanResult.results.length}</span>
                  </span>
                  <div className="ml-2 mt-2">
                    {scanResult.results.length === 0 ? (
                      <div className="text-blue-400">Nenhuma porta aberta encontrada</div>
                    ) : (
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="text-gray-500 text-xs border-b border-dark-600">
                            <th className="text-left py-1 pr-4">Porta</th>
                            <th className="text-left py-1 pr-4">Serviço</th>
                            <th className="text-left py-1">Banner</th>
                          </tr>
                        </thead>
                        <tbody>
                          {scanResult.results.map((p, i) => (
                            <tr key={i} className="border-b border-dark-700/50">
                              <td className="py-1 pr-4 text-green-400 font-mono font-bold">{p.porta}</td>
                              <td className="py-1 pr-4 text-blue-300">{p.servico}</td>
                              <td className="py-1 text-gray-400 font-mono text-xs truncate max-w-xs">{p.banner || '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Consulta de IP */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="space-y-4">
          <div className="card-dark border-purple-600/30 p-6">
            <div className="flex items-center gap-2 mb-4">
              <Globe className="w-5 h-5 text-purple-400" />
              <h2 className="text-xl font-bold text-gray-100">Consulta de IP</h2>
            </div>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Endereço IP
                </label>
                <input
                  type="text"
                  value={ipInfoTarget}
                  onChange={(e) => setIpInfoTarget(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && lookupIpInfo()}
                  placeholder="ex: 8.8.8.8"
                  className="input-dark w-full"
                />
              </div>
              <button
                onClick={lookupIpInfo}
                disabled={loadingIpInfo}
                className="btn-blue w-full flex justify-center items-center gap-2 disabled:opacity-50"
                style={{ background: 'rgba(109,40,217,0.7)', borderColor: '#7c3aed' }}
              >
                {loadingIpInfo ? <Loader className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
                {loadingIpInfo ? 'Consultando...' : 'Consultar'}
              </button>
            </div>
          </div>
        </div>

        {ipInfoResult && (
          <div className="card-dark border-purple-600/30 p-6">
            <h3 className="font-semibold text-gray-100 mb-4">Resultado — {ipInfoResult.query}</h3>
            <div className="space-y-2 text-sm">
              {[
                ['País', `${ipInfoResult.country} (${ipInfoResult.countryCode})`],
                ['Região', ipInfoResult.regionName],
                ['Cidade', ipInfoResult.city],
                ['ISP', ipInfoResult.isp],
                ['Organização', ipInfoResult.org],
                ['ASN', ipInfoResult.as],
                ['Lat / Lon', `${ipInfoResult.lat}, ${ipInfoResult.lon}`],
              ].map(([label, value]) => value && (
                <div key={label} className="flex gap-2">
                  <span className="text-gray-400 w-28 flex-shrink-0">{label}:</span>
                  <span className="text-gray-100 font-mono text-xs break-all">{value}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* CDN Bypass — descoberta de IP real */}
      <div className="card-dark p-6">
        <div className="flex items-center gap-2 mb-4">
          <ShieldOff className="w-5 h-5 text-red-400" />
          <h2 className="text-xl font-bold text-gray-100">CDN Bypass — Descoberta de IP Real</h2>
        </div>
        <p className="text-sm text-gray-500 mb-4">
          Detecta CDN e tenta encontrar o IP real do servidor via DNS histórico, crt.sh, MX, SPF e subdomínios.
        </p>
        <div className="flex gap-3 mb-4">
          <input type="text" value={cdnDomain} onChange={e => setCdnDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && runCdnCheck()}
            placeholder="exemplo.com" className="input-dark flex-1 text-sm" />
          <button onClick={runCdnCheck} disabled={cdnLoading}
            className="flex items-center gap-2 px-5 py-2 rounded bg-red-700 hover:bg-red-600 text-white text-sm font-semibold transition disabled:opacity-50">
            {cdnLoading ? <Loader className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {cdnLoading ? 'Analisando...' : 'Descobrir IP'}
          </button>
        </div>

        {cdnResult && (
          <div className="space-y-4">
            {/* CDN detection */}
            <div className={`flex items-center gap-3 p-3 rounded border ${cdnResult.behind_cdn ? 'bg-red-900/20 border-red-600/40' : 'bg-green-900/20 border-green-600/40'}`}>
              {cdnResult.behind_cdn
                ? <><XCircle className="w-5 h-5 text-red-400 shrink-0" /><span className="text-red-300 text-sm"><strong>{cdnDomain}</strong> está atrás de <strong>{cdnResult.cdn_name}</strong> — tráfego passa pela CDN antes de chegar ao servidor</span></>
                : <><CheckCircle className="w-5 h-5 text-green-400 shrink-0" /><span className="text-green-300 text-sm"><strong>{cdnDomain}</strong> não parece usar CDN — ataque direto ao servidor é possível</span></>
              }
            </div>

            {/* IPs verificados (sem CDN) */}
            {cdnResult.verified_origins?.length > 0 && (
              <div>
                <p className="text-sm font-semibold text-green-400 mb-2">IPs de Origem Verificados ({cdnResult.verified_origins.length})</p>
                <div className="space-y-2">
                  {cdnResult.verified_origins.map((o, i) => (
                    <div key={i} className="flex items-center gap-3 p-2 rounded bg-green-900/20 border border-green-700/40 text-sm font-mono">
                      <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
                      <span className="text-green-300 font-bold">{o.ip}</span>
                      <span className="text-gray-500">:{o.open_ports?.join(', ')}</span>
                      {o.status_code && <span className="text-gray-400">HTTP {o.status_code}</span>}
                      {o.server && <span className="text-gray-500">{o.server}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Subdomínios que bypassam */}
            {cdnResult.subdomains_resolved?.length > 0 && (
              <details>
                <summary className="text-sm text-gray-400 cursor-pointer hover:text-gray-200">
                  Subdomínios resolvidos ({cdnResult.subdomains_resolved.length}) — clique para expandir
                </summary>
                <div className="mt-2 grid grid-cols-2 gap-1 max-h-48 overflow-y-auto">
                  {cdnResult.subdomains_resolved.map((s, i) => (
                    <div key={i} className="flex gap-2 text-xs font-mono p-1 rounded bg-dark-800">
                      <span className="text-gray-400 truncate">{s.subdomain}</span>
                      <span className="text-blue-400 shrink-0">{s.ip}</span>
                    </div>
                  ))}
                </div>
              </details>
            )}

            {/* Resumo fontes */}
            <div className="grid grid-cols-3 gap-3 text-center text-xs">
              {[
                { label: 'IPs históricos', val: cdnResult.historical_ips?.length || 0 },
                { label: 'MX records', val: cdnResult.mx_records?.length || 0 },
                { label: 'SPF IPs', val: cdnResult.spf_ips?.length || 0 },
              ].map(({ label, val }) => (
                <div key={label} className="p-2 rounded bg-dark-800 border border-dark-700">
                  <div className="text-lg font-bold text-gray-200">{val}</div>
                  <div className="text-gray-500">{label}</div>
                </div>
              ))}
            </div>

            {cdnResult.verified_origins?.length === 0 && (
              <p className="text-sm text-yellow-400">Nenhum IP de origem confirmado. Tente CloudFail ou consulte DNS history manual.</p>
            )}
          </div>
        )}
      </div>

      {/* Serverless Endpoints */}
      <div className="card-dark p-6">
        <div className="flex items-center gap-2 mb-1">
          <Zap className="w-5 h-5 text-yellow-400" />
          <h2 className="text-xl font-bold text-gray-100">Serverless Endpoints</h2>
          <span className="text-xs px-2 py-0.5 rounded bg-yellow-900/30 text-yellow-400 border border-yellow-700/40">λ</span>
        </div>
        <p className="text-gray-500 text-sm mb-4">Descobre endpoints de funções serverless (Vercel/Next.js/Netlify/AWS Lambda)</p>
        <div className="flex gap-3 mb-4">
          <input type="text" value={serverlessDomain} onChange={e => setServerlessDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && runServerlessRecon()}
            placeholder="ex: exemplo.com" className="input-dark flex-1 text-sm" />
          <button onClick={runServerlessRecon} disabled={serverlessLoading}
            className="flex items-center gap-2 px-5 py-2 rounded bg-yellow-700 hover:bg-yellow-600 text-white text-sm font-semibold transition disabled:opacity-50">
            {serverlessLoading ? <Loader className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {serverlessLoading ? 'Descobrindo...' : 'Descobrir'}
          </button>
        </div>
        {serverlessResult && (
          <div className="space-y-4">
            <div className="flex items-center gap-3 flex-wrap text-sm">
              <span className="text-gray-400">Plataforma:</span>
              <span className="font-bold text-yellow-300 font-mono">{serverlessResult.platform}</span>
              <span className="text-gray-400 ml-4">Endpoints encontrados:</span>
              <span className="font-bold text-gray-100">{serverlessResult.endpoints?.length || 0}</span>
              <span className="text-gray-400 ml-4">Recomendados (serverless+uncached):</span>
              <span className="font-bold text-green-400">{serverlessResult.recommended_targets?.length || 0}</span>
            </div>
            {serverlessResult.recommended_targets?.length > 0 && (
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-400">Alvos recomendados:</span>
                <code className="text-xs text-green-300 bg-dark-800 px-2 py-1 rounded font-mono">
                  {serverlessResult.recommended_targets.join(',')}
                </code>
                <button
                  onClick={() => { navigator.clipboard.writeText(serverlessResult.recommended_targets.join(',')) ; toast('Copiado!', 'success') }}
                  className="text-xs px-3 py-1 rounded bg-green-800/40 hover:bg-green-700/60 text-green-300 border border-green-700/40 transition">
                  Copiar para DDoS
                </button>
              </div>
            )}
            {serverlessResult.endpoints?.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-gray-500 border-b border-dark-600">
                      <th className="text-left py-1 pr-3">Path</th>
                      <th className="text-left py-1 pr-3">Status</th>
                      <th className="text-left py-1 pr-3">Tipo</th>
                      <th className="text-left py-1">Cache</th>
                    </tr>
                  </thead>
                  <tbody>
                    {serverlessResult.endpoints.map((ep, i) => (
                      <tr key={i} className="border-b border-dark-700/50">
                        <td className="py-1 pr-3 font-mono text-gray-200">{ep.path}</td>
                        <td className="py-1 pr-3">
                          <span className={`font-mono font-bold ${ep.status < 300 ? 'text-green-400' : ep.status < 400 ? 'text-yellow-400' : 'text-gray-400'}`}>{ep.status}</span>
                        </td>
                        <td className="py-1 pr-3">
                          {ep.serverless
                            ? <span className="px-1.5 py-0.5 rounded bg-yellow-900/40 text-yellow-300 border border-yellow-700/40">SERVERLESS</span>
                            : <span className="text-gray-500">STATIC</span>}
                        </td>
                        <td className="py-1">
                          {ep.cached
                            ? <span className="text-blue-400">CACHED</span>
                            : <span className="text-green-400">MISS</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* CloudFail — descoberta de IP real atrás do Cloudflare */}
      <div className="card-dark border-orange-600/30 p-6">
        <div className="flex items-center gap-2 mb-1">
          <ShieldOff className="w-5 h-5 text-orange-400" />
          <h2 className="text-xl font-bold text-gray-100">CloudFail</h2>
          <span className="text-xs px-2 py-0.5 rounded bg-orange-900/30 text-orange-400 border border-orange-700/40">OSINT</span>
        </div>
        <p className="text-gray-500 text-sm mb-4">Descobre IPs reais atrás do Cloudflare via brute-force de subdomínios DNS</p>

        <div className="flex gap-3">
          <input type="text" value={cfDomain}
            onChange={e => setCfDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && startCloudfail()}
            placeholder="ex: exemplo.com.br"
            className="input-dark flex-1" />
          <button onClick={startCloudfail}
            disabled={cfLoading || cfJob?.status === 'running' || cfJob?.status === 'starting'}
            className="flex items-center gap-2 px-5 py-2 rounded bg-orange-700 hover:bg-orange-600 text-white text-sm disabled:opacity-50 transition">
            {(cfLoading || cfJob?.status === 'running' || cfJob?.status === 'starting')
              ? <Loader className="w-4 h-4 animate-spin" />
              : <Search className="w-4 h-4" />}
            {cfJob?.status === 'running' ? 'Escaneando...' : 'Escanear'}
          </button>
        </div>

        {cfJob && (
          <div className="mt-4 space-y-3">
            {/* Status do domínio */}
            {cfJob.domain_info?.resolves != null && (
              <div className="flex items-center gap-3 text-sm">
                {cfJob.domain_info.behind_cloudflare ? (
                  <>
                    <CheckCircle className="w-4 h-4 text-orange-400 flex-shrink-0" />
                    <span className="text-orange-300">
                      <strong>{cfJob.domain}</strong> está atrás do Cloudflare — buscando IP real...
                    </span>
                  </>
                ) : cfJob.domain_info.resolves ? (
                  <>
                    <XCircle className="w-4 h-4 text-gray-400 flex-shrink-0" />
                    <span className="text-gray-400">
                      <strong>{cfJob.domain}</strong> não usa Cloudflare (IPs: {cfJob.domain_info.ips?.join(', ')})
                    </span>
                  </>
                ) : (
                  <span className="text-red-400">Domínio não resolve</span>
                )}
              </div>
            )}

            {/* Barra de progresso */}
            {(cfJob.status === 'running' || cfJob.status === 'starting') && (
              <div>
                <div className="flex justify-between text-xs text-gray-500 mb-1">
                  <span>Testando subdomínios...</span>
                  <span className="font-mono">{cfJob.progress} / {cfJob.total} ({cfPct}%)</span>
                </div>
                <div className="w-full bg-dark-700 rounded-full h-2 overflow-hidden">
                  <div className="h-2 rounded-full bg-orange-500 transition-all duration-300" style={{ width: `${cfPct}%` }} />
                </div>
              </div>
            )}

            {/* Resultados */}
            {cfJob.status === 'completed' && (
              <div>
                {cfJob.found_count === 0 ? (
                  <p className="text-gray-500 text-sm">Nenhum IP exposto encontrado nos subdomínios testados.</p>
                ) : (
                  <div>
                    <p className="text-orange-300 text-sm font-semibold mb-2">
                      {cfJob.found_count} IP{cfJob.found_count > 1 ? 's' : ''} exposto{cfJob.found_count > 1 ? 's' : ''} encontrado{cfJob.found_count > 1 ? 's' : ''}:
                    </p>
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-gray-500 text-xs border-b border-dark-600">
                          <th className="text-left py-1 pr-4">Subdomínio</th>
                          <th className="text-left py-1 pr-4">IP Real</th>
                        </tr>
                      </thead>
                      <tbody>
                        {cfJob.found.map((item, i) => (
                          <tr key={i} className="border-b border-dark-700/50">
                            <td className="py-1.5 pr-4 text-blue-300 font-mono text-xs">{item.subdomain}</td>
                            <td className="py-1.5 pr-4">
                              <span className="text-orange-300 font-mono font-bold text-xs">{item.ip}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {cfJob.all_found?.length > cfJob.found_count && (
                      <p className="text-xs text-gray-600 mt-2">
                        + {cfJob.all_found.length - cfJob.found_count} subdomínios via Cloudflare (ocultados)
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}

            {cfJob.status === 'error' && (
              <p className="text-red-400 text-sm">{cfJob.error}</p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
