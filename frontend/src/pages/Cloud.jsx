import React, { useState, useEffect, useRef } from 'react'
import { Server, AlertTriangle, Shield, Database, Key, Globe, RefreshCw, Play, Clock, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react'
import api from '../api'

const RISK_BADGE = {
  critical: 'bg-red-900/50 text-red-400 border-red-700',
  high:     'bg-orange-900/50 text-orange-400 border-orange-700',
  medium:   'bg-yellow-900/50 text-yellow-400 border-yellow-700',
  low:      'bg-green-900/40 text-green-400 border-green-800',
}

function Section({ title, icon: Icon, count, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="card-dark overflow-hidden">
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-center justify-between px-5 py-4 hover:bg-dark-700/50 transition">
        <div className="flex items-center gap-3">
          <Icon className="w-5 h-5 text-red-400" />
          <span className="font-semibold text-gray-200">{title}</span>
          {count !== undefined && (
            <span className={`text-xs px-2 py-0.5 rounded-full font-bold ${count > 0 ? 'bg-red-900/50 text-red-400' : 'bg-dark-700 text-gray-500'}`}>{count}</span>
          )}
        </div>
        {open ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
      </button>
      {open && <div className="px-5 pb-5">{children}</div>}
    </div>
  )
}

export default function Cloud() {
  const [host, setHost] = useState('')
  const [company, setCompany] = useState('')
  const [extraWords, setExtraWords] = useState('')
  const [running, setRunning] = useState(false)
  const [currentId, setCurrentId] = useState(null)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const pollRef = useRef(null)

  const loadHistory = () => {
    api.get('/api/cloud/results').then(r => setHistory(r.data.results || [])).catch(() => {})
  }

  useEffect(() => {
    loadHistory()
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [])

  const startRecon = () => {
    if (!host.trim()) return
    setRunning(true)
    setResult(null)
    api.post('/api/cloud/recon', {
      host: host.trim(),
      company_name: company.trim() || host.trim().split('.')[0],
      extra_words: extraWords.split(',').map(w => w.trim()).filter(Boolean),
    }).then(r => {
      const id = r.data.id
      setCurrentId(id)
      pollRef.current = setInterval(() => {
        api.get(`/api/cloud/results/${id}`).then(r2 => {
          if (r2.data.status !== 'running') {
            clearInterval(pollRef.current)
            setResult(r2.data)
            setRunning(false)
            loadHistory()
          }
        }).catch(() => { clearInterval(pollRef.current); setRunning(false) })
      }, 2000)
    }).catch(() => setRunning(false))
  }

  const loadResult = (id) => {
    api.get(`/api/cloud/results/${id}`).then(r => setResult(r.data)).catch(() => {})
  }

  const r = result?.results || {}
  const s3 = r.s3_buckets || []
  const meta = r.metadata_endpoints || []
  const iam = r.iam_findings || []

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
          <Globe className="w-6 h-6 text-red-500" />
          Cloud Recon
        </h1>
        <p className="text-gray-400 text-sm mt-0.5">S3 bucket discovery, IMDS metadata exposure, credenciais expostas</p>
      </div>

      <div className="flex gap-4 flex-col lg:flex-row">
        {/* Config + History */}
        <div className="space-y-4 lg:w-72 flex-shrink-0">
          {/* Config */}
          <div className="card-dark p-5 space-y-3">
            <h2 className="font-semibold text-gray-200 text-sm">Configuração</h2>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Host / IP alvo *</label>
              <input className="input-dark w-full font-mono" placeholder="192.168.1.1 ou empresa.com"
                value={host} onChange={e => setHost(e.target.value)} />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Nome da empresa (S3 enum)</label>
              <input className="input-dark w-full" placeholder="ex: acme, mycompany"
                value={company} onChange={e => setCompany(e.target.value)} />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Keywords extras <span className="text-gray-600">(vírgula)</span></label>
              <input className="input-dark w-full text-xs" placeholder="dev, backup, prod, api"
                value={extraWords} onChange={e => setExtraWords(e.target.value)} />
            </div>
            <button onClick={startRecon} disabled={running || !host.trim()}
              className="w-full btn-blue flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed">
              {running ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {running ? 'Escaneando...' : 'Iniciar Cloud Recon'}
            </button>
          </div>

          {/* History */}
          {history.length > 0 && (
            <div className="card-dark p-4">
              <h2 className="font-semibold text-gray-200 text-sm mb-3 flex items-center gap-2">
                <Clock className="w-4 h-4 text-gray-500" /> Histórico
              </h2>
              <div className="space-y-2">
                {history.slice(0, 5).map(h => (
                  <button key={h.id} onClick={() => loadResult(h.id)}
                    className={`w-full text-left p-2.5 rounded border text-xs transition hover:border-red-700/50 ${result?.id === h.id ? 'border-red-700 bg-red-950/20' : 'border-dark-600 bg-dark-700/40'}`}>
                    <p className="font-mono text-gray-300 truncate">{h.host}</p>
                    <p className="text-gray-500 mt-0.5">{h.cloud_provider || '—'} · {h.status === 'done' ? '✓' : h.status === 'running' ? '⏳' : '✗'}</p>
                    <p className="text-gray-600">{h.created_at?.slice(0, 10)}</p>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Results */}
        <div className="flex-1 space-y-3">
          {running && !result && (
            <div className="card-dark p-12 text-center">
              <RefreshCw className="w-8 h-8 text-red-500 animate-spin mx-auto mb-3" />
              <p className="text-gray-300 font-semibold">Cloud recon em andamento...</p>
              <p className="text-gray-500 text-sm mt-1">S3 bucket enumeration + metadata check + credential scan</p>
              <div className="mt-4 space-y-1 text-xs text-gray-600">
                <p>⏳ Verificando S3 buckets por nome da empresa...</p>
                <p>⏳ Checando endpoints IMDS (AWS/Azure/GCP)...</p>
                <p>⏳ Buscando arquivos de credenciais expostos...</p>
              </div>
            </div>
          )}

          {!running && !result && (
            <div className="card-dark p-12 text-center">
              <Globe className="w-10 h-10 text-gray-600 mx-auto mb-3" />
              <p className="text-gray-500">Configure o alvo e inicie o cloud recon</p>
            </div>
          )}

          {result && (
            <>
              {/* Cloud provider banner */}
              <div className="card-dark p-4 flex items-center gap-3">
                <Server className="w-5 h-5 text-blue-400 flex-shrink-0" />
                <div>
                  <p className="text-xs text-gray-500">Provedor cloud detectado</p>
                  <p className="font-bold text-gray-100">{result.cloud_provider || 'Desconhecido'}</p>
                </div>
                <div className="ml-auto text-right">
                  <p className="text-xs text-gray-500">Host</p>
                  <p className="font-mono text-gray-300 text-sm">{result.host}</p>
                </div>
              </div>

              {/* Critical alert */}
              {(s3.some(b => b.risk === 'critical') || meta.length > 0 || iam.length > 0) && (
                <div className="flex items-start gap-3 p-4 rounded-lg bg-red-950/30 border border-red-800/40">
                  <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-red-300 font-semibold text-sm">Exposições críticas detectadas</p>
                    <p className="text-red-400/70 text-xs mt-0.5">
                      {[s3.filter(b => b.risk === 'critical').length > 0 && `${s3.filter(b=>b.risk==='critical').length} bucket(s) S3 públicos`,
                        meta.length > 0 && `${meta.length} endpoint(s) IMDS expostos`,
                        iam.length > 0 && `${iam.length} arquivo(s) de credenciais expostos`
                      ].filter(Boolean).join(' · ')}
                    </p>
                  </div>
                </div>
              )}

              {/* S3 Buckets */}
              <Section title="Buckets S3" icon={Database} count={s3.length} defaultOpen={s3.length > 0}>
                {s3.length === 0 ? (
                  <p className="text-gray-500 text-sm">Nenhum bucket encontrado</p>
                ) : (
                  <div className="space-y-2">
                    {s3.map((b, i) => (
                      <div key={i} className={`p-3 rounded border ${b.risk === 'critical' ? 'bg-red-950/30 border-red-800/40' : 'bg-dark-700/40 border-dark-600'}`}>
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className={`text-xs px-2 py-0.5 rounded border flex-shrink-0 ${RISK_BADGE[b.risk] || RISK_BADGE.low}`}>{b.status}</span>
                            <span className="font-mono text-sm text-gray-200 truncate">{b.name}</span>
                          </div>
                          <a href={b.url} target="_blank" rel="noreferrer" className="text-gray-500 hover:text-gray-300 flex-shrink-0" onClick={e => e.stopPropagation()}>
                            <ExternalLink className="w-3.5 h-3.5" />
                          </a>
                        </div>
                        <p className="text-xs text-gray-400 mt-1">{b.detail}</p>
                        {b.preview && <pre className="text-[10px] text-gray-600 mt-1 overflow-x-auto whitespace-pre-wrap max-h-16 overflow-y-hidden">{b.preview}</pre>}
                      </div>
                    ))}
                  </div>
                )}
              </Section>

              {/* Metadata endpoints */}
              <Section title="Metadados Cloud Expostos" icon={Server} count={meta.length} defaultOpen={meta.length > 0}>
                {meta.length === 0 ? (
                  <p className="text-gray-500 text-sm">Nenhum endpoint IMDS exposto encontrado</p>
                ) : (
                  <div className="space-y-2">
                    {meta.map((m, i) => (
                      <div key={i} className="p-3 rounded border bg-red-950/30 border-red-800/40">
                        <div className="flex items-center gap-2">
                          <span className="text-xs px-2 py-0.5 rounded border bg-red-900/50 text-red-400 border-red-700">EXPOSTO</span>
                          <span className="text-sm text-gray-200 font-semibold">{m.label}</span>
                        </div>
                        <p className="font-mono text-xs text-gray-400 mt-1">{m.url}</p>
                        <p className="text-xs text-red-300 mt-1">{m.detail}</p>
                        {m.preview && <pre className="text-[10px] text-gray-600 mt-2 overflow-x-auto bg-dark-900 p-2 rounded max-h-20 overflow-y-hidden">{m.preview}</pre>}
                      </div>
                    ))}
                  </div>
                )}
              </Section>

              {/* IAM / Credentials */}
              <Section title="IAM / Credenciais Expostas" icon={Key} count={iam.length} defaultOpen={iam.length > 0}>
                {iam.length === 0 ? (
                  <p className="text-gray-500 text-sm">Nenhum arquivo de credencial exposto encontrado</p>
                ) : (
                  <div className="space-y-2">
                    {iam.map((f, i) => (
                      <div key={i} className="p-3 rounded border bg-red-950/30 border-red-800/40">
                        <div className="flex items-center gap-2">
                          <span className="text-xs px-2 py-0.5 rounded border bg-red-900/50 text-red-400 border-red-700">CRÍTICO</span>
                          <span className="text-sm text-gray-200">{f.type}</span>
                        </div>
                        <p className="font-mono text-xs text-gray-400 mt-1">{f.url}</p>
                        <p className="text-xs text-red-300 mt-1">{f.detail}</p>
                        {f.preview && <pre className="text-[10px] text-gray-600 mt-2 overflow-x-auto bg-dark-900 p-2 rounded max-h-20 overflow-y-hidden">{f.preview}</pre>}
                      </div>
                    ))}
                  </div>
                )}
              </Section>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
