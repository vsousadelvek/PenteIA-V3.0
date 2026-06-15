import React, { useState, useEffect } from 'react'
import { AlertTriangle, Play, Plus, X, Loader, BookOpen, ShieldCheck, ShieldAlert, ChevronDown, ChevronRight, Info, Clock, Calendar, GitBranch } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useToast } from '../components/Toast'
import api from '../api'

const SEV_PT = { Low: 'Baixa', Medium: 'Média', High: 'Alta', Critical: 'Crítica' }
const SEV_COLOR = {
  Low: 'text-blue-400',
  Medium: 'text-yellow-400',
  High: 'text-orange-400',
  Critical: 'text-red-400',
}

const CVSS_BADGE = (score) => {
  if (!score) return 'bg-gray-800 text-gray-500'
  if (score >= 9.0) return 'bg-red-900/70 text-red-300 border border-red-700/50'
  if (score >= 7.0) return 'bg-orange-900/70 text-orange-300 border border-orange-700/50'
  if (score >= 4.0) return 'bg-yellow-900/70 text-yellow-300 border border-yellow-700/50'
  return 'bg-blue-900/70 text-blue-300 border border-blue-700/50'
}

const CVSS_LABEL = (score) => {
  if (!score) return 'N/A'
  if (score >= 9.0) return 'Crítico'
  if (score >= 7.0) return 'Alto'
  if (score >= 4.0) return 'Médio'
  return 'Baixo'
}

const PLAYBOOK_TEMPLATES = [
  { name: 'Reconhecimento Inicial', severity: 'Low', techniques: 5, description: 'Simula a fase de coleta de informações que um invasor faz antes de atacar.' },
  { name: 'Movimentação Lateral', severity: 'High', techniques: 8, description: 'Testa se um invasor que já entrou na rede consegue se mover para outros sistemas.' },
  { name: 'Exfiltração de Dados', severity: 'Critical', techniques: 6, description: 'Simula um invasor tentando roubar arquivos e dados sensíveis da empresa.' },
  { name: 'Persistência no Sistema', severity: 'Medium', techniques: 4, description: 'Testa se técnicas para "ficar escondido" são detectadas pelas defesas.' },
]

function TechCard({ t }) {
  const [expanded, setExpanded] = useState(false)
  const isVuln = t.status === 'found'
  const isUnknown = t.status === 'unknown'
  const hasMeta = t.cvss_score > 0

  return (
    <div className={`text-xs border-b border-dark-600 last:border-0 ${isVuln ? 'bg-red-950/20' : 'bg-dark-800'}`}>
      <div
        className="flex items-start gap-2 p-3 cursor-pointer hover:bg-dark-700/30 transition"
        onClick={() => (t.remediation || t.compliance?.length > 0) && setExpanded(e => !e)}
      >
        {/* Status badge */}
        <span className={`font-mono text-[10px] px-1.5 py-0.5 rounded mt-0.5 flex-shrink-0 ${
          isVuln    ? 'bg-red-900/60 text-red-400' :
          isUnknown ? 'bg-gray-700 text-gray-400'  :
                      'bg-green-900/60 text-green-400'
        }`}>
          {isVuln ? 'VULNERÁVEL' : isUnknown ? 'N/A' : 'PROTEGIDO'}
        </span>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-gray-300 font-semibold">{t.name}</span>
            <span className="text-gray-600 text-[10px]">{t.id}</span>

            {/* HTTP status */}
            {t.http_status > 0 && (
              <span className={`font-mono text-[10px] px-1 py-0.5 rounded ${
                t.http_status === 200 ? 'bg-yellow-900/40 text-yellow-400' :
                t.http_status === 403 ? 'bg-green-900/40 text-green-400' :
                t.http_status === 429 ? 'bg-blue-900/40 text-blue-400' :
                t.http_status >= 300 && t.http_status < 400 ? 'bg-purple-900/40 text-purple-400' :
                'bg-dark-700 text-gray-500'
              }`}>
                HTTP {t.http_status}
              </span>
            )}

            {/* CVSS score */}
            {hasMeta && (
              <span className={`font-mono text-[10px] px-1.5 py-0.5 rounded font-bold ${CVSS_BADGE(t.cvss_score)}`}>
                CVSS {t.cvss_score} · {CVSS_LABEL(t.cvss_score)}
              </span>
            )}
          </div>

          <p className="text-gray-500 mt-0.5 leading-relaxed">{t.detail}</p>

          {/* Compliance tags */}
          {t.compliance?.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {t.compliance.map(c => (
                <span key={c} className="text-[9px] px-1.5 py-0.5 rounded bg-dark-600 text-gray-400 border border-dark-500">
                  {c}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Expand chevron — só quando há remediação */}
        {(t.remediation || t.compliance?.length > 0) && (
          <span className="text-gray-600 flex-shrink-0 mt-0.5">
            {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
          </span>
        )}
      </div>

      {/* Remediação expandida */}
      {expanded && t.remediation && (
        <div className="mx-3 mb-3 p-2.5 rounded bg-orange-900/10 border border-orange-800/30 text-orange-200/80 text-[11px] leading-relaxed">
          <span className="font-semibold text-orange-400 mr-1">Remediação:</span>{t.remediation}
          {t.cvss_vector && (
            <p className="mt-1 font-mono text-[9px] text-gray-600">{t.cvss_vector}</p>
          )}
        </div>
      )}
    </div>
  )
}

function RiskSummary({ techs }) {
  const bySev = { Critical: 0, High: 0, Medium: 0, Low: 0 }
  techs.filter(t => t.status === 'found').forEach(t => {
    const sev = t.cvss_severity || 'Low'
    if (sev in bySev) bySev[sev]++
  })
  const total = Object.values(bySev).reduce((a, b) => a + b, 0)
  if (total === 0) return null

  return (
    <div className="flex items-center gap-3 text-xs">
      {bySev.Critical > 0 && <span className="text-red-400 font-bold">{bySev.Critical} Crítico{bySev.Critical > 1 ? 's' : ''}</span>}
      {bySev.High > 0    && <span className="text-orange-400 font-bold">{bySev.High} Alto{bySev.High > 1 ? 's' : ''}</span>}
      {bySev.Medium > 0  && <span className="text-yellow-400 font-bold">{bySev.Medium} Médio{bySev.Medium > 1 ? 's' : ''}</span>}
      {bySev.Low > 0     && <span className="text-blue-400 font-bold">{bySev.Low} Baixo{bySev.Low > 1 ? 's' : ''}</span>}
    </div>
  )
}

export default function BAS() {
  const toast = useToast()
  const navigate = useNavigate()
  const [playbooks, setPlaybooks] = useState([])
  const [simulations, setSimulations] = useState([])
  const [showNewPlaybook, setShowNewPlaybook] = useState(false)
  const [loading, setLoading] = useState(true)
  const [executingId, setExecutingId] = useState(null)
  const [newPlaybook, setNewPlaybook] = useState({ name: '', techniques: 5, severity: 'Medium', description: '' })
  const [creatingTemplate, setCreatingTemplate] = useState(null)
  const [execModal, setExecModal] = useState({ show: false, playbook: null, target: '', port: '' })
  const [schedModal, setSchedModal] = useState({ show: false, playbook: null, target: '', interval: 'weekly' })
  const [sevFilter, setSevFilter] = useState('all')

  useEffect(() => {
    fetchPlaybooks()
    fetchSimulations()
  }, [])

  useEffect(() => {
    const hasRunning = simulations.some(s => s.status === 'running')
    if (!hasRunning) return
    const id = setInterval(fetchSimulations, 3000)
    return () => clearInterval(id)
  }, [simulations])

  const fetchPlaybooks = async () => {
    try {
      const res = await api.get('/api/bas/playbooks')
      setPlaybooks(res.data.playbooks || [])
    } catch (err) {
      console.error('Erro ao buscar playbooks:', err)
    } finally {
      setLoading(false)
    }
  }

  const fetchSimulations = async () => {
    try {
      const res = await api.get('/api/bas/simulations')
      setSimulations(res.data.simulations || [])
    } catch (err) {
      console.error('Erro ao buscar simulações:', err)
    }
  }

  const handleCreatePlaybook = async () => {
    if (!newPlaybook.name.trim()) {
      toast('Digite um nome para o roteiro de ataque', 'warning')
      return
    }
    try {
      await api.post('/api/bas/playbooks', {
        name: newPlaybook.name,
        techniques: newPlaybook.techniques,
        severity: newPlaybook.severity,
        description: newPlaybook.description,
      })
      setNewPlaybook({ name: '', techniques: 5, severity: 'Medium', description: '' })
      setShowNewPlaybook(false)
      await fetchPlaybooks()
      toast('Roteiro de ataque criado!', 'success')
    } catch (err) {
      toast('Erro ao criar roteiro: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  const handleCreateFromTemplate = async (tpl) => {
    setCreatingTemplate(tpl.name)
    try {
      await api.post('/api/bas/playbooks', {
        name: tpl.name,
        techniques: tpl.techniques,
        severity: tpl.severity,
        description: tpl.description,
      })
      await fetchPlaybooks()
      toast(`Roteiro "${tpl.name}" criado!`, 'success')
    } catch (err) {
      toast('Erro ao criar roteiro: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setCreatingTemplate(null)
    }
  }

  const openExecModal = (pb) => {
    let env = {}
    try { env = JSON.parse(localStorage.getItem('penteia_env') || '{}') } catch {}
    setExecModal({ show: true, playbook: pb, target: env.host || '', port: env.port || '' })
  }

  const handleExecutePlaybook = async () => {
    const { playbook, target, port } = execModal
    if (!target.trim()) { toast('Informe o host ou IP alvo', 'warning'); return }
    setExecModal(m => ({ ...m, show: false }))
    setExecutingId(playbook.id)
    try {
      const targetStr = port ? `${target.trim()}:${port}` : target.trim()
      await api.post('/api/bas/execute', { playbook_id: playbook.id, target: targetStr })
      await fetchSimulations()
      toast('Simulação executada! Veja os resultados abaixo.', 'success')
    } catch (err) {
      toast('Erro ao executar: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setExecutingId(null)
    }
  }

  const handleSchedule = async () => {
    const { playbook, target, interval } = schedModal
    if (!target.trim()) { toast('Informe o host alvo para agendamento', 'warning'); return }
    try {
      const res = await api.post('/api/schedule', { playbook_id: playbook.id, target: target.trim(), interval })
      setSchedModal(m => ({ ...m, show: false }))
      const nextDate = new Date(res.data.next_run).toLocaleString('pt-BR')
      toast(`Agendado! Próxima execução: ${nextDate}`, 'success')
    } catch (err) {
      toast('Erro ao agendar: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  const getSimPlaybookName = (sim) => {
    const pb = playbooks.find(p => p.id === sim.playbook_id)
    return pb?.name || sim.playbook_id || '-'
  }

  const filterTechs = (techs) => {
    if (sevFilter === 'all') return techs
    if (sevFilter === 'vulns') return techs.filter(t => t.status === 'found')
    return techs.filter(t => t.cvss_severity === sevFilter)
  }

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">Simulação de Ataques (BAS)</h1>
        <p className="text-gray-400">Testa as defesas da empresa simulando ataques reais — com scoring CVSS 3.1 e mapeamento de compliance</p>
      </div>

      {/* O que é BAS */}
      <div className="card-dark p-6 bg-blue-900/10 border-l-4 border-blue-600">
        <div className="flex items-center gap-2 mb-3">
          <BookOpen className="w-5 h-5 text-blue-400" />
          <h2 className="text-lg font-bold text-gray-100">O que é o BAS?</h2>
        </div>
        <p className="text-gray-300 text-sm mb-3 leading-relaxed">
          <strong>BAS (Breach &amp; Attack Simulation)</strong> é uma técnica que simula ataques reais de forma segura e controlada.
          Em vez de esperar que um hacker ataque a empresa, você mesmo faz os ataques em ambiente de teste para descobrir se as defesas funcionam.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
          {[
            { n: '1', t: 'Crie um Roteiro', d: 'Escolha um dos modelos prontos abaixo ou crie seu próprio roteiro de ataque.' },
            { n: '2', t: 'Execute a Simulação', d: 'A plataforma realiza os ataques automaticamente e calcula o risco com score CVSS 3.1.' },
            { n: '3', t: 'Analise e Corrija', d: 'Veja o score de risco, os controles de compliance afetados e as recomendações de remediação.' },
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
      </div>

      <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4">
        <p className="text-red-400 text-sm">
          <strong>Aviso Legal:</strong> Execute apenas em ambientes que você tem autorização para testar. Nunca use em sistemas de terceiros sem permissão.
        </p>
      </div>

      {/* Modelos Prontos */}
      <div className="card-dark p-6">
        <div className="flex items-center gap-2 mb-2">
          <h2 className="text-2xl font-bold text-gray-100">Modelos Prontos de Roteiro</h2>
        </div>
        <p className="text-gray-400 text-sm mb-5">Clique em um modelo para criá-lo instantaneamente na sua lista de roteiros.</p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {PLAYBOOK_TEMPLATES.map(tpl => (
            <div key={tpl.name} className="bg-dark-700 border border-dark-600 rounded-lg p-4 hover:border-orange-600/50 transition">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <h3 className="font-bold text-gray-100">{tpl.name}</h3>
                  <p className="text-xs text-gray-400 mt-1 leading-relaxed">{tpl.description}</p>
                </div>
              </div>
              <div className="flex items-center justify-between mt-3">
                <div className="flex gap-3 text-xs">
                  <span className="text-gray-500">{tpl.techniques} técnicas</span>
                  <span className={SEV_COLOR[tpl.severity]}>Impacto {SEV_PT[tpl.severity]}</span>
                </div>
                <button
                  onClick={() => handleCreateFromTemplate(tpl)}
                  disabled={!!creatingTemplate}
                  className="flex items-center gap-1 text-xs px-3 py-1.5 bg-orange-700 hover:bg-orange-600 text-white rounded transition disabled:opacity-50"
                >
                  {creatingTemplate === tpl.name ? <Loader className="w-3 h-3 animate-spin" /> : <Plus className="w-3 h-3" />}
                  Usar este modelo
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Meus Roteiros */}
      <div className="card-dark p-6">
        <div className="flex justify-between items-center mb-2">
          <h2 className="text-2xl font-bold text-gray-100">Meus Roteiros de Ataque ({playbooks.length})</h2>
          <button onClick={() => setShowNewPlaybook(true)} className="btn-blue flex items-center gap-2">
            <Plus className="w-4 h-4" />
            Criar Roteiro
          </button>
        </div>
        <p className="text-gray-400 text-sm mb-5">
          Um <strong className="text-gray-300">roteiro de ataque</strong> é uma sequência de técnicas que serão executadas automaticamente no alvo.
        </p>

        {loading ? (
          <p className="text-gray-400">Carregando...</p>
        ) : playbooks.length === 0 ? (
          <div className="text-center py-10 border border-dashed border-dark-600 rounded-lg">
            <p className="text-gray-500 mb-3">Nenhum roteiro criado ainda.</p>
            <p className="text-gray-600 text-sm">Use os modelos prontos acima para começar rapidamente.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {playbooks.map(pb => (
              <div key={pb.id} className="bg-dark-700 border border-dark-600 rounded-lg p-4 hover:border-orange-600/50 transition">
                <h3 className="font-bold text-gray-100 mb-2">{pb.name}</h3>
                {pb.description && <p className="text-xs text-gray-400 mb-3 leading-relaxed">{pb.description}</p>}
                <div className="space-y-1 text-xs text-gray-400 mb-4">
                  <p>Técnicas de ataque: <span className="text-gray-300 font-semibold">{pb.techniques}</span></p>
                  <p>
                    Nível de impacto:{' '}
                    <span className={`font-semibold ${SEV_COLOR[pb.severity] || 'text-gray-300'}`}>
                      {SEV_PT[pb.severity] || pb.severity}
                    </span>
                  </p>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => openExecModal(pb)}
                    disabled={!!executingId}
                    className="btn-red flex-1 text-sm flex justify-center items-center gap-2 disabled:opacity-50"
                  >
                    {executingId === pb.id ? (
                      <><Loader className="w-3 h-3 animate-spin" /> Executando...</>
                    ) : (
                      <><Play className="w-3 h-3" /> Executar</>
                    )}
                  </button>
                  <button
                    onClick={() => setSchedModal({ show: true, playbook: pb, target: '', interval: 'weekly' })}
                    title="Agendar simulação recorrente"
                    className="px-3 py-2 bg-dark-600 hover:bg-dark-500 border border-dark-500 hover:border-cyan-700 text-cyan-400 rounded transition text-xs flex items-center gap-1"
                  >
                    <Clock className="w-3 h-3" /> Agendar
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Histórico de Simulações */}
      <div className="card-dark p-6">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-2xl font-bold text-gray-100">Histórico de Simulações ({simulations.length})</h2>
          {simulations.some(s => (s.results?.techniques || []).some(t => t.cvss_score > 0)) && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-500">Filtrar:</span>
              {[
                { v: 'all',      label: 'Todas'       },
                { v: 'vulns',    label: 'Só Vuln.'    },
                { v: 'Critical', label: 'Crítico'     },
                { v: 'High',     label: 'Alto'        },
                { v: 'Medium',   label: 'Médio'       },
              ].map(f => (
                <button
                  key={f.v}
                  onClick={() => setSevFilter(f.v)}
                  className={`text-xs px-2 py-1 rounded transition ${
                    sevFilter === f.v
                      ? 'bg-orange-700 text-white'
                      : 'bg-dark-700 text-gray-400 hover:bg-dark-600'
                  }`}
                >
                  {f.label}
                </button>
              ))}
            </div>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-4 mb-5">
          <p className="text-gray-400 text-sm">
            O <strong className="text-gray-300">score</strong> indica quanto do risco total foi explorado com sucesso —
            quanto menor, mais protegido está o alvo.
          </p>
          <div className="flex gap-2 text-xs flex-wrap">
            <span className="px-2 py-0.5 rounded bg-green-900/30 text-green-400 border border-green-800/30">0–25% Bem protegido</span>
            <span className="px-2 py-0.5 rounded bg-yellow-900/30 text-yellow-400 border border-yellow-800/30">25–50% Atenção</span>
            <span className="px-2 py-0.5 rounded bg-red-900/30 text-red-400 border border-red-800/30">50%+ Crítico</span>
          </div>
        </div>

        {simulations.length === 0 ? (
          <div className="text-center py-8 border border-dashed border-dark-600 rounded-lg">
            <p className="text-gray-500 text-sm">Nenhuma simulação executada ainda.</p>
            <p className="text-gray-600 text-xs mt-1">Execute um roteiro acima para começar.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {simulations.map(sim => {
              const techs = sim.results?.techniques || []
              const vulns = techs.filter(t => t.status === 'found')
              const safe  = techs.filter(t => t.status === 'blocked')
              const unknown = techs.filter(t => t.status === 'unknown')
              const scoreColor = sim.score >= 50 ? 'text-red-400' : sim.score >= 25 ? 'text-orange-400' : 'text-green-400'
              const filtered = filterTechs(techs)

              return (
                <div key={sim.id} className="border border-dark-600 rounded-lg overflow-hidden">
                  {/* Cabeçalho */}
                  <div className="flex items-center justify-between p-4 bg-dark-700">
                    <div className="flex items-center gap-3">
                      <div className="text-center">
                        <span className={`text-2xl font-black ${scoreColor}`}>{sim.score ?? 0}%</span>
                        <p className="text-gray-600 text-[9px] leading-none mt-0.5">risco CVSS</p>
                        <p className={`text-[9px] font-semibold mt-0.5 ${scoreColor}`}>
                          {(sim.score ?? 0) >= 50 ? 'CRÍTICO' : (sim.score ?? 0) >= 25 ? 'ATENÇÃO' : 'PROTEGIDO'}
                        </p>
                      </div>
                      <div>
                        <p className="font-semibold text-gray-100">{getSimPlaybookName(sim)}</p>
                        <p className="text-xs text-gray-400 font-mono">{sim.target} · {sim.date ? new Date(sim.date).toLocaleString('pt-BR') : ''}</p>
                        {techs.length > 0 && <RiskSummary techs={techs} />}
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {techs.length > 0 && (
                        <div className="text-xs text-right hidden sm:block space-y-1">
                          <div>
                            <span className="text-red-400 font-bold">{vulns.length} vuln</span>
                            <span className="text-gray-500 mx-1">/</span>
                            <span className="text-green-400 font-bold">{safe.length} bloq</span>
                          </div>
                          {sim.results?.detection_coverage_pct != null && (
                            <div className="flex items-center gap-2">
                              <div className="w-20 h-1.5 bg-dark-600 rounded-full overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${sim.results.detection_coverage_pct >= 70 ? 'bg-green-500' : sim.results.detection_coverage_pct >= 40 ? 'bg-yellow-500' : 'bg-red-500'}`}
                                  style={{ width: `${sim.results.detection_coverage_pct}%` }}
                                />
                              </div>
                              <span className={`text-[10px] ${sim.results.detection_coverage_pct >= 70 ? 'text-green-400' : sim.results.detection_coverage_pct >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>
                                {sim.results.detection_coverage_pct.toFixed(0)}% detecção
                              </span>
                            </div>
                          )}
                        </div>
                      )}
                      {sim.status === 'completed' && (
                        <>
                          <button
                            onClick={() => navigate(`/attack-path/${sim.id}`)}
                            className="text-xs px-2 py-1 rounded bg-cyan-900/30 text-cyan-400 border border-cyan-800/40 hover:border-cyan-600 transition flex items-center gap-1"
                          >
                            <GitBranch className="w-3 h-3" /> Grafo
                          </button>
                          <button
                            onClick={() => {
                              api.post(`/api/bas/retest/${sim.id}`)
                                .then(r => {
                                  toast.success('Retest iniciado', `Simulação ${r.data.id.slice(0,8)} criada para revalidação`)
                                  fetchSimulations()
                                })
                                .catch(e => toast.error('Erro no retest', e.response?.data?.detail || 'Falha ao iniciar retest'))
                            }}
                            className="text-xs px-2 py-1 rounded bg-purple-900/30 text-purple-400 border border-purple-800/40 hover:border-purple-600 transition flex items-center gap-1"
                            title="Retest pós-remediação: verifica se vulnerabilidades foram corrigidas"
                          >
                            ↺ Retest
                          </button>
                        </>
                      )}
                      <span className={`text-xs px-2 py-1 rounded ${
                        sim.status === 'completed' ? 'bg-green-900/30 text-green-400' : 'bg-yellow-900/30 text-yellow-400 animate-pulse'
                      }`}>
                        {sim.status === 'completed' ? 'Concluída' : 'Executando...'}
                      </span>
                    </div>
                  </div>

                  {/* Progress bar */}
                  {sim.status === 'running' && (
                    <div className="h-1 bg-dark-600">
                      <div className="h-1 bg-orange-500 animate-pulse w-full" />
                    </div>
                  )}

                  {/* Técnicas */}
                  {filtered.length > 0 && (
                    <div className="divide-y divide-dark-600/50">
                      {filtered.map((t, i) => <TechCard key={i} t={t} />)}
                    </div>
                  )}

                  {filtered.length === 0 && techs.length > 0 && (
                    <p className="text-gray-600 text-xs p-4">Nenhuma técnica para o filtro selecionado.</p>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Modal Executar */}
      {execModal.show && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="card-dark max-w-md w-full">
            <div className="flex justify-between items-center p-6 border-b border-dark-600">
              <div>
                <h2 className="text-xl font-bold text-gray-100">Executar Simulação</h2>
                <p className="text-xs text-gray-400 mt-1">Roteiro: <span className="text-orange-400">{execModal.playbook?.name}</span></p>
              </div>
              <button onClick={() => setExecModal(m => ({ ...m, show: false }))} className="text-gray-400 hover:text-gray-100">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label className="block text-sm font-medium text-gray-300 mb-2">Host / IP Alvo</label>
                  <input
                    type="text"
                    value={execModal.target}
                    onChange={e => setExecModal(m => ({ ...m, target: e.target.value }))}
                    placeholder="ex: 192.168.1.10 ou servidor.local"
                    className="input-dark w-full"
                    autoFocus
                    onKeyDown={e => e.key === 'Enter' && handleExecutePlaybook()}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Porta <span className="text-gray-500">(opcional)</span></label>
                  <input
                    type="number"
                    value={execModal.port}
                    onChange={e => setExecModal(m => ({ ...m, port: e.target.value }))}
                    placeholder="80"
                    className="input-dark w-full"
                  />
                </div>
              </div>
              <div className="bg-dark-700 rounded p-3 text-xs text-gray-400 space-y-1">
                <p><span className="text-gray-500">Técnicas:</span> {execModal.playbook?.techniques}</p>
                <p><span className="text-gray-500">Impacto:</span> <span className={SEV_COLOR[execModal.playbook?.severity]}>{SEV_PT[execModal.playbook?.severity]}</span></p>
              </div>
              <div className="bg-red-900/20 border border-red-700/40 rounded p-3 text-xs text-red-400 flex gap-2">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>Execute apenas em sistemas que você tem autorização explícita para testar.</span>
              </div>
            </div>
            <div className="flex justify-end gap-2 p-6 border-t border-dark-600">
              <button onClick={() => setExecModal(m => ({ ...m, show: false }))} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded transition">
                Cancelar
              </button>
              <button onClick={handleExecutePlaybook} className="btn-red flex items-center gap-2">
                <Play className="w-4 h-4" /> Iniciar Simulação
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal Agendar */}
      {schedModal.show && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="card-dark max-w-md w-full">
            <div className="flex justify-between items-center p-6 border-b border-dark-600">
              <div>
                <h2 className="text-xl font-bold text-gray-100 flex items-center gap-2">
                  <Calendar className="w-5 h-5 text-cyan-400" /> Agendar Simulação
                </h2>
                <p className="text-xs text-gray-400 mt-1">Roteiro: <span className="text-cyan-400">{schedModal.playbook?.name}</span></p>
              </div>
              <button onClick={() => setSchedModal(m => ({ ...m, show: false }))} className="text-gray-400 hover:text-gray-100">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Host / IP Alvo</label>
                <input
                  type="text"
                  value={schedModal.target}
                  onChange={e => setSchedModal(m => ({ ...m, target: e.target.value }))}
                  placeholder="ex: 192.168.1.10"
                  className="input-dark w-full"
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Frequência</label>
                <select
                  value={schedModal.interval}
                  onChange={e => setSchedModal(m => ({ ...m, interval: e.target.value }))}
                  className="select-dark w-full"
                >
                  <option value="daily">Diário — a cada 24 horas</option>
                  <option value="weekly">Semanal — a cada 7 dias</option>
                  <option value="monthly">Mensal — a cada 30 dias</option>
                </select>
              </div>
              <div className="bg-cyan-900/20 border border-cyan-700/40 rounded p-3 text-xs text-cyan-300 flex gap-2">
                <Clock className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>A simulação será executada automaticamente no intervalo escolhido. Você pode cancelar o agendamento a qualquer momento.</span>
              </div>
            </div>
            <div className="flex justify-end gap-2 p-6 border-t border-dark-600">
              <button onClick={() => setSchedModal(m => ({ ...m, show: false }))} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded transition">
                Cancelar
              </button>
              <button onClick={handleSchedule} className="px-4 py-2 bg-cyan-700 hover:bg-cyan-600 text-white rounded transition flex items-center gap-2">
                <Calendar className="w-4 h-4" /> Confirmar Agendamento
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal Novo Roteiro */}
      {showNewPlaybook && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 overflow-y-auto">
          <div className="card-dark max-w-md w-full my-auto">
            <div className="flex justify-between items-center p-6 border-b border-dark-600">
              <div>
                <h2 className="text-xl font-bold text-gray-100">Criar Roteiro de Ataque</h2>
                <p className="text-xs text-gray-400 mt-1">Defina o nome e características da simulação</p>
              </div>
              <button onClick={() => setShowNewPlaybook(false)} className="text-gray-400 hover:text-gray-100 transition">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Nome do Roteiro <span className="text-gray-500 font-normal ml-1">(dê um nome descritivo)</span>
                </label>
                <input
                  type="text"
                  value={newPlaybook.name}
                  onChange={(e) => setNewPlaybook({ ...newPlaybook, name: e.target.value })}
                  placeholder="ex: Teste de Firewall - Rede Interna"
                  className="input-dark w-full"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">Nº de Técnicas</label>
                  <p className="text-xs text-gray-500 mb-2">Quantas técnicas de ataque usar</p>
                  <input
                    type="number"
                    value={newPlaybook.techniques}
                    onChange={(e) => setNewPlaybook({ ...newPlaybook, techniques: parseInt(e.target.value) || 0 })}
                    min="1" max="40"
                    className="input-dark w-full"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">Nível de Impacto</label>
                  <p className="text-xs text-gray-500 mb-2">Agressividade da simulação</p>
                  <select
                    value={newPlaybook.severity}
                    onChange={(e) => setNewPlaybook({ ...newPlaybook, severity: e.target.value })}
                    className="select-dark w-full"
                  >
                    <option value="Low">Baixo — impacto mínimo</option>
                    <option value="Medium">Médio — equilibrado</option>
                    <option value="High">Alto — agressivo</option>
                    <option value="Critical">Crítico — máximo</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Descrição <span className="text-gray-500 font-normal">(opcional)</span>
                </label>
                <textarea
                  value={newPlaybook.description}
                  onChange={(e) => setNewPlaybook({ ...newPlaybook, description: e.target.value })}
                  placeholder="Descreva o objetivo deste roteiro de ataque..."
                  className="input-dark w-full h-24 resize-none"
                />
              </div>
              <div className="bg-blue-900/20 border border-blue-700/40 rounded p-3 text-xs text-blue-300 flex gap-2">
                <Info className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>Após criar o roteiro, ele aparecerá na lista acima onde você poderá executá-lo a qualquer momento.</span>
              </div>
            </div>
            <div className="flex justify-end gap-2 p-6 border-t border-dark-600">
              <button onClick={() => setShowNewPlaybook(false)} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded transition">
                Cancelar
              </button>
              <button onClick={handleCreatePlaybook} className="btn-blue">
                Criar Roteiro
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
