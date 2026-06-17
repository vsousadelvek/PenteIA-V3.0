import React, { useState, useEffect } from 'react'
import { Shield, CheckCircle, AlertTriangle, XCircle, FileText, Download, ChevronDown, X } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

const TAB_LABELS = {
  lgpd:    'LGPD',
  bacen:   'BACEN 4.893',
  pci:     'PCI DSS v4.0',
  iso27001: 'ISO 27001:2022',
}

const RISK_META = {
  Alto:  { color: 'text-red-400',    bg: 'bg-red-900/30 border-red-700/50',    icon: XCircle },
  Médio: { color: 'text-yellow-400', bg: 'bg-yellow-900/30 border-yellow-700/50', icon: AlertTriangle },
  Baixo: { color: 'text-green-400',  bg: 'bg-green-900/30 border-green-700/50',  icon: CheckCircle },
}

function getRiskMeta(level) {
  return RISK_META[level] || RISK_META['Médio']
}

// ---------------------------------------------------------------------------
// Skeleton loader
// ---------------------------------------------------------------------------
function SkeletonBlock({ className = '' }) {
  return (
    <div className={`animate-pulse rounded bg-dark-700 ${className}`} />
  )
}

function ComplianceSkeleton() {
  return (
    <div className="space-y-6">
      {/* Summary bar */}
      <div className="card-dark p-5 flex flex-wrap gap-6 items-center">
        <SkeletonBlock className="h-8 w-48" />
        <SkeletonBlock className="h-8 w-32" />
        <SkeletonBlock className="h-8 w-36" />
      </div>
      {/* Tabs */}
      <div className="flex gap-2">
        {[1, 2, 3, 4].map(i => <SkeletonBlock key={i} className="h-10 w-32" />)}
      </div>
      {/* Violations list */}
      <div className="card-dark p-6 space-y-4">
        {[1, 2, 3].map(i => (
          <div key={i} className="space-y-2">
            <SkeletonBlock className="h-5 w-40" />
            <SkeletonBlock className="h-4 w-full" />
            <SkeletonBlock className="h-4 w-3/4" />
            <div className="flex gap-2 pt-1">
              <SkeletonBlock className="h-5 w-16" />
              <SkeletonBlock className="h-5 w-16" />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Risk level badge
// ---------------------------------------------------------------------------
function RiskBadge({ level }) {
  const meta = getRiskMeta(level)
  const Icon = meta.icon
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded border ${meta.bg} ${meta.color}`}>
      <Icon className="w-3.5 h-3.5" />
      Risco {level}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Single violation card
// ---------------------------------------------------------------------------
function ViolationCard({ violation }) {
  const { article, title, description, technique_ids = [] } = violation
  return (
    <div className="border border-dark-600 rounded-lg p-4 bg-dark-800 hover:border-dark-500 transition">
      <div className="flex flex-wrap items-start gap-3 mb-2">
        <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-red-900/40 text-red-400 border border-red-800/40 flex-shrink-0">
          {article}
        </span>
        <h4 className="text-sm font-semibold text-gray-100 leading-snug">{title}</h4>
      </div>
      {description && (
        <p className="text-xs text-gray-400 leading-relaxed mb-3">{description}</p>
      )}
      {technique_ids.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {technique_ids.map(tid => (
            <span
              key={tid}
              className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-dark-600 text-gray-500 border border-dark-500"
            >
              {tid}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Framework tab panel
// ---------------------------------------------------------------------------
function FrameworkPanel({ data }) {
  if (!data) {
    return (
      <div className="card-dark p-8 text-center text-gray-500 text-sm">
        Dados do framework não disponíveis.
      </div>
    )
  }

  const { risk_level, violations = [] } = data

  return (
    <div className="space-y-4">
      {/* Header row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <RiskBadge level={risk_level} />
        <span className="text-xs text-gray-500">
          {violations.length === 0
            ? 'Nenhuma violação encontrada'
            : `${violations.length} violação${violations.length > 1 ? 'ões' : ''} detectada${violations.length > 1 ? 's' : ''}`}
        </span>
      </div>

      {violations.length === 0 ? (
        <div className="flex items-center gap-3 p-4 rounded-lg bg-green-900/20 border border-green-700/40">
          <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
          <p className="text-sm text-green-300 font-medium">Sem violações detectadas</p>
        </div>
      ) : (
        <div className="space-y-3">
          {violations.map((v, idx) => (
            <ViolationCard key={`${v.article}-${idx}`} violation={v} />
          ))}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// ANPD notification modal
// ---------------------------------------------------------------------------
function AnpdModal({ simId, onClose, toast }) {
  const [form, setForm] = useState({
    controllerName: '',
    controllerCnpj: '',
    dpoName: '',
    dpoEmail: '',
  })
  const [loading, setLoading] = useState(false)

  const handleChange = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }))

  const handleSubmit = async e => {
    e.preventDefault()
    if (!form.controllerName || !form.controllerCnpj || !form.dpoName || !form.dpoEmail) {
      toast('Preencha todos os campos obrigatórios.', 'error')
      return
    }
    setLoading(true)
    try {
      const res = await api.post(
        '/api/compliance/anpd-custom',
        {
          simulation_id: simId,
          controller_info: {
            controller_name: form.controllerName,
            controller_cnpj: form.controllerCnpj,
            dpo_name: form.dpoName,
            dpo_email: form.dpoEmail,
          },
        },
        { responseType: 'blob' }
      )
      const url = URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }))
      const a   = document.createElement('a')
      a.href     = url
      a.download = `notificacao_anpd_${simId?.slice(0, 8) || 'export'}.pdf`
      a.click()
      URL.revokeObjectURL(url)
      toast('Notificação ANPD gerada com sucesso!', 'success')
      onClose()
    } catch (err) {
      toast('Erro ao gerar notificação ANPD: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-md bg-dark-800 border border-dark-600 rounded-xl shadow-2xl p-6 mx-4">
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-3 right-3 text-gray-500 hover:text-gray-300 transition"
          aria-label="Fechar"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-5">
          <AlertTriangle className="w-6 h-6 text-orange-400 flex-shrink-0" />
          <h2 className="text-lg font-bold text-gray-100">Gerar Notificação ANPD</h2>
        </div>

        <p className="text-xs text-gray-400 mb-5 leading-relaxed">
          Preencha os dados do controlador e do encarregado (DPO) para gerar a notificação
          de incidente conforme a LGPD (Lei 13.709/2018, Art. 48).
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">
              Nome do Controlador (empresa) <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              name="controllerName"
              value={form.controllerName}
              onChange={handleChange}
              placeholder="Ex.: Acme Instituição Financeira S.A."
              className="input-dark w-full text-sm"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">
              CNPJ do Controlador <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              name="controllerCnpj"
              value={form.controllerCnpj}
              onChange={handleChange}
              placeholder="00.000.000/0000-00"
              className="input-dark w-full text-sm"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">
              Nome do Encarregado (DPO) <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              name="dpoName"
              value={form.dpoName}
              onChange={handleChange}
              placeholder="Ex.: João Silva"
              className="input-dark w-full text-sm"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">
              Email do Encarregado <span className="text-red-400">*</span>
            </label>
            <input
              type="email"
              name="dpoEmail"
              value={form.dpoEmail}
              onChange={handleChange}
              placeholder="dpo@empresa.com.br"
              className="input-dark w-full text-sm"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-orange-700 hover:bg-orange-600 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold rounded transition border border-orange-600/50 mt-2"
          >
            <AlertTriangle className="w-4 h-4" />
            {loading ? 'Gerando…' : 'Gerar Notificação ANPD'}
          </button>
        </form>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function Compliance() {
  const toast = useToast()

  const [simulations, setSimulations]         = useState([])
  const [selectedSimId, setSelectedSimId]     = useState('')
  const [complianceData, setComplianceData]   = useState(null)
  const [loadingSims, setLoadingSims]         = useState(true)
  const [loadingMap, setLoadingMap]           = useState(false)
  const [activeTab, setActiveTab]             = useState('lgpd')
  const [anpdOpen, setAnpdOpen]               = useState(false)
  const [bacenLoading, setBacenLoading]       = useState(false)

  // Fetch completed simulations on mount
  useEffect(() => {
    const fetchSimulations = async () => {
      try {
        const res = await api.get('/api/bas/simulations')
        const completed = (res.data.simulations || []).filter(s => s.status === 'completed')
        setSimulations(completed)
      } catch (err) {
        toast('Erro ao carregar simulações: ' + (err.response?.data?.detail || err.message), 'error')
      } finally {
        setLoadingSims(false)
      }
    }
    fetchSimulations()
  }, [])

  // Fetch compliance map whenever selection changes
  useEffect(() => {
    if (!selectedSimId) {
      setComplianceData(null)
      return
    }

    const fetchMap = async () => {
      setLoadingMap(true)
      setComplianceData(null)
      try {
        const res = await api.get(`/api/compliance/map?simulation_id=${selectedSimId}`)
        setComplianceData(res.data)
        setActiveTab('lgpd')
      } catch (err) {
        toast('Erro ao carregar mapa de conformidade: ' + (err.response?.data?.detail || err.message), 'error')
      } finally {
        setLoadingMap(false)
      }
    }
    fetchMap()
  }, [selectedSimId])

  // Download BACEN 4.893 evidence PDF
  const handleBacenPdf = async () => {
    if (!selectedSimId) return
    setBacenLoading(true)
    try {
      const res = await api.get(`/api/compliance/bacen-pdf/${selectedSimId}`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }))
      const a   = document.createElement('a')
      a.href     = url
      a.download = `bacen_4893_evidencia_${selectedSimId.slice(0, 8)}.pdf`
      a.click()
      URL.revokeObjectURL(url)
      toast('Relatório BACEN 4.893 baixado com sucesso!', 'success')
    } catch (err) {
      toast('Erro ao gerar relatório BACEN: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setBacenLoading(false)
    }
  }

  // Export compliance data as JSON file
  const handleExport = () => {
    if (!complianceData) return
    const blob = new Blob([JSON.stringify(complianceData, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    const sim  = complianceData.simulation
    const name = `compliance_${sim?.target || 'export'}_${sim?.id?.slice(0, 8) || 'data'}.json`
    a.href     = url
    a.download = name
    a.click()
    URL.revokeObjectURL(url)
    toast('Evidências exportadas com sucesso!', 'success')
  }

  // Derived values
  const frameworks  = complianceData?.frameworks  || {}
  const summary     = complianceData?.summary     || {}
  const simulation  = complianceData?.simulation  || {}

  const totalViolations = summary.total_violations ?? 0
  const frameworksFailed = summary.frameworks_failed ?? 0

  // Overall risk: use highest risk level found across tabs
  const riskOrder = { Alto: 3, Médio: 2, Baixo: 1 }
  const overallRisk = Object.values(frameworks).reduce((acc, fw) => {
    const lvl = fw?.risk_level
    if (!lvl) return acc
    return (riskOrder[lvl] || 0) > (riskOrder[acc] || 0) ? lvl : acc
  }, 'Baixo')

  return (
    <div className="space-y-8">
      {/* ------------------------------------------------------------------ */}
      {/* Header                                                              */}
      {/* ------------------------------------------------------------------ */}
      <div className="slide-in">
        <div className="flex items-center gap-3 mb-2">
          <Shield className="w-8 h-8 text-blue-400" />
          <h1 className="text-4xl font-bold text-gray-100">Conformidade Regulatória</h1>
        </div>
        <p className="text-gray-400">
          Mapeie automaticamente os resultados de simulações BAS para frameworks regulatórios —
          LGPD, BACEN 4.893, PCI DSS v4.0 e ISO 27001:2022.
        </p>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* BACEN 4.893 info box                                                */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex items-start gap-3 px-4 py-3 rounded-lg bg-blue-900/20 border border-blue-700/40 text-sm text-blue-200 leading-relaxed">
        <FileText className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
        <span>
          <span className="font-semibold text-blue-300">Resolução BCB 4.893/2021 — Art. 4º</span>{' '}
          exige testes de segurança anuais documentados. Este relatório serve como evidência
          formal para fins de conformidade com o Banco Central do Brasil.
        </span>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Simulation selector                                                 */}
      {/* ------------------------------------------------------------------ */}
      <div className="card-dark p-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex-1 min-w-[260px]">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Selecionar Simulação BAS
            </label>
            {loadingSims ? (
              <div className="animate-pulse h-10 rounded bg-dark-700 w-full" />
            ) : (
              <div className="relative">
                <select
                  value={selectedSimId}
                  onChange={e => setSelectedSimId(e.target.value)}
                  className="select-dark w-full pr-8 appearance-none"
                >
                  <option value="">— Escolha uma simulação concluída —</option>
                  {simulations.map(sim => (
                    <option key={sim.id} value={sim.id}>
                      {sim.playbook_name || sim.id?.slice(0, 8) || '?'} · {sim.target} · Score {sim.score ?? 0}%
                      {(sim.date || sim.created_at) ? ` · ${new Date(sim.date || sim.created_at).toLocaleDateString('pt-BR')}` : ''}
                    </option>
                  ))}
                </select>
                <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              </div>
            )}
            {!loadingSims && simulations.length === 0 && (
              <p className="mt-2 text-xs text-gray-500">
                Nenhuma simulação concluída encontrada. Execute uma simulação BAS primeiro.
              </p>
            )}
          </div>

          {complianceData && (
            <button
              onClick={handleExport}
              className="flex items-center gap-2 px-4 py-2 bg-blue-800 hover:bg-blue-700 text-white text-sm rounded transition border border-blue-700/50 flex-shrink-0"
            >
              <Download className="w-4 h-4" />
              Exportar Evidências (JSON)
            </button>
          )}
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Empty state                                                         */}
      {/* ------------------------------------------------------------------ */}
      {!selectedSimId && !loadingMap && (
        <div className="card-dark p-12 text-center border border-dashed border-dark-600">
          <FileText className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h2 className="text-lg font-semibold text-gray-400 mb-2">Nenhuma simulação selecionada</h2>
          <p className="text-sm text-gray-500 max-w-md mx-auto leading-relaxed">
            Selecione uma simulação BAS concluída no menu acima para visualizar o mapeamento
            de conformidade regulatória e as violações identificadas.
          </p>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Loading skeleton                                                    */}
      {/* ------------------------------------------------------------------ */}
      {loadingMap && <ComplianceSkeleton />}

      {/* ------------------------------------------------------------------ */}
      {/* Compliance map                                                      */}
      {/* ------------------------------------------------------------------ */}
      {!loadingMap && complianceData && (
        <div className="space-y-6">
          {/* Summary bar */}
          <div className="card-dark p-5">
            <div className="flex flex-wrap gap-6 items-center">
              {/* Simulation info */}
              <div className="flex items-center gap-2 text-sm">
                <Shield className="w-4 h-4 text-blue-400 flex-shrink-0" />
                <span className="text-gray-400">Alvo:</span>
                <span className="text-gray-100 font-mono font-semibold">{simulation.target || '—'}</span>
                <span className="text-gray-600">·</span>
                <span className="text-gray-400">Score BAS:</span>
                <span className={`font-bold ${(simulation.score ?? 0) >= 50 ? 'text-red-400' : (simulation.score ?? 0) >= 25 ? 'text-yellow-400' : 'text-green-400'}`}>
                  {simulation.score ?? 0}%
                </span>
              </div>

              <div className="h-5 w-px bg-dark-600 hidden sm:block" />

              {/* Total violations */}
              <div className="flex items-center gap-2 text-sm">
                {totalViolations > 0
                  ? <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                  : <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                }
                <span className={`font-bold ${totalViolations > 0 ? 'text-red-400' : 'text-green-400'}`}>
                  {totalViolations}
                </span>
                <span className="text-gray-400">violação{totalViolations !== 1 ? 'ões' : ''} no total</span>
              </div>

              <div className="h-5 w-px bg-dark-600 hidden sm:block" />

              {/* Frameworks failed */}
              <div className="flex items-center gap-2 text-sm">
                <AlertTriangle className={`w-4 h-4 flex-shrink-0 ${frameworksFailed > 0 ? 'text-yellow-400' : 'text-green-400'}`} />
                <span className={`font-bold ${frameworksFailed > 0 ? 'text-yellow-400' : 'text-green-400'}`}>
                  {frameworksFailed}
                </span>
                <span className="text-gray-400">framework{frameworksFailed !== 1 ? 's' : ''} com falha</span>
              </div>

              <div className="h-5 w-px bg-dark-600 hidden sm:block" />

              {/* Overall risk */}
              <RiskBadge level={overallRisk} />
            </div>
          </div>

          {/* ---------------------------------------------------------------- */}
          {/* Tabs                                                             */}
          {/* ---------------------------------------------------------------- */}
          <div className="flex gap-1 flex-wrap">
            {Object.entries(TAB_LABELS).map(([key, label]) => {
              const fw = frameworks[key]
              const hasViolations = (fw?.violations?.length ?? 0) > 0
              const isActive = activeTab === key
              return (
                <button
                  key={key}
                  onClick={() => setActiveTab(key)}
                  className={`flex items-center gap-2 px-4 py-2.5 rounded-t text-sm font-medium transition border-b-2 ${
                    isActive
                      ? 'bg-dark-700 text-gray-100 border-blue-500'
                      : 'bg-dark-800 text-gray-400 border-transparent hover:bg-dark-700 hover:text-gray-300'
                  }`}
                >
                  {label}
                  {hasViolations && (
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full ${
                      isActive ? 'bg-red-700 text-white' : 'bg-red-900/60 text-red-400'
                    }`}>
                      {fw?.violations?.length ?? 0}
                    </span>
                  )}
                  {!hasViolations && fw && (
                    <CheckCircle className="w-3.5 h-3.5 text-green-500" />
                  )}
                </button>
              )
            })}
          </div>

          {/* Tab panel */}
          <div className="card-dark p-6">
            <div className="flex items-center gap-2 mb-5 pb-4 border-b border-dark-600">
              <FileText className="w-5 h-5 text-blue-400" />
              <h2 className="text-lg font-bold text-gray-100">{TAB_LABELS[activeTab]}</h2>
            </div>
            <FrameworkPanel data={frameworks[activeTab]} />
          </div>

          {/* ---------------------------------------------------------------- */}
          {/* Exportar Documentos                                              */}
          {/* ---------------------------------------------------------------- */}
          <div className="card-dark p-6 space-y-4">
            <div className="flex items-center gap-2 pb-3 border-b border-dark-600">
              <Download className="w-5 h-5 text-gray-400" />
              <h2 className="text-base font-bold text-gray-100">Exportar Documentos</h2>
            </div>

            <div className="flex flex-wrap gap-3">
              {/* Button A — BACEN 4.893 PDF */}
              <button
                onClick={handleBacenPdf}
                disabled={bacenLoading}
                className="flex items-center gap-2 px-5 py-2.5 bg-red-700 hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold rounded transition border border-red-600/50"
              >
                <FileText className="w-4 h-4" />
                {bacenLoading ? 'Gerando PDF…' : 'Relatório BACEN 4.893 (PDF)'}
              </button>

              {/* Button B — ANPD notification modal */}
              <button
                onClick={() => setAnpdOpen(true)}
                className="flex items-center gap-2 px-5 py-2.5 bg-orange-700 hover:bg-orange-600 text-white text-sm font-semibold rounded transition border border-orange-600/50"
              >
                <AlertTriangle className="w-4 h-4" />
                Notificação ANPD (PDF)
              </button>
            </div>

            <p className="text-xs text-gray-500 leading-relaxed">
              O relatório BACEN gera evidência formal dos testes realizados conforme Art. 4º da
              Resolução 4.893/2021. A notificação ANPD documenta o incidente conforme LGPD Art. 48.
            </p>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* ANPD modal                                                          */}
      {/* ------------------------------------------------------------------ */}
      {anpdOpen && (
        <AnpdModal
          simId={selectedSimId}
          onClose={() => setAnpdOpen(false)}
          toast={toast}
        />
      )}
    </div>
  )
}
