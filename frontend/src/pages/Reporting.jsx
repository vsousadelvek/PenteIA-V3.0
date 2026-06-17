import React, { useState, useEffect } from 'react'
import { Download, FileText, Plus, Loader, BookOpen, Info, Shield, CheckCircle, FileDown, Building2, BarChart2 } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

const COMPLIANCE_FRAMEWORKS = [
  {
    id: 'lgpd',
    name: 'LGPD',
    full: 'Lei Geral de Proteção de Dados (Lei 13.709/2018)',
    desc: 'Mapeia vulnerabilidades para os artigos da LGPD relacionados à segurança e proteção de dados pessoais.',
    color: 'border-green-600/40',
    tag: 'text-green-400',
    badge: 'bg-green-900/30 text-green-400',
    flag: '🇧🇷',
  },
  {
    id: 'iso27001',
    name: 'ISO 27001',
    full: 'ISO/IEC 27001:2022 — Segurança da Informação',
    desc: 'Mapeamento para controles do Annex A da ISO 27001:2022 — padrão internacional de segurança da informação.',
    color: 'border-blue-600/40',
    tag: 'text-blue-400',
    badge: 'bg-blue-900/30 text-blue-400',
    flag: '🌐',
  },
  {
    id: 'pcidss',
    name: 'PCI DSS 4.0',
    full: 'Payment Card Industry Data Security Standard v4.0',
    desc: 'Mapeamento para requisitos PCI DSS 4.0 — obrigatório para ambientes que processam cartões de pagamento.',
    color: 'border-yellow-600/40',
    tag: 'text-yellow-400',
    badge: 'bg-yellow-900/30 text-yellow-400',
    flag: '💳',
  },
]

const TEMPLATES = [
  {
    id: 1,
    name: 'Penetration Test Report',
    label: 'Relatório Completo de Pentest',
    format: 'PDF',
    sections: 12,
    desc: 'Relatório técnico detalhado com todas as vulnerabilidades encontradas, evidências e recomendações. Ideal para a equipe de TI e segurança.',
    audience: 'Equipe técnica de TI',
    color: 'border-red-600/40',
    tag: 'text-red-400',
  },
  {
    id: 2,
    name: 'Executive Summary',
    label: 'Resumo Executivo',
    format: 'DOCX',
    sections: 5,
    desc: 'Documento simplificado para gestores e diretores, sem termos técnicos. Foca no impacto para o negócio e nas prioridades de correção.',
    audience: 'Gestores e diretores',
    color: 'border-blue-600/40',
    tag: 'text-blue-400',
  },
  {
    id: 3,
    name: 'Technical Findings',
    label: 'Achados Técnicos',
    format: 'PDF',
    sections: 8,
    desc: 'Lista detalhada de todas as vulnerabilidades com classificação de risco, prova de conceito e detalhes técnicos para desenvolvedores.',
    audience: 'Desenvolvedores e analistas',
    color: 'border-yellow-600/40',
    tag: 'text-yellow-400',
  },
  {
    id: 4,
    name: 'Remediation Roadmap',
    label: 'Plano de Correção',
    format: 'XLSX',
    sections: 6,
    desc: 'Planilha com cronograma priorizado de correções: o que corrigir primeiro, estimativa de esforço e quem é responsável.',
    audience: 'Gerente de projetos / TI',
    color: 'border-green-600/40',
    tag: 'text-green-400',
  },
]

const FORMAT_INFO = {
  PDF:  'Formato fixo, ideal para enviar por email e imprimir. Não editável.',
  DOCX: 'Formato Word — pode ser editado e personalizado antes de enviar.',
  HTML: 'Página web interativa — boa para visualizar no navegador.',
  XLSX: 'Planilha Excel — ideal para organizar em tarefas e acompanhar correções.',
}

export default function Reporting() {
  const toast = useToast()
  const [reports, setReports] = useState([])
  const [simulations, setSimulations] = useState([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [complianceGen, setComplianceGen] = useState(null)
  const [selectedSimId, setSelectedSimId] = useState('')
  const [formData, setFormData] = useState({
    template: 'Penetration Test Report',
    format: 'PDF',
    title: '',
  })

  const selectedTemplate = TEMPLATES.find(t => t.name === formData.template)

  // Executive PDF state
  const [execForm, setExecForm] = useState({
    organization: '',
    period_start: '',
    period_end: '',
    sector: 'general',
    prepared_by: '',
  })
  const [execGenerating, setExecGenerating] = useState(false)
  const [benchmark, setBenchmark] = useState(null)
  const [benchmarkLoading, setBenchmarkLoading] = useState(false)

  const SECTORS = [
    { value: 'financial',   label: 'Financeiro' },
    { value: 'healthcare',  label: 'Saúde' },
    { value: 'retail',      label: 'Varejo' },
    { value: 'government',  label: 'Governo' },
    { value: 'technology',  label: 'Tecnologia' },
    { value: 'energy',      label: 'Energia' },
    { value: 'general',     label: 'Geral' },
  ]

  const fetchBenchmark = async (sector) => {
    setBenchmarkLoading(true)
    setBenchmark(null)
    try {
      const res = await api.get(`/api/reports/benchmarks/${sector}`)
      setBenchmark(res.data)
    } catch (err) {
      toast('Erro ao buscar benchmark: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setBenchmarkLoading(false)
    }
  }

  const handleSectorChange = (sector) => {
    setExecForm(f => ({ ...f, sector }))
    fetchBenchmark(sector)
  }

  const handleExecPdf = async () => {
    if (!execForm.organization.trim()) {
      toast('Informe o nome da organização', 'warning')
      return
    }
    if (!execForm.period_start || !execForm.period_end) {
      toast('Informe o período do relatório', 'warning')
      return
    }
    setExecGenerating(true)
    try {
      const res = await api.post('/api/reports/executive/pdf', execForm, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }))
      const link = document.createElement('a')
      link.href = url
      const orgSlug = execForm.organization.replace(/[^a-z0-9]/gi, '_').toLowerCase()
      link.setAttribute('download', `relatorio_executivo_${orgSlug}.pdf`)
      document.body.appendChild(link)
      link.click()
      link.parentNode.removeChild(link)
      window.URL.revokeObjectURL(url)
      toast('Relatório Executivo gerado com sucesso!', 'success')
    } catch (err) {
      toast('Erro ao gerar PDF Executivo: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setExecGenerating(false)
    }
  }

  useEffect(() => {
    fetchReports()
    api.get('/api/bas/simulations').then(r => {
      const completed = (r.data.simulations || []).filter(s => s.status === 'completed')
      setSimulations(completed)
      if (completed.length > 0) setSelectedSimId(completed[0].id)
    }).catch(() => {})
  }, [])

  const fetchReports = async () => {
    try {
      const res = await api.get('/api/reporting/reports')
      setReports(res.data.reports || [])
    } catch (err) {
      console.error('Erro ao buscar relatórios:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleGenerateReport = async () => {
    if (!formData.title.trim()) {
      toast('Digite um título para o relatório antes de gerar', 'warning')
      return
    }
    setGenerating(true)
    try {
      await api.post('/api/reporting/generate', {
        title: formData.title,
        report_type: formData.template,
        format: formData.format,
      })
      setFormData(f => ({ ...f, title: '' }))
      await fetchReports()
      toast('Relatório gerado com sucesso!', 'success')
    } catch (err) {
      toast('Erro ao gerar relatório: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setGenerating(false)
    }
  }

  const handleComplianceReport = async (framework) => {
    setComplianceGen(framework)
    try {
      const res = await api.post('/api/reporting/compliance', {
        framework,
        simulation_id: selectedSimId || undefined,
      }, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `compliance_${framework}.pdf`)
      document.body.appendChild(link)
      link.click()
      link.parentNode.removeChild(link)
      window.URL.revokeObjectURL(url)
      toast(`Relatório ${framework.toUpperCase()} gerado!`, 'success')
    } catch (err) {
      toast('Erro ao gerar relatório de compliance: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setComplianceGen(null)
    }
  }

  const handleDownload = async (report) => {
    try {
      const res = await api.get(`/api/reporting/reports/${report.id}/download`, { responseType: 'blob' })
      const fmt = (report.format || 'pdf').toLowerCase()
      const ext = fmt === 'word' || fmt === 'docx' ? 'docx' : fmt === 'excel' || fmt === 'xlsx' ? 'xlsx' : 'pdf'
      const name = (report.title || `report-${report.id}`).replace(/[^a-z0-9_-]/gi, '_')
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `${name}.${ext}`)
      document.body.appendChild(link)
      link.click()
      link.parentNode.removeChild(link)
      window.URL.revokeObjectURL(url)
    } catch (err) {
      toast('Erro ao baixar relatório: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">Relatórios</h1>
        <p className="text-gray-400">Gere documentos profissionais com os resultados dos testes de segurança</p>
      </div>

      {/* ── Relatório Executivo para Board ─────────────────────────────── */}
      <div className="card-dark p-6 border-2 border-purple-600/40">
        <div className="flex items-center gap-3 mb-5">
          <Building2 className="w-6 h-6 text-purple-400" />
          <div>
            <h2 className="text-2xl font-bold text-gray-100">Relatório Executivo para Board</h2>
            <p className="text-gray-400 text-sm mt-0.5">Gere um PDF executivo formatado para apresentação à diretoria, com comparativo de benchmark setorial.</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 mb-6">
          {/* Organização */}
          <div className="lg:col-span-3">
            <label className="block text-sm font-medium text-gray-300 mb-1">Nome da Organização</label>
            <div className="flex items-center gap-2">
              <Building2 className="w-4 h-4 text-gray-500 shrink-0" />
              <input
                type="text"
                value={execForm.organization}
                onChange={e => setExecForm(f => ({ ...f, organization: e.target.value }))}
                placeholder="ex: Empresa ABC Ltda."
                className="input-dark w-full"
                disabled={execGenerating}
              />
            </div>
          </div>

          {/* Período início */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Início do Período</label>
            <input
              type="date"
              value={execForm.period_start}
              onChange={e => setExecForm(f => ({ ...f, period_start: e.target.value }))}
              className="input-dark w-full"
              disabled={execGenerating}
            />
          </div>

          {/* Período fim */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Fim do Período</label>
            <input
              type="date"
              value={execForm.period_end}
              onChange={e => setExecForm(f => ({ ...f, period_end: e.target.value }))}
              className="input-dark w-full"
              disabled={execGenerating}
            />
          </div>

          {/* Setor */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Setor</label>
            <select
              value={execForm.sector}
              onChange={e => handleSectorChange(e.target.value)}
              className="select-dark w-full"
              disabled={execGenerating}
            >
              {SECTORS.map(s => (
                <option key={s.value} value={s.value}>{s.label}</option>
              ))}
            </select>
          </div>

          {/* Preparado por */}
          <div className="md:col-span-2 lg:col-span-3">
            <label className="block text-sm font-medium text-gray-300 mb-1">Preparado por</label>
            <input
              type="text"
              value={execForm.prepared_by}
              onChange={e => setExecForm(f => ({ ...f, prepared_by: e.target.value }))}
              placeholder="ex: João Silva — Analista de Segurança"
              className="input-dark w-full"
              disabled={execGenerating}
            />
          </div>
        </div>

        {/* Benchmark widget */}
        <div className="mb-6">
          <div className="flex items-center gap-2 mb-3">
            <BarChart2 className="w-5 h-5 text-purple-400" />
            <h3 className="text-base font-semibold text-gray-200">Sua org vs benchmark do setor</h3>
            {!benchmark && !benchmarkLoading && (
              <button
                onClick={() => fetchBenchmark(execForm.sector)}
                className="ml-auto text-xs text-purple-400 hover:text-purple-300 underline transition"
              >
                Carregar benchmark
              </button>
            )}
          </div>

          {benchmarkLoading && (
            <div className="flex items-center gap-2 text-gray-400 text-sm py-4">
              <Loader className="w-4 h-4 animate-spin text-purple-400" />
              Buscando dados do setor...
            </div>
          )}

          {benchmark && !benchmarkLoading && (() => {
            const sectorAvg  = benchmark.sector_average  ?? benchmark.average ?? null
            const top25      = benchmark.top_25_percent  ?? benchmark.top25   ?? null
            const orgScore   = benchmark.your_score      ?? benchmark.org_score ?? null
            const diffRaw    = (orgScore !== null && sectorAvg !== null) ? orgScore - sectorAvg : null
            const diffSign   = diffRaw !== null ? (diffRaw >= 0 ? 'acima' : 'abaixo') : null
            const diffColor  = diffRaw !== null ? (diffRaw >= 0 ? 'text-green-400' : 'text-red-400') : 'text-gray-400'
            const sectorLabel = SECTORS.find(s => s.value === execForm.sector)?.label ?? execForm.sector

            return (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 bg-dark-700 rounded-lg p-4 border border-purple-600/30">
                <div className="text-center">
                  <p className="text-xs text-gray-500 mb-1">Media do setor ({sectorLabel})</p>
                  <p className="text-2xl font-bold text-gray-100">
                    {sectorAvg !== null ? `${Number(sectorAvg).toFixed(1)}%` : '—'}
                  </p>
                </div>
                <div className="text-center">
                  <p className="text-xs text-gray-500 mb-1">Top 25%</p>
                  <p className="text-2xl font-bold text-yellow-400">
                    {top25 !== null ? `${Number(top25).toFixed(1)}%` : '—'}
                  </p>
                </div>
                <div className="text-center">
                  <p className="text-xs text-gray-500 mb-1">Posicionamento</p>
                  {diffRaw !== null ? (
                    <p className={`text-2xl font-bold ${diffColor}`}>
                      {Math.abs(diffRaw).toFixed(1)}% {diffSign} da media
                    </p>
                  ) : (
                    <p className="text-lg text-gray-500 pt-1">Score da org nao disponivel</p>
                  )}
                </div>
              </div>
            )
          })()}

          {!benchmark && !benchmarkLoading && (
            <p className="text-xs text-gray-600 mt-1">Selecione um setor e clique em "Carregar benchmark" para ver a comparacao.</p>
          )}
        </div>

        {/* Gerar PDF button */}
        <button
          onClick={handleExecPdf}
          disabled={execGenerating}
          className="w-full flex justify-center items-center gap-2 py-3 px-6 rounded-lg font-semibold text-white bg-purple-700 hover:bg-purple-600 disabled:opacity-50 transition"
        >
          {execGenerating ? (
            <><Loader className="w-4 h-4 animate-spin" /> Gerando PDF Executivo...</>
          ) : (
            <><FileDown className="w-4 h-4" /> Gerar PDF Executivo</>
          )}
        </button>
      </div>

      {/* Guia */}
      <div className="card-dark p-6 bg-blue-900/10 border-l-4 border-blue-600">
        <div className="flex items-center gap-2 mb-3">
          <BookOpen className="w-5 h-5 text-blue-400" />
          <h2 className="text-lg font-bold text-gray-100">Qual relatório devo escolher?</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {[
            { label: 'Para gestores e diretores', rec: 'Resumo Executivo', reason: 'Sem jargão técnico, foco em impacto e prioridades' },
            { label: 'Para a equipe de TI e segurança', rec: 'Relatório Completo de Pentest', reason: 'Detalhado, com todas as evidências técnicas' },
            { label: 'Para desenvolvedores', rec: 'Achados Técnicos', reason: 'Detalha cada vulnerabilidade com provas de conceito' },
            { label: 'Para acompanhar correções', rec: 'Plano de Correção', reason: 'Planilha com cronograma e responsáveis' },
          ].map(({ label, rec, reason }) => (
            <div key={label} className="flex gap-3 p-3 rounded bg-dark-700 border border-dark-600 text-sm">
              <span className="text-blue-400 font-bold flex-shrink-0">→</span>
              <div>
                <span className="text-gray-400">{label}: </span>
                <span className="text-gray-100 font-semibold">{rec}</span>
                <p className="text-gray-500 text-xs mt-0.5">{reason}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Escolha do Modelo */}
      <div className="card-dark p-6">
        <h2 className="text-2xl font-bold text-gray-100 mb-2">Escolha o Tipo de Relatório</h2>
        <p className="text-gray-400 text-sm mb-5">Clique no modelo desejado para selecioná-lo.</p>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {TEMPLATES.map(tpl => (
            <button
              key={tpl.id}
              onClick={() => setFormData(f => ({ ...f, template: tpl.name, format: tpl.format }))}
              className={`text-left bg-dark-700 border-2 rounded-lg p-4 transition ${
                formData.template === tpl.name
                  ? 'border-blue-500 bg-blue-900/20'
                  : `${tpl.color} hover:bg-dark-600`
              }`}
            >
              <div className="flex items-start justify-between mb-3">
                <FileText className={`w-6 h-6 ${tpl.tag}`} />
                <span className="text-xs bg-dark-600 text-gray-300 px-2 py-1 rounded">{tpl.format}</span>
              </div>
              <h3 className="font-bold text-gray-100 text-sm mb-1">{tpl.label}</h3>
              <p className="text-xs text-gray-400 leading-relaxed mb-2">{tpl.desc}</p>
              <p className="text-xs text-gray-500">
                <span className="font-semibold">Para:</span> {tpl.audience}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* Gerar Relatório */}
      <div className="card-dark p-6">
        <h2 className="text-2xl font-bold text-gray-100 mb-5">Gerar Relatório</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Tipo Selecionado</label>
            <p className="text-xs text-gray-500 mb-2">Para mudar, clique em outro modelo acima</p>
            <div className="input-dark w-full bg-dark-700 flex items-center gap-2 cursor-default">
              <FileText className="w-4 h-4 text-gray-400" />
              <span className="text-gray-100">{selectedTemplate?.label || formData.template}</span>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Formato do Arquivo</label>
            <p className="text-xs text-gray-500 mb-2">{FORMAT_INFO[formData.format] || ''}</p>
            <select
              value={formData.format}
              onChange={(e) => setFormData(f => ({ ...f, format: e.target.value }))}
              className="select-dark w-full"
              disabled={generating}
            >
              <option value="PDF">PDF — para enviar e imprimir</option>
              <option value="DOCX">DOCX — editável no Word</option>
              <option value="HTML">HTML — visualizar no navegador</option>
              <option value="XLSX">XLSX — planilha Excel</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <label className="block text-sm font-medium text-gray-300 mb-1">Título do Relatório</label>
            <p className="text-xs text-gray-500 mb-2">Use um título descritivo que identifique o cliente e a data</p>
            <input
              type="text"
              value={formData.title}
              onChange={(e) => setFormData(f => ({ ...f, title: e.target.value }))}
              onKeyDown={(e) => e.key === 'Enter' && !generating && handleGenerateReport()}
              placeholder="ex: Relatório de Pentest — Empresa XYZ — Junho 2026"
              className="input-dark w-full"
              disabled={generating}
            />
          </div>

          <button
            onClick={handleGenerateReport}
            disabled={generating}
            className="md:col-span-2 btn-blue w-full flex justify-center items-center gap-2 disabled:opacity-50 py-3"
          >
            {generating ? (
              <><Loader className="w-4 h-4 animate-spin" /> Gerando relatório...</>
            ) : (
              <><Plus className="w-4 h-4" /> Gerar Relatório</>
            )}
          </button>
        </div>
      </div>

      {/* Relatórios de Compliance */}
      <div className="card-dark p-6">
        <div className="flex items-center gap-2 mb-2">
          <Shield className="w-5 h-5 text-green-400" />
          <h2 className="text-2xl font-bold text-gray-100">Relatórios de Compliance</h2>
        </div>
        <p className="text-gray-400 text-sm mb-5">
          Gera PDFs que mapeiam automaticamente as vulnerabilidades encontradas nas simulações para os controles dos frameworks de compliance.
        </p>

        {simulations.length > 0 && (
          <div className="mb-5">
            <label className="block text-sm font-medium text-gray-300 mb-2">Simulação de referência</label>
            <select
              value={selectedSimId}
              onChange={e => setSelectedSimId(e.target.value)}
              className="select-dark"
            >
              {simulations.map(s => (
                <option key={s.id} value={s.id}>
                  {s.target} — {new Date(s.date).toLocaleDateString('pt-BR')} — Score: {s.score?.toFixed(1)}%
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {COMPLIANCE_FRAMEWORKS.map(fw => (
            <div key={fw.id} className={`bg-dark-700 border-2 ${fw.color} rounded-lg p-5`}>
              <div className="flex items-start justify-between mb-3">
                <div>
                  <span className="text-2xl mr-2">{fw.flag}</span>
                  <span className={`font-black text-xl ${fw.tag}`}>{fw.name}</span>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded font-medium ${fw.badge}`}>PDF</span>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed mb-4">{fw.full}</p>
              <p className="text-xs text-gray-500 mb-4">{fw.desc}</p>
              <button
                onClick={() => handleComplianceReport(fw.id)}
                disabled={!!complianceGen || simulations.length === 0}
                className={`w-full flex justify-center items-center gap-2 py-2 px-4 rounded text-sm font-medium transition disabled:opacity-50 ${fw.badge} border ${fw.color} hover:opacity-80`}
              >
                {complianceGen === fw.id ? (
                  <><Loader className="w-4 h-4 animate-spin" /> Gerando...</>
                ) : (
                  <><CheckCircle className="w-4 h-4" /> Gerar {fw.name}</>
                )}
              </button>
              {simulations.length === 0 && (
                <p className="text-xs text-gray-600 mt-2 text-center">Execute uma simulação BAS primeiro</p>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Relatórios Gerados */}
      <div className="card-dark p-6">
        <h2 className="text-2xl font-bold text-gray-100 mb-5">Relatórios Gerados ({reports.length})</h2>
        {loading ? (
          <p className="text-gray-400">Carregando...</p>
        ) : reports.length === 0 ? (
          <div className="text-center py-10 border border-dashed border-dark-600 rounded-lg">
            <FileText className="w-8 h-8 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-500 text-sm">Nenhum relatório gerado ainda.</p>
            <p className="text-gray-600 text-xs mt-1">Preencha o formulário acima para gerar seu primeiro relatório.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-600">
                  <th className="text-left py-3 text-gray-400 font-semibold">Título</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Tipo</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Formato</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Data de Geração</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Ação</th>
                </tr>
              </thead>
              <tbody>
                {reports.map(report => {
                  const tpl = TEMPLATES.find(t => t.name === report.type)
                  return (
                    <tr key={report.id} className="border-b border-dark-700 hover:bg-dark-700 transition">
                      <td className="py-3 text-gray-100 font-medium">{report.title}</td>
                      <td className="py-3">
                        <span className="text-xs bg-dark-600 text-gray-300 px-2 py-1 rounded">{tpl?.label || report.type}</span>
                      </td>
                      <td className="py-3 text-gray-300">{report.format}</td>
                      <td className="py-3 text-gray-400">{report.created_at ? new Date(report.created_at).toLocaleDateString('pt-BR') : '-'}</td>
                      <td className="py-3">
                        <button onClick={() => handleDownload(report)} className="text-blue-400 hover:text-blue-300 transition flex items-center gap-1 text-xs">
                          <Download className="w-4 h-4" />
                          Baixar
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
