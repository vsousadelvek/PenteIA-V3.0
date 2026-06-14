import React, { useState, useEffect } from 'react'
import { Download, FileText, Plus, Loader, BookOpen, Info } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

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
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [formData, setFormData] = useState({
    template: 'Penetration Test Report',
    format: 'PDF',
    title: '',
  })

  const selectedTemplate = TEMPLATES.find(t => t.name === formData.template)

  useEffect(() => {
    fetchReports()
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

  const handleDownload = async (reportId) => {
    try {
      const res = await api.get(`/api/reporting/reports/${reportId}/download`, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `report-${reportId}.pdf`)
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
                        <button onClick={() => handleDownload(report.id)} className="text-blue-400 hover:text-blue-300 transition flex items-center gap-1 text-xs">
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
