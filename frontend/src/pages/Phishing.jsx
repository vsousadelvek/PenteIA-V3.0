import React, { useState, useEffect, useCallback } from 'react'
import { Mail, Plus, Play, Trash2, Users, Eye, MousePointer, Key, RefreshCw, X, ChevronDown, ChevronRight, Send, Target } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

const STATUS_BADGE = {
  draft:     'bg-gray-700 text-gray-300 border-gray-600',
  active:    'bg-blue-900/40 text-blue-300 border-blue-700',
  completed: 'bg-green-900/40 text-green-300 border-green-700',
}

const TEMPLATES = [
  { id: 'it-reset',   subject: '[ACTION REQUIRED] Reset de senha obrigatório',
    body: 'Caro colaborador,\n\nSua senha expira em 24 horas. Clique no link abaixo para renová-la:\n\n{TRACKING_LINK}\n\nIT Security Team',
    sender_name: 'IT Security', sender_email: 'it-security@{COMPANY}.com' },
  { id: 'hr-doc',    subject: 'Documento de RH pendente para assinatura',
    body: 'Prezado(a),\n\nHá um documento importante aguardando sua assinatura:\n\n{TRACKING_LINK}\n\nAtenciosamente,\nRH',
    sender_name: 'Recursos Humanos', sender_email: 'rh@{COMPANY}.com' },
  { id: 'invoice',   subject: 'Fatura #INV-2024 aprovada para pagamento',
    body: 'Prezado(a),\n\nA fatura abaixo foi aprovada. Acesse para detalhes:\n\n{TRACKING_LINK}\n\nFinanceiro',
    sender_name: 'Financeiro', sender_email: 'financeiro@{COMPANY}.com' },
  { id: 'vpn-alert', subject: 'Alerta: Acesso VPN de localização incomum',
    body: 'Detectamos um acesso VPN de uma localização incomum.\nSe não foi você, acesse imediatamente:\n\n{TRACKING_LINK}\n\nSecurity Operations',
    sender_name: 'Security Operations', sender_email: 'soc@{COMPANY}.com' },
]

function RateBar({ value, color }) {
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-dark-700 rounded-full h-1.5">
        <div className={`${color} h-1.5 rounded-full transition-all`} style={{ width: `${Math.min(value, 100)}%` }} />
      </div>
      <span className="text-xs font-mono w-10 text-right">{value.toFixed(1)}%</span>
    </div>
  )
}

function CampaignModal({ onClose, onSaved }) {
  const toast = useToast()
  const [step, setStep] = useState('template')
  const [template, setTemplate] = useState(null)
  const [form, setForm] = useState({ name: '', subject: '', sender_name: '', sender_email: '', body_template: '', landing_url: '' })
  const [targetText, setTargetText] = useState('')
  const [saving, setSaving] = useState(false)
  const [campaignId, setCampaignId] = useState(null)

  const applyTemplate = (t) => {
    setTemplate(t)
    setForm(f => ({ ...f, subject: t.subject, sender_name: t.sender_name, sender_email: t.sender_email, body_template: t.body }))
    setStep('config')
  }

  const createCampaign = async () => {
    if (!form.name.trim() || !form.subject.trim()) { toast('Nome e assunto são obrigatórios', 'warning'); return }
    setSaving(true)
    try {
      const r = await api.post('/api/phishing/campaigns', form)
      setCampaignId(r.data.id)
      setStep('targets')
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao criar campanha', 'error') }
    finally { setSaving(false) }
  }

  const addTargets = async () => {
    const lines = targetText.trim().split('\n').filter(l => l.includes('@'))
    if (lines.length === 0) { toast('Adicione ao menos um e-mail', 'warning'); return }
    const targets = lines.map(l => {
      const parts = l.split(',')
      return { email: parts[0].trim(), name: parts[1]?.trim() || '', department: parts[2]?.trim() || '' }
    })
    setSaving(true)
    try {
      await api.post(`/api/phishing/campaigns/${campaignId}/targets`, { targets })
      await api.post(`/api/phishing/campaigns/${campaignId}/launch`)
      toast(`Campanha lançada com ${targets.length} alvos`, 'success')
      onSaved()
      onClose()
    } catch (e) { toast(e.response?.data?.detail || 'Erro', 'error') }
    finally { setSaving(false) }
  }

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-dark-800 border border-dark-600 rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-5 border-b border-dark-600">
          <h2 className="text-lg font-bold text-gray-100">Nova Campanha de Phishing</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-100"><X className="w-5 h-5" /></button>
        </div>

        <div className="p-5 space-y-5">
          {step === 'template' && (
            <>
              <p className="text-sm text-gray-400">Escolha um template ou crie do zero:</p>
              <div className="grid grid-cols-1 gap-3">
                {TEMPLATES.map(t => (
                  <button key={t.id} onClick={() => applyTemplate(t)}
                    className="text-left p-4 rounded-lg border border-dark-600 bg-dark-700 hover:border-red-700 hover:bg-red-950/10 transition">
                    <p className="font-medium text-gray-200 text-sm">{t.subject}</p>
                    <p className="text-xs text-gray-500 mt-1">De: {t.sender_name} &lt;{t.sender_email}&gt;</p>
                  </button>
                ))}
                <button onClick={() => setStep('config')} className="text-left p-4 rounded-lg border border-dashed border-dark-600 text-gray-500 hover:text-gray-300 text-sm transition">
                  + Criar do zero
                </button>
              </div>
            </>
          )}

          {step === 'config' && (
            <>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Nome da campanha</label>
                <input className="input-dark w-full" placeholder="Ex: Teste de phishing Q1 2026" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">Nome do remetente</label>
                  <input className="input-dark w-full" value={form.sender_name} onChange={e => setForm(f => ({ ...f, sender_name: e.target.value }))} />
                </div>
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">E-mail do remetente</label>
                  <input className="input-dark w-full" value={form.sender_email} onChange={e => setForm(f => ({ ...f, sender_email: e.target.value }))} />
                </div>
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Assunto</label>
                <input className="input-dark w-full" value={form.subject} onChange={e => setForm(f => ({ ...f, subject: e.target.value }))} />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Corpo do e-mail</label>
                <textarea className="input-dark w-full h-28 resize-none text-xs font-mono" value={form.body_template} onChange={e => setForm(f => ({ ...f, body_template: e.target.value }))} />
                <p className="text-[10px] text-gray-600 mt-1">Use {'{TRACKING_LINK}'} para inserir o link rastreado</p>
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Landing URL (após clique)</label>
                <input className="input-dark w-full font-mono text-sm" placeholder="https://..." value={form.landing_url} onChange={e => setForm(f => ({ ...f, landing_url: e.target.value }))} />
              </div>
              <div className="flex gap-2 justify-end">
                <button onClick={() => setStep('template')} className="px-4 py-2 bg-dark-700 text-gray-300 rounded text-sm">Voltar</button>
                <button onClick={createCampaign} disabled={saving} className="px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded text-sm">
                  {saving ? 'Salvando...' : 'Próximo: Alvos →'}
                </button>
              </div>
            </>
          )}

          {step === 'targets' && (
            <>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Alvos (um por linha: email, nome, departamento)</label>
                <textarea
                  className="input-dark w-full h-40 resize-none text-xs font-mono"
                  placeholder="joao.silva@empresa.com, João Silva, TI&#10;maria.souza@empresa.com, Maria Souza, Financeiro&#10;pedro@empresa.com"
                  value={targetText}
                  onChange={e => setTargetText(e.target.value)}
                />
                <p className="text-[10px] text-gray-600 mt-1">
                  {targetText.split('\n').filter(l => l.includes('@')).length} alvos detectados
                </p>
              </div>
              <div className="flex gap-2 justify-end">
                <button onClick={onClose} className="px-4 py-2 bg-dark-700 text-gray-300 rounded text-sm">Cancelar</button>
                <button onClick={addTargets} disabled={saving} className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded text-sm">
                  <Send className="w-4 h-4" />
                  {saving ? 'Lançando...' : 'Lançar campanha'}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function CampaignDetail({ campaign, onClose }) {
  const [detail, setDetail] = useState(null)

  useEffect(() => {
    if (!campaign) return
    api.get(`/api/phishing/campaigns/${campaign.id}`).then(r => setDetail(r.data)).catch(() => {})
  }, [campaign])

  if (!detail) return null

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-dark-800 border border-dark-600 rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-5 border-b border-dark-600">
          <div>
            <h2 className="text-lg font-bold text-gray-100">{detail.name}</h2>
            <p className="text-xs text-gray-500">{detail.subject}</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-100"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-5">
          <div className="grid grid-cols-3 gap-4">
            <div className="card-dark p-4 text-center">
              <Eye className="w-5 h-5 text-blue-400 mx-auto mb-1" />
              <p className="text-2xl font-bold text-blue-400">{detail.open_rate}%</p>
              <p className="text-xs text-gray-500">{detail.opened}/{detail.total_targets} abertos</p>
            </div>
            <div className="card-dark p-4 text-center">
              <MousePointer className="w-5 h-5 text-orange-400 mx-auto mb-1" />
              <p className="text-2xl font-bold text-orange-400">{detail.click_rate}%</p>
              <p className="text-xs text-gray-500">{detail.clicked}/{detail.total_targets} clicaram</p>
            </div>
            <div className="card-dark p-4 text-center">
              <Key className="w-5 h-5 text-red-400 mx-auto mb-1" />
              <p className="text-2xl font-bold text-red-400">{detail.cred_rate}%</p>
              <p className="text-xs text-gray-500">{detail.credentials_harvested}/{detail.total_targets} credenciais</p>
            </div>
          </div>

          <div className="card-dark overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-600 text-gray-500 text-xs">
                  <th className="px-4 py-2 text-left">E-mail</th>
                  <th className="px-4 py-2 text-left">Nome</th>
                  <th className="px-4 py-2 text-left">Dept</th>
                  <th className="px-4 py-2 text-center">Abriu</th>
                  <th className="px-4 py-2 text-center">Clicou</th>
                  <th className="px-4 py-2 text-center">Credencial</th>
                </tr>
              </thead>
              <tbody>
                {detail.targets.map(t => (
                  <tr key={t.id} className="border-b border-dark-700/50 hover:bg-dark-700/30">
                    <td className="px-4 py-2 font-mono text-xs text-gray-300">{t.email}</td>
                    <td className="px-4 py-2 text-gray-400 text-xs">{t.name || '—'}</td>
                    <td className="px-4 py-2 text-gray-500 text-xs">{t.department || '—'}</td>
                    <td className="px-4 py-2 text-center">
                      <span className={t.opened ? 'text-blue-400' : 'text-gray-700'}>
                        {t.opened ? '✓' : '—'}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-center">
                      <span className={t.clicked ? 'text-orange-400' : 'text-gray-700'}>
                        {t.clicked ? '✓' : '—'}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-center">
                      <span className={t.credential_harvested ? 'text-red-400 font-bold' : 'text-gray-700'}>
                        {t.credential_harvested ? '✓' : '—'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function Phishing() {
  const toast = useToast()
  const [campaigns, setCampaigns] = useState([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [selected, setSelected] = useState(null)

  const load = useCallback(() => {
    setLoading(true)
    api.get('/api/phishing/campaigns').then(r => setCampaigns(r.data.campaigns || [])).catch(() => {}).finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const del = async (id) => {
    if (!window.confirm('Excluir esta campanha?')) return
    await api.delete(`/api/phishing/campaigns/${id}`)
    toast('Campanha excluída', 'info')
    load()
  }

  const totals = campaigns.reduce((acc, c) => ({
    campaigns: acc.campaigns + 1,
    targets: acc.targets + c.total_targets,
    opened: acc.opened + c.opened,
    clicked: acc.clicked + c.clicked,
    harvested: acc.harvested + c.credentials_harvested,
  }), { campaigns: 0, targets: 0, opened: 0, clicked: 0, harvested: 0 })

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <Mail className="w-6 h-6 text-red-500" />
            Phishing / Human Simulation
          </h1>
          <p className="text-sm text-gray-400 mt-1">Simule ataques de phishing para medir a resiliência humana da organização</p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="p-2 text-gray-400 hover:text-gray-200 hover:bg-dark-700 rounded transition">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button onClick={() => setShowModal(true)} className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm transition">
            <Plus className="w-4 h-4" /> Nova Campanha
          </button>
        </div>
      </div>

      <div className="card-dark p-4 border-l-4 border-orange-600 bg-orange-900/10">
        <p className="text-sm text-orange-300">
          <strong>Uso autorizado apenas.</strong> Esta funcionalidade simula ataques de phishing para fins educacionais e de conscientização.
          Use exclusivamente em ambientes autorizados com consentimento documentado dos responsáveis.
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Campanhas', value: totals.campaigns, color: 'text-gray-100' },
          { label: 'Alvos', value: totals.targets, color: 'text-blue-400', Icon: Users },
          { label: 'Abriram', value: totals.opened, color: 'text-blue-400', Icon: Eye },
          { label: 'Clicaram', value: totals.clicked, color: 'text-orange-400', Icon: MousePointer },
          { label: 'Credenciais', value: totals.harvested, color: 'text-red-400', Icon: Key },
        ].map(s => (
          <div key={s.label} className="card-dark p-3 text-center">
            {s.Icon && <s.Icon className={`w-4 h-4 mx-auto mb-1 ${s.color}`} />}
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            <p className="text-xs text-gray-500">{s.label}</p>
          </div>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-16">
          <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : campaigns.length === 0 ? (
        <div className="card-dark p-12 text-center">
          <Mail className="w-10 h-10 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">Nenhuma campanha ainda</p>
          <button onClick={() => setShowModal(true)} className="mt-4 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded text-sm">
            Criar primeira campanha
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {campaigns.map(c => (
            <div key={c.id} className="card-dark p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 flex-wrap mb-2">
                    <h3 className="font-bold text-gray-100">{c.name}</h3>
                    <span className={`text-xs px-2 py-0.5 rounded border ${STATUS_BADGE[c.status] || STATUS_BADGE.draft}`}>
                      {c.status}
                    </span>
                    <span className="text-xs text-gray-500">{c.total_targets} alvos</span>
                  </div>
                  <p className="text-xs text-gray-500 mb-3">{c.subject}</p>
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    <div>
                      <div className="flex items-center gap-1 text-blue-400 mb-1"><Eye className="w-3 h-3" /> Abertura</div>
                      <RateBar value={c.open_rate} color="bg-blue-500" />
                    </div>
                    <div>
                      <div className="flex items-center gap-1 text-orange-400 mb-1"><MousePointer className="w-3 h-3" /> Clique</div>
                      <RateBar value={c.click_rate} color="bg-orange-500" />
                    </div>
                    <div>
                      <div className="flex items-center gap-1 text-red-400 mb-1"><Key className="w-3 h-3" /> Credencial</div>
                      <RateBar value={c.cred_rate} color="bg-red-500" />
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <button onClick={() => setSelected(c)} className="p-2 text-gray-500 hover:text-blue-400 hover:bg-dark-700 rounded transition" title="Ver detalhes">
                    <Eye className="w-4 h-4" />
                  </button>
                  <button onClick={() => del(c.id)} className="p-2 text-gray-500 hover:text-red-400 hover:bg-dark-700 rounded transition" title="Excluir">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {showModal && <CampaignModal onClose={() => setShowModal(false)} onSaved={load} />}
      {selected && <CampaignDetail campaign={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
