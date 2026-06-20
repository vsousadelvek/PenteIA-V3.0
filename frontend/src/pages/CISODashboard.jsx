import { useState, useEffect } from 'react'
import { BarChart2, Share2, Eye, Clock, TrendingUp, TrendingDown, Copy, Trash2, Plus, Shield, Loader, CheckCircle } from 'lucide-react'
import api from '../api'
import { useToast } from '../components/Toast'

function RiskScore({ score }) {
  const color = score >= 70 ? 'text-red-400' : score >= 40 ? 'text-orange-400' : 'text-green-400'
  const ring = score >= 70 ? 'border-red-500' : score >= 40 ? 'border-orange-500' : 'border-green-500'
  return (
    <div className={`w-28 h-28 rounded-full border-4 ${ring} flex items-center justify-center`}>
      <div className="text-center">
        <div className={`text-3xl font-bold ${color}`}>{Math.round(score)}</div>
        <div className="text-xs text-gray-500">risco</div>
      </div>
    </div>
  )
}

export default function CISODashboard() {
  const [tokens, setTokens] = useState([])
  const [form, setForm] = useState({ org_name: '', expires_days: 30, label: '' })
  const [creating, setCreating] = useState(false)
  const [preview, setPreview] = useState(null)
  const [loadingPreview, setLoadingPreview] = useState(false)
  const [activeTab, setActiveTab] = useState('tokens')
  const [newToken, setNewToken] = useState(null)
  const toast = useToast()

  const loadTokens = () => {
    api.get('/api/ciso-dashboard/tokens')
      .then(r => setTokens(r.data.tokens || []))
      .catch(() => {})
  }

  useEffect(() => { loadTokens() }, [])

  const handleCreate = async () => {
    if (!form.org_name) { toast('Informe o nome da organização', 'error'); return }
    setCreating(true)
    try {
      const { data } = await api.post('/api/ciso-dashboard/tokens', form)
      setNewToken(data)
      toast('Token CISO criado com sucesso!', 'success')
      loadTokens()
    } catch (e) {
      toast(e.response?.data?.detail || 'Erro ao criar token', 'error')
    } finally {
      setCreating(false)
    }
  }

  const handleRevoke = async (prefix) => {
    try {
      await api.delete('/api/ciso-dashboard/tokens', { data: { token_hash_prefix: prefix } })
      toast('Token revogado', 'success')
      loadTokens()
    } catch {
      toast('Erro ao revogar', 'error')
    }
  }

  const handlePreview = async (token) => {
    setLoadingPreview(true)
    try {
      const { data } = await api.get(`/api/ciso-dashboard/view/${token}`)
      setPreview(data)
      setActiveTab('preview')
    } catch {
      toast('Erro ao carregar dashboard', 'error')
    } finally {
      setLoadingPreview(false)
    }
  }

  const shareUrl = (token) => `${window.location.origin}/api/ciso-dashboard/view/${token}`

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <BarChart2 size={24} className="text-red-500" />
          CISO Live Dashboard
        </h1>
        <p className="text-gray-400 mt-1">Dashboards compartilháveis para a diretoria — sem acesso à plataforma completa</p>
      </div>

      <div className="flex gap-2">
        {[
          { id: 'tokens', label: 'Links Compartilháveis', icon: <Share2 size={14} /> },
          { id: 'create', label: 'Novo Link', icon: <Plus size={14} /> },
          { id: 'preview', label: 'Preview', icon: <Eye size={14} /> },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium ${
              activeTab === t.id ? 'bg-red-700 text-white' : 'bg-dark-800 text-gray-400 hover:text-white'
            }`}
          >
            {t.icon}{t.label}
          </button>
        ))}
      </div>

      {activeTab === 'tokens' && (
        <div className="space-y-3">
          {tokens.length === 0 ? (
            <div className="text-center py-12 text-gray-500">
              <Share2 size={32} className="mx-auto mb-3 opacity-40" />
              <div>Nenhum link criado. Crie um para compartilhar com a diretoria.</div>
            </div>
          ) : (
            tokens.map(tk => (
              <div key={tk.token_hash} className="bg-dark-800 border border-dark-600 rounded-lg p-4">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="font-medium text-white">{tk.label}</div>
                    <div className="text-xs text-gray-400 mt-0.5">
                      <span className="mr-3"><Eye size={10} className="inline mr-1" />{tk.views} visualizações</span>
                      <span className="mr-3"><Clock size={10} className="inline mr-1" />Expira: {tk.expires_at?.slice(0, 10)}</span>
                      {!tk.active && <span className="text-red-400">REVOGADO</span>}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => { navigator.clipboard.writeText(shareUrl(tk.token_hash)); toast('Link copiado!', 'success') }}
                      className="text-xs flex items-center gap-1 bg-dark-700 hover:bg-dark-600 px-2 py-1 rounded text-gray-300"
                    >
                      <Copy size={12} />Copiar Link
                    </button>
                    {tk.active && (
                      <button
                        onClick={() => handleRevoke(tk.token_preview?.replace('...', ''))}
                        className="text-xs flex items-center gap-1 bg-red-900/40 hover:bg-red-900/60 px-2 py-1 rounded text-red-300"
                      >
                        <Trash2 size={12} />Revogar
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {activeTab === 'create' && (
        <div className="max-w-lg bg-dark-800 border border-dark-600 rounded-lg p-6 space-y-4">
          <h2 className="font-semibold text-white">Criar Link Compartilhável</h2>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Nome da Organização</label>
            <input
              value={form.org_name}
              onChange={e => setForm(f => ({ ...f, org_name: e.target.value }))}
              placeholder="Empresa XYZ"
              className="w-full bg-dark-900 border border-dark-600 rounded px-3 py-2 text-sm text-white"
            />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Rótulo (opcional)</label>
            <input
              value={form.label}
              onChange={e => setForm(f => ({ ...f, label: e.target.value }))}
              placeholder="Ex: Dashboard Q2 2025"
              className="w-full bg-dark-900 border border-dark-600 rounded px-3 py-2 text-sm text-white"
            />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Validade (dias)</label>
            <select
              value={form.expires_days}
              onChange={e => setForm(f => ({ ...f, expires_days: Number(e.target.value) }))}
              className="w-full bg-dark-900 border border-dark-600 rounded px-3 py-2 text-sm text-white"
            >
              <option value={7}>7 dias</option>
              <option value={30}>30 dias</option>
              <option value={90}>90 dias</option>
              <option value={365}>1 ano</option>
            </select>
          </div>
          <button
            onClick={handleCreate}
            disabled={creating}
            className="w-full flex items-center justify-center gap-2 bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white py-2 rounded-lg text-sm font-medium"
          >
            {creating ? <Loader size={16} className="animate-spin" /> : <Plus size={16} />}
            Gerar Link
          </button>

          {newToken && (
            <div className="bg-green-900/20 border border-green-700 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle size={16} className="text-green-400" />
                <span className="text-sm font-semibold text-green-300">Link Criado!</span>
              </div>
              <div className="text-xs font-mono bg-dark-900 rounded p-2 text-gray-300 break-all">
                {shareUrl(newToken.token)}
              </div>
              <button
                onClick={() => { navigator.clipboard.writeText(shareUrl(newToken.token)); toast('Copiado!', 'success') }}
                className="mt-2 text-xs flex items-center gap-1 text-green-400 hover:text-green-300"
              >
                <Copy size={12} />Copiar link
              </button>
              <p className="text-xs text-gray-400 mt-2">Compartilhe este link com a diretoria. Válido por {form.expires_days} dias.</p>
            </div>
          )}
        </div>
      )}

      {activeTab === 'preview' && (
        loadingPreview ? (
          <div className="flex justify-center py-12"><Loader size={32} className="animate-spin text-red-500" /></div>
        ) : preview ? (
          <div className="space-y-6">
            <div className="bg-dark-800 border border-dark-600 rounded-lg p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-xl font-bold text-white">{preview.org_name}</h2>
                  <p className="text-xs text-gray-500 mt-0.5">Atualizado: {preview.generated_at?.slice(0, 19).replace('T', ' ')}</p>
                </div>
                <div className="flex items-center gap-3">
                  {preview.trend === 'improving' && <TrendingUp className="text-green-400" />}
                  {preview.trend === 'worsening' && <TrendingDown className="text-red-400" />}
                  <RiskScore score={preview.risk_score || 0} />
                </div>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center"><div className="text-2xl font-bold text-white">{preview.total_simulations}</div><div className="text-xs text-gray-500">Simulações</div></div>
                <div className="text-center"><div className="text-2xl font-bold text-red-400">{preview.critical_findings}</div><div className="text-xs text-gray-500">Críticos</div></div>
                <div className="text-center">
                  <div className={`text-2xl font-bold ${preview.trend === 'improving' ? 'text-green-400' : preview.trend === 'worsening' ? 'text-red-400' : 'text-gray-300'}`}>
                    {preview.trend === 'improving' ? '↓' : preview.trend === 'worsening' ? '↑' : '→'}
                  </div>
                  <div className="text-xs text-gray-500">Tendência</div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center py-12 text-gray-500">
            <BarChart2 size={32} className="mx-auto mb-3 opacity-40" />
            <div>Selecione um token na aba "Links" para visualizar o dashboard</div>
          </div>
        )
      )}
    </div>
  )
}
