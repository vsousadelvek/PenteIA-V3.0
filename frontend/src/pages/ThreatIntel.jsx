import { useState, useEffect } from 'react'
import { Globe, Shield, Search, Link2, CheckCircle, Loader, Database, Radio } from 'lucide-react'
import api from '../api'
import { useToast } from '../components/Toast'

const TIP_TYPES = [
  { id: 'misp', label: 'MISP', desc: 'Malware Information Sharing Platform', color: 'text-blue-400', needsUrl: true, needsKey: true, keyLabel: 'API Key' },
  { id: 'opencti', label: 'OpenCTI', desc: 'Open Cyber Threat Intelligence Platform', color: 'text-purple-400', needsUrl: true, needsToken: true },
  { id: 'otx', label: 'OTX AlienVault', desc: 'Open Threat Exchange', color: 'text-orange-400', needsUrl: false, needsKey: true, keyLabel: 'API Key' },
]

export default function ThreatIntel() {
  const [activeTab, setActiveTab] = useState('misp')
  const [config, setConfig] = useState({ base_url: '', api_key: '', api_token: '', verify_ssl: true })
  const [saving, setSaving] = useState(false)
  const [currentConfig, setCurrentConfig] = useState(null)
  const [enrichTid, setEnrichTid] = useState('')
  const [enrichResult, setEnrichResult] = useState(null)
  const [enriching, setEnriching] = useState(false)
  const toast = useToast()

  useEffect(() => {
    api.get('/api/tip/config').then(r => setCurrentConfig(r.data)).catch(() => {})
  }, [])

  const handleSave = async () => {
    setSaving(true)
    try {
      await api.post('/api/tip/configure', { tip_type: activeTab, ...config })
      toast('TIP configurado com sucesso', 'success')
      const r = await api.get('/api/tip/config')
      setCurrentConfig(r.data)
    } catch (e) {
      toast(e.response?.data?.detail || 'Erro ao configurar TIP', 'error')
    } finally {
      setSaving(false)
    }
  }

  const handleEnrich = async () => {
    if (!enrichTid) { toast('Informe o ID da técnica (ex: T1059)', 'error'); return }
    setEnriching(true)
    setEnrichResult(null)
    try {
      const { data } = await api.post('/api/tip/enrich', { technique_id: enrichTid })
      setEnrichResult(data)
    } catch (e) {
      toast(e.response?.data?.detail || 'TIP não configurado. Configure primeiro.', 'error')
    } finally {
      setEnriching(false)
    }
  }

  const tip = TIP_TYPES.find(t => t.id === activeTab)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Radio size={24} className="text-red-500" />
          Threat Intelligence Platform
        </h1>
        <p className="text-gray-400 mt-1">Integre MISP, OpenCTI ou OTX para enriquecer cenários com inteligência de ameaças</p>
      </div>

      {currentConfig && Object.keys(currentConfig).length > 0 && (
        <div className="bg-green-900/20 border border-green-700/50 rounded-lg p-4 flex items-center gap-3">
          <CheckCircle size={18} className="text-green-400" />
          <div>
            <span className="text-green-300 font-medium">TIP Configurado: </span>
            <span className="text-green-200 text-sm">{currentConfig.type?.toUpperCase()}</span>
            {currentConfig.base_url && <span className="text-gray-400 text-xs ml-2">{currentConfig.base_url}</span>}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-dark-800 border border-dark-600 rounded-lg p-5">
          <h2 className="font-semibold text-white mb-4">Configurar TIP</h2>

          <div className="flex gap-2 mb-4">
            {TIP_TYPES.map(t => (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`flex-1 py-2 rounded-lg text-sm font-medium ${
                  activeTab === t.id ? 'bg-red-700 text-white' : 'bg-dark-700 text-gray-400 hover:text-white'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          {tip && (
            <div className="space-y-3">
              <p className="text-xs text-gray-400">{tip.desc}</p>
              {tip.needsUrl && (
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">URL Base</label>
                  <input
                    value={config.base_url}
                    onChange={e => setConfig(c => ({ ...c, base_url: e.target.value }))}
                    placeholder="https://misp.example.com"
                    className="w-full bg-dark-900 border border-dark-600 rounded px-3 py-2 text-sm text-white"
                  />
                </div>
              )}
              {tip.needsKey && (
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">{tip.keyLabel || 'API Key'}</label>
                  <input
                    type="password"
                    value={config.api_key}
                    onChange={e => setConfig(c => ({ ...c, api_key: e.target.value }))}
                    placeholder="••••••••••••••••"
                    className="w-full bg-dark-900 border border-dark-600 rounded px-3 py-2 text-sm text-white"
                  />
                </div>
              )}
              {tip.needsToken && (
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">API Token</label>
                  <input
                    type="password"
                    value={config.api_token}
                    onChange={e => setConfig(c => ({ ...c, api_token: e.target.value }))}
                    placeholder="••••••••••••••••"
                    className="w-full bg-dark-900 border border-dark-600 rounded px-3 py-2 text-sm text-white"
                  />
                </div>
              )}
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.verify_ssl}
                  onChange={e => setConfig(c => ({ ...c, verify_ssl: e.target.checked }))}
                  className="accent-red-500"
                />
                <span className="text-sm text-gray-300">Verificar SSL</span>
              </label>
              <button
                onClick={handleSave}
                disabled={saving}
                className="w-full flex items-center justify-center gap-2 bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white py-2 rounded-lg text-sm font-medium"
              >
                {saving ? <Loader size={16} className="animate-spin" /> : <Link2 size={16} />}
                {saving ? 'Conectando...' : 'Testar & Salvar'}
              </button>
            </div>
          )}
        </div>

        <div className="bg-dark-800 border border-dark-600 rounded-lg p-5">
          <h2 className="font-semibold text-white mb-4">Enriquecer Técnica MITRE</h2>
          <p className="text-xs text-gray-400 mb-3">Busca IoCs relacionados à técnica no TIP configurado</p>
          <div className="flex gap-2 mb-4">
            <input
              value={enrichTid}
              onChange={e => setEnrichTid(e.target.value)}
              placeholder="Ex: T1059, T1190, T1003"
              className="flex-1 bg-dark-900 border border-dark-600 rounded px-3 py-2 text-sm text-white"
            />
            <button
              onClick={handleEnrich}
              disabled={enriching}
              className="flex items-center gap-1.5 bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm"
            >
              {enriching ? <Loader size={14} className="animate-spin" /> : <Search size={14} />}
              Buscar
            </button>
          </div>
          {enrichResult && (
            <div className="bg-dark-900 border border-dark-600 rounded p-3 space-y-2">
              <div className="text-sm font-semibold text-white">{enrichResult.technique_id}</div>
              <div className="text-xs text-gray-400">Fonte: <span className="text-blue-400">{enrichResult.source}</span></div>
              {enrichResult.misp_matches !== undefined && (
                <div className="text-sm text-gray-300">{enrichResult.misp_matches} IoC(s) encontrado(s)</div>
              )}
              {(enrichResult.iocs || []).length > 0 && (
                <div className="space-y-1">
                  {enrichResult.iocs.slice(0, 5).map((ioc, i) => (
                    <div key={i} className="text-xs font-mono bg-dark-800 p-1 rounded text-gray-300">
                      <span className="text-gray-500">[{ioc.type}]</span> {ioc.value}
                    </div>
                  ))}
                </div>
              )}
              {enrichResult.message && <div className="text-sm text-gray-400">{enrichResult.message}</div>}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
