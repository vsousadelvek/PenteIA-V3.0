import { useState, useEffect } from 'react'
import { Globe, Shield, AlertTriangle, Search, Play, ChevronDown, ChevronUp, CheckCircle, XCircle, Loader, Code2 } from 'lucide-react'
import api from '../api'
import { useToast } from '../components/Toast'

const SEVERITY_BADGE = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-600 text-white',
  medium: 'bg-yellow-600 text-black',
  low: 'bg-blue-600 text-white',
}

function VulnCard({ vuln }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="bg-dark-800 border border-dark-600 rounded-lg p-4">
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-sm font-mono font-bold text-red-400">{vuln.id}</span>
            <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded ${SEVERITY_BADGE[vuln.severity]}`}>{vuln.severity}</span>
            <span className="text-xs bg-dark-700 px-2 py-0.5 rounded text-gray-400">CVSS {vuln.cvss}</span>
          </div>
          <h3 className="font-semibold text-white">{vuln.name}</h3>
          <p className="text-sm text-gray-400 mt-1">{vuln.description}</p>
          {vuln.example && (
            <div className="mt-2 bg-dark-900 border border-dark-600 rounded px-3 py-2">
              <span className="text-xs text-yellow-400 font-semibold">Exemplo: </span>
              <span className="text-xs text-gray-300 font-mono">{vuln.example}</span>
            </div>
          )}
        </div>
        <button onClick={() => setExpanded(e => !e)} className="text-gray-400 hover:text-white">
          {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
        </button>
      </div>

      {expanded && (
        <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase mb-1">Payloads de Teste</h4>
            <ul className="text-xs text-gray-300 list-disc list-inside space-y-1">
              {(vuln.test_payloads || []).map((p, i) => <li key={i}>{p}</li>)}
            </ul>
          </div>
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase mb-1">Detecção</h4>
            <ul className="text-xs text-gray-300 list-disc list-inside space-y-1">
              {(vuln.detection_rules || []).map((r, i) => <li key={i}>{r}</li>)}
            </ul>
          </div>
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase mb-1">Mitigações</h4>
            <ul className="text-xs text-gray-300 list-disc list-inside space-y-1">
              {(vuln.mitigations || []).map((m, i) => <li key={i}>{m}</li>)}
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}

export default function APISecurity() {
  const [vulns, setVulns] = useState([])
  const [loading, setLoading] = useState(true)
  const [scanForm, setScanForm] = useState({ base_url: '', endpoint: '/', method: 'GET', test_bola: true, test_auth: true, test_ssrf: true })
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState(null)
  const [activeTab, setActiveTab] = useState('list')
  const toast = useToast()

  useEffect(() => {
    api.get('/api/api-security/owasp-top10')
      .then(r => setVulns(r.data.vulnerabilities || []))
      .catch(() => setVulns([]))
      .finally(() => setLoading(false))
  }, [])

  const handleScan = async () => {
    if (!scanForm.base_url) { toast('Informe a URL base', 'error'); return }
    setScanning(true)
    setScanResult(null)
    try {
      const { data } = await api.post('/api/api-security/scan', scanForm)
      setScanResult(data)
      toast(`Scan concluído: ${data.findings_count} achados (${data.risk_level})`, data.findings_count > 0 ? 'error' : 'success')
    } catch (e) {
      toast(e.response?.data?.detail || 'Erro no scan', 'error')
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Globe size={24} className="text-red-500" />
          API Security — OWASP Top 10 (2023)
        </h1>
        <p className="text-gray-400 mt-1">Teste e simulação das 10 vulnerabilidades mais críticas em APIs REST/GraphQL</p>
      </div>

      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total OWASP', value: vulns.length, color: 'text-gray-300' },
          { label: 'Crítico', value: vulns.filter(v => v.severity === 'critical').length, color: 'text-red-400' },
          { label: 'Alto', value: vulns.filter(v => v.severity === 'high').length, color: 'text-orange-400' },
          { label: 'CVSS Máx', value: vulns.length ? Math.max(...vulns.map(v => v.cvss || 0)).toFixed(1) : '—', color: 'text-yellow-400' },
        ].map(s => (
          <div key={s.label} className="bg-dark-800 border border-dark-600 rounded-lg p-3 text-center">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-gray-500 mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="flex gap-2">
        {[
          { id: 'list', label: 'OWASP API Top 10', icon: <Shield size={14} /> },
          { id: 'scan', label: 'Live Scanner', icon: <Search size={14} /> },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium ${
              activeTab === tab.id ? 'bg-red-700 text-white' : 'bg-dark-800 text-gray-400 hover:text-white'
            }`}
          >
            {tab.icon}{tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'list' && (
        <div className="space-y-3">
          {loading ? (
            <div className="flex justify-center py-12"><Loader size={32} className="animate-spin text-red-500" /></div>
          ) : (
            vulns.map(v => <VulnCard key={v.id} vuln={v} />)
          )}
        </div>
      )}

      {activeTab === 'scan' && (
        <div className="space-y-4">
          <div className="bg-dark-800 border border-dark-600 rounded-lg p-5">
            <h2 className="font-semibold text-white mb-4 flex items-center gap-2"><Search size={18} className="text-red-400" />Scanner de API</h2>
            <div className="grid grid-cols-2 gap-3 mb-3">
              <div>
                <label className="text-xs text-gray-400 mb-1 block">URL Base</label>
                <input
                  value={scanForm.base_url}
                  onChange={e => setScanForm(f => ({ ...f, base_url: e.target.value }))}
                  placeholder="https://api.target.com"
                  className="w-full bg-dark-900 border border-dark-600 rounded px-3 py-2 text-sm text-white"
                />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Endpoint</label>
                <input
                  value={scanForm.endpoint}
                  onChange={e => setScanForm(f => ({ ...f, endpoint: e.target.value }))}
                  placeholder="/api/users/123"
                  className="w-full bg-dark-900 border border-dark-600 rounded px-3 py-2 text-sm text-white"
                />
              </div>
            </div>
            <div className="flex gap-4 mb-4">
              {[
                { key: 'test_bola', label: 'BOLA/IDOR (API1)' },
                { key: 'test_auth', label: 'Auth JWT (API2)' },
                { key: 'test_ssrf', label: 'SSRF (API7)' },
              ].map(c => (
                <label key={c.key} className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={scanForm[c.key]} onChange={e => setScanForm(f => ({ ...f, [c.key]: e.target.checked }))} className="accent-red-500" />
                  <span className="text-sm text-gray-300">{c.label}</span>
                </label>
              ))}
            </div>
            <button
              onClick={handleScan}
              disabled={scanning}
              className="flex items-center gap-2 bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white px-5 py-2 rounded-lg text-sm font-medium"
            >
              {scanning ? <Loader size={16} className="animate-spin" /> : <Play size={16} />}
              {scanning ? 'Scanning...' : 'Iniciar Scan'}
            </button>
          </div>

          {scanResult && (
            <div className="bg-dark-800 border border-dark-600 rounded-lg p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-semibold text-white">Resultado do Scan</h3>
                <span className={`text-sm font-bold px-3 py-1 rounded ${SEVERITY_BADGE[scanResult.risk_level] || 'bg-gray-700 text-gray-300'}`}>
                  {scanResult.risk_level?.toUpperCase()}
                </span>
              </div>
              {scanResult.findings?.length === 0 ? (
                <div className="flex items-center gap-2 text-green-400"><CheckCircle size={18} /><span>Nenhuma vulnerabilidade encontrada</span></div>
              ) : (
                <div className="space-y-3">
                  {scanResult.findings.map((f, i) => (
                    <div key={i} className="border border-red-900/50 bg-red-900/20 rounded p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <XCircle size={14} className="text-red-400" />
                        <span className="text-sm font-semibold text-red-300">{f.vuln_id}</span>
                        <span className={`text-xs px-2 py-0.5 rounded ${SEVERITY_BADGE[f.severity]}`}>{f.severity}</span>
                      </div>
                      <div className="text-sm text-gray-300">{f.detail}</div>
                      <div className="text-xs text-gray-500 mt-1 font-mono">{f.evidence}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
