import React, { useState } from 'react'
import { Cloud, Shield, Key, AlertTriangle, ChevronDown, ChevronRight, Play, Loader } from 'lucide-react'
import api from '../api'

const SEV = {
  Critical: 'bg-red-900/50 text-red-400 border border-red-700',
  High:     'bg-orange-900/50 text-orange-400 border border-orange-700',
  Medium:   'bg-yellow-900/50 text-yellow-400 border border-yellow-700',
  Low:      'bg-green-900/40 text-green-400 border border-green-700',
}

function PathCard({ path }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="card-dark overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-dark-700/50 transition text-left"
      >
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <span className={`text-xs px-2 py-0.5 rounded font-bold shrink-0 ${SEV[path.severity] || SEV.Medium}`}>
            {path.severity?.toUpperCase() || 'MEDIUM'}
          </span>
          <span className="font-semibold text-gray-200 truncate">{path.name}</span>
        </div>
        <div className="flex items-center gap-3 ml-4 shrink-0">
          <span className="text-xs text-gray-500 font-mono">{path.technique}</span>
          {open ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
        </div>
      </button>
      {open && (
        <div className="px-5 pb-5 space-y-4 border-t border-dark-600">
          <p className="text-gray-400 text-sm mt-3">{path.description}</p>

          {path.steps?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Caminho de Ataque</p>
              <ol className="space-y-1.5">
                {path.steps.map((step, i) => (
                  <li key={i} className="flex gap-3 text-sm">
                    <span className="w-5 h-5 rounded-full bg-red-900/60 text-red-400 text-xs flex items-center justify-center shrink-0 mt-0.5 font-bold">{i + 1}</span>
                    <span className="text-gray-300">{step}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {path.remediation?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-green-600 uppercase tracking-wide mb-2">Remediação</p>
              <ul className="space-y-1">
                {path.remediation.map((r, i) => (
                  <li key={i} className="flex gap-2 text-sm text-gray-300">
                    <span className="text-green-500 shrink-0">✓</span> {r}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {path.cvss && (
            <div className="flex gap-4 text-xs text-gray-500">
              <span>CVSS: <strong className="text-gray-300">{path.cvss}</strong></span>
              <span>MITRE: <strong className="text-gray-300 font-mono">{path.technique}</strong></span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function ProviderPanel({ title, icon: Icon, color, fields, endpoint, placeholder }) {
  const [form, setForm] = useState({})
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const run = async () => {
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const res = await api.post(endpoint, form)
      setResult(res.data)
    } catch (e) {
      setError(e.response?.data?.detail || 'Erro ao executar análise')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card-dark p-6 space-y-5">
      <div className="flex items-center gap-3">
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${color}`}>
          <Icon className="w-5 h-5 text-white" />
        </div>
        <div>
          <h2 className="font-bold text-gray-100">{title}</h2>
          <p className="text-xs text-gray-500">Análise de caminhos de ataque de identidade cloud</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {fields.map(f => (
          <div key={f.key}>
            <label className="block text-xs font-medium text-gray-400 mb-1">{f.label}</label>
            <input
              type={f.secret ? 'password' : 'text'}
              className="input-dark w-full text-sm"
              placeholder={f.placeholder || ''}
              value={form[f.key] || ''}
              onChange={e => setForm(p => ({ ...p, [f.key]: e.target.value }))}
            />
          </div>
        ))}
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={run}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition disabled:opacity-50"
        >
          {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          {loading ? 'Analisando...' : 'Executar Análise'}
        </button>
        <span className="text-xs text-gray-600">Simulação — sem acesso real ao ambiente</span>
      </div>

      {error && (
        <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-3 text-red-400 text-sm flex gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" /> {error}
        </div>
      )}

      {result && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold text-gray-300">
              {result.attack_paths?.length || 0} caminho(s) de ataque identificado(s)
            </p>
            <span className={`text-xs px-2 py-1 rounded font-bold ${SEV[result.risk_level] || SEV.Medium}`}>
              Risco: {result.risk_level}
            </span>
          </div>
          {result.summary && (
            <p className="text-sm text-gray-400 bg-dark-700 rounded-lg p-3">{result.summary}</p>
          )}
          <div className="space-y-2">
            {(result.attack_paths || []).map((p, i) => (
              <PathCard key={i} path={p} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default function CloudIdentity() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
          <Cloud className="w-7 h-7 text-red-400" />
          Cloud Identity Attack Paths
        </h1>
        <p className="text-gray-500 text-sm mt-1">
          Analisa caminhos de ataque de identidade em AWS IAM e Microsoft Entra ID (Azure AD).
          Simula técnicas MITRE ATT&CK focadas em privilege escalation e lateral movement na nuvem.
        </p>
      </div>

      <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-lg px-4 py-3 flex gap-3 text-sm text-yellow-300">
        <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5 text-yellow-500" />
        <span>
          <strong>Uso autorizado.</strong> Esta análise simula caminhos de ataque sem executar ações reais.
          Use apenas em ambientes de sua propriedade ou com autorização explícita.
        </span>
      </div>

      <ProviderPanel
        title="AWS IAM Attack Paths"
        icon={Shield}
        color="bg-orange-700"
        endpoint="/api/cloud/identity/aws-iam"
        fields={[
          { key: 'account_id', label: 'Account ID', placeholder: '123456789012' },
          { key: 'region', label: 'Região', placeholder: 'us-east-1' },
          { key: 'access_key', label: 'Access Key (opcional)', placeholder: 'AKIA...' },
          { key: 'secret_key', label: 'Secret Key (opcional)', placeholder: '••••••••', secret: true },
        ]}
      />

      <ProviderPanel
        title="Microsoft Entra ID (Azure AD) Attack Paths"
        icon={Key}
        color="bg-blue-700"
        endpoint="/api/cloud/identity/entra-id"
        fields={[
          { key: 'tenant_id', label: 'Tenant ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
          { key: 'client_id', label: 'Client ID (opcional)', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
          { key: 'client_secret', label: 'Client Secret (opcional)', placeholder: '••••••••', secret: true },
          { key: 'target_domain', label: 'Domínio Alvo', placeholder: 'empresa.onmicrosoft.com' },
        ]}
      />
    </div>
  )
}
