import { useState, useEffect } from 'react'
import { Server, Box, Shield, AlertTriangle, Play, ChevronDown, ChevronUp, Key, Loader, CheckCircle } from 'lucide-react'
import api from '../api'
import { useToast } from '../components/Toast'

const SEVERITY_COLORS = {
  critical: 'bg-red-900/40 border-red-700 text-red-300',
  high: 'bg-orange-900/40 border-orange-700 text-orange-300',
  medium: 'bg-yellow-900/40 border-yellow-700 text-yellow-300',
  low: 'bg-blue-900/40 border-blue-700 text-blue-300',
}

const TACTIC_COLORS = {
  PRIVILEGE_ESCALATION: 'bg-purple-900/30 text-purple-300',
  CREDENTIAL_ACCESS: 'bg-yellow-900/30 text-yellow-300',
  INITIAL_ACCESS: 'bg-red-900/30 text-red-300',
  LATERAL_MOVEMENT: 'bg-blue-900/30 text-blue-300',
  IMPACT: 'bg-pink-900/30 text-pink-300',
}

function TechniqueCard({ tech, onSimulate }) {
  const [expanded, setExpanded] = useState(false)
  const [target, setTarget] = useState('')
  const [simulating, setSimulating] = useState(false)
  const [result, setResult] = useState(null)
  const toast = useToast()

  const handleSimulate = async () => {
    if (!target.trim()) { toast('Informe o alvo (ex: 10.0.0.1 ou cluster.internal)', 'error'); return }
    setSimulating(true)
    try {
      const { data } = await api.post(`/api/k8s/techniques/${tech.id}/simulate`, { target })
      setResult(data)
      toast(`Simulação concluída: ${tech.name}`, 'success')
    } catch (e) {
      toast(e.response?.data?.detail || 'Erro na simulação', 'error')
    } finally {
      setSimulating(false)
    }
  }

  return (
    <div className={`border rounded-lg p-4 ${SEVERITY_COLORS[tech.severity]}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-xs font-mono bg-dark-900/60 px-2 py-0.5 rounded text-gray-300">{tech.id}</span>
            <span className="text-xs bg-dark-900/60 px-2 py-0.5 rounded text-gray-400">{tech.mitre_id}</span>
            <span className={`text-xs px-2 py-0.5 rounded font-medium ${TACTIC_COLORS[tech.tactic] || 'bg-gray-800 text-gray-300'}`}>
              {tech.tactic?.replace(/_/g, ' ')}
            </span>
            <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded ${
              tech.severity === 'critical' ? 'bg-red-600 text-white' :
              tech.severity === 'high' ? 'bg-orange-600 text-white' :
              tech.severity === 'medium' ? 'bg-yellow-600 text-black' : 'bg-blue-600 text-white'
            }`}>{tech.severity}</span>
          </div>
          <h3 className="font-semibold text-white">{tech.name}</h3>
          <p className="text-sm text-gray-400 mt-1">{tech.description}</p>
        </div>
        <button onClick={() => setExpanded(e => !e)} className="text-gray-400 hover:text-white mt-1">
          {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
        </button>
      </div>

      {expanded && (
        <div className="mt-4 space-y-3">
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase mb-1">Kill Chain</h4>
            <div className="space-y-1">
              {(tech.kill_chain || []).map(s => (
                <div key={s.step} className="flex gap-2 text-sm">
                  <span className="text-red-400 font-mono min-w-6">{s.step}.</span>
                  <span className="text-gray-300">{s.action}</span>
                </div>
              ))}
            </div>
          </div>
          {tech.tools?.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-gray-400 uppercase mb-1">Ferramentas</h4>
              <div className="flex gap-1 flex-wrap">
                {tech.tools.map(t => (
                  <span key={t} className="text-xs bg-dark-800 border border-dark-600 px-2 py-0.5 rounded text-gray-300">{t}</span>
                ))}
              </div>
            </div>
          )}
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase mb-1">Mitigações</h4>
            <ul className="text-sm text-gray-300 list-disc list-inside space-y-0.5">
              {(tech.mitigations || []).map((m, i) => <li key={i}>{m}</li>)}
            </ul>
          </div>
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase mb-1">Detecção</h4>
            <ul className="text-sm text-gray-300 list-disc list-inside space-y-0.5">
              {(tech.detection || []).map((d, i) => <li key={i}>{d}</li>)}
            </ul>
          </div>

          <div className="pt-2 border-t border-white/10">
            <div className="flex gap-2">
              <input
                value={target}
                onChange={e => setTarget(e.target.value)}
                placeholder="Alvo (ex: 10.0.0.1, cluster.internal)"
                className="flex-1 bg-dark-800 border border-dark-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-500"
              />
              <button
                onClick={handleSimulate}
                disabled={simulating}
                className="flex items-center gap-1.5 bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white text-sm px-3 py-1.5 rounded"
              >
                {simulating ? <Loader size={14} className="animate-spin" /> : <Play size={14} />}
                Simular
              </button>
            </div>
          </div>

          {result && (
            <div className="bg-dark-900 border border-green-800 rounded p-3 mt-2">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle size={14} className="text-green-400" />
                <span className="text-sm font-semibold text-green-400">Simulação Concluída</span>
              </div>
              <div className="text-xs text-gray-300 space-y-1">
                {(result.findings || []).map((f, i) => <div key={i}>{f}</div>)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function K8sSecurity() {
  const [techniques, setTechniques] = useState([])
  const [categories, setCategories] = useState({})
  const [activeTab, setActiveTab] = useState('all')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const { data } = await api.get('/api/k8s/techniques')
        setTechniques(data.techniques || [])
        setCategories(data.categories || {})
      } catch {
        setTechniques([])
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  const filtered = activeTab === 'all'
    ? techniques
    : techniques.filter(t => t.id.startsWith(activeTab === 'k8s' ? 'K8S' : 'CNT'))

  const critical = techniques.filter(t => t.severity === 'critical').length
  const high = techniques.filter(t => t.severity === 'high').length

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Server size={24} className="text-red-500" />
          Kubernetes & Container Security
        </h1>
        <p className="text-gray-400 mt-1">Cenários de ataque para ambientes K8s e containers (MITRE ATT&CK)</p>
      </div>

      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total', value: techniques.length, color: 'text-gray-300' },
          { label: 'K8s', value: techniques.filter(t => t.id.startsWith('K8S')).length, color: 'text-blue-400' },
          { label: 'Container', value: techniques.filter(t => t.id.startsWith('CNT')).length, color: 'text-purple-400' },
          { label: 'Crítico', value: critical, color: 'text-red-400' },
        ].map(s => (
          <div key={s.label} className="bg-dark-800 border border-dark-600 rounded-lg p-3 text-center">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-gray-500 mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="flex gap-2">
        {[
          { id: 'all', label: 'Todos', icon: <Shield size={14} /> },
          { id: 'k8s', label: 'Kubernetes', icon: <Server size={14} /> },
          { id: 'container', label: 'Container', icon: <Box size={14} /> },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTab === tab.id ? 'bg-red-700 text-white' : 'bg-dark-800 text-gray-400 hover:text-white'
            }`}
          >
            {tab.icon}{tab.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-12">
          <Loader size={32} className="animate-spin text-red-500" />
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map(tech => (
            <TechniqueCard key={tech.id} tech={tech} />
          ))}
          {filtered.length === 0 && (
            <div className="text-center py-12 text-gray-500">Nenhuma técnica encontrada</div>
          )}
        </div>
      )}
    </div>
  )
}
