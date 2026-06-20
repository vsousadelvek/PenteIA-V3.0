import { useState, useEffect } from 'react'
import { Cpu, Zap, Droplets, Factory, AlertTriangle, Shield, Play, ChevronDown, ChevronUp, Loader, CheckCircle } from 'lucide-react'
import api from '../api'
import { useToast } from '../components/Toast'

const SECTORS = [
  { id: 'energy', label: 'Elétrico', icon: <Zap size={16} />, color: 'text-yellow-400' },
  { id: 'oil_gas', label: 'Petróleo & Gás', icon: <Factory size={16} />, color: 'text-orange-400' },
  { id: 'water', label: 'Saneamento', icon: <Droplets size={16} />, color: 'text-blue-400' },
  { id: 'manufacturing', label: 'Indústria 4.0', icon: <Cpu size={16} />, color: 'text-purple-400' },
]

function TechCard({ tech, onSimulate }) {
  const [expanded, setExpanded] = useState(false)
  const [target, setTarget] = useState('')
  const [simulating, setSimulating] = useState(false)
  const [result, setResult] = useState(null)
  const toast = useToast()

  const handleSim = async () => {
    if (!target.trim()) { toast('Informe o IP do alvo OT/ICS', 'error'); return }
    setSimulating(true)
    try {
      const { data } = await api.post(`/api/ot-ics/techniques/${tech.id}/simulate`, { target, sector: 'energy' })
      setResult(data)
      toast(`Simulação OT: ${tech.name} concluída`, 'success')
    } catch (e) {
      toast(e.response?.data?.detail || 'Erro', 'error')
    } finally {
      setSimulating(false)
    }
  }

  return (
    <div className="bg-dark-800 border border-red-900/50 rounded-lg p-4">
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-xs font-mono bg-dark-900 px-2 py-0.5 rounded text-orange-300">{tech.id}</span>
            <span className="text-xs bg-dark-900 px-2 py-0.5 rounded text-gray-400">ICS {tech.mitre_ics}</span>
            <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded ${
              tech.severity === 'critical' ? 'bg-red-600 text-white' : 'bg-orange-600 text-white'
            }`}>{tech.severity}</span>
            <span className="text-xs bg-dark-700 px-2 py-0.5 rounded text-gray-400">{tech.tactic?.replace(/_/g, ' ')}</span>
          </div>
          <h3 className="font-semibold text-white">{tech.name}</h3>
          <p className="text-sm text-gray-400 mt-1">{tech.description}</p>
          {tech.real_world && (
            <div className="mt-2 border border-orange-900/50 bg-orange-900/20 rounded px-3 py-2">
              <span className="text-xs text-orange-400 font-semibold">Caso Real: </span>
              <span className="text-xs text-orange-200">{tech.real_world}</span>
            </div>
          )}
        </div>
        <button onClick={() => setExpanded(e => !e)} className="text-gray-400 hover:text-white">
          {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
        </button>
      </div>

      {expanded && (
        <div className="mt-4 space-y-3">
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase mb-1">Kill Chain</h4>
            {(tech.kill_chain || []).map(s => (
              <div key={s.step} className="flex gap-2 text-sm">
                <span className="text-red-400 font-mono min-w-6">{s.step}.</span>
                <span className="text-gray-300">{s.action}</span>
              </div>
            ))}
          </div>
          {tech.affected_systems?.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-gray-400 uppercase mb-1">Sistemas Afetados</h4>
              <div className="flex gap-1 flex-wrap">
                {tech.affected_systems.map(s => (
                  <span key={s} className="text-xs bg-red-900/30 border border-red-800/50 px-2 py-0.5 rounded text-red-300">{s}</span>
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

          <div className="border border-red-900 bg-red-950/30 rounded p-3">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle size={14} className="text-red-400" />
              <span className="text-xs font-semibold text-red-300">ATENÇÃO: Simulação OT requer autorização explícita do operador</span>
            </div>
            <div className="flex gap-2">
              <input
                value={target}
                onChange={e => setTarget(e.target.value)}
                placeholder="IP do PLC/HMI (ex: 192.168.1.10)"
                className="flex-1 bg-dark-900 border border-dark-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-500"
              />
              <button
                onClick={handleSim}
                disabled={simulating}
                className="flex items-center gap-1.5 bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white text-sm px-3 py-1.5 rounded"
              >
                {simulating ? <Loader size={14} className="animate-spin" /> : <Play size={14} />}
                Simular
              </button>
            </div>
          </div>

          {result && (
            <div className="bg-dark-900 border border-green-800 rounded p-3">
              <div className="flex items-center gap-2 mb-1">
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

export default function OTSecurity() {
  const [activeSector, setActiveSector] = useState('energy')
  const [sectorData, setSectorData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    api.get(`/api/ot-ics/sectors/${activeSector}`)
      .then(r => setSectorData(r.data))
      .catch(() => setSectorData(null))
      .finally(() => setLoading(false))
  }, [activeSector])

  const sectorMeta = SECTORS.find(s => s.id === activeSector)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu size={24} className="text-red-500" />
          OT / ICS / SCADA Security
          <span className="text-sm bg-green-900/40 border border-green-700 text-green-300 px-2 py-0.5 rounded">🇧🇷 Contexto Brasil</span>
        </h1>
        <p className="text-gray-400 mt-1">Cenários de ataque em sistemas de controle industrial — energia, petróleo, saneamento</p>
      </div>

      <div className="bg-orange-900/20 border border-orange-700/50 rounded-lg p-4 flex items-start gap-3">
        <AlertTriangle size={20} className="text-orange-400 mt-0.5 shrink-0" />
        <div>
          <div className="font-semibold text-orange-300">Ambientes de Missão Crítica</div>
          <div className="text-sm text-orange-200/80 mt-0.5">
            Técnicas OT/ICS podem causar danos físicos reais. Toda simulação deve ter autorização formal do operador da planta e ser executada apenas em ambiente isolado/testbed.
          </div>
        </div>
      </div>

      <div className="flex gap-2">
        {SECTORS.map(s => (
          <button
            key={s.id}
            onClick={() => setActiveSector(s.id)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeSector === s.id ? 'bg-red-700 text-white' : 'bg-dark-800 text-gray-400 hover:text-white'
            }`}
          >
            <span className={activeSector === s.id ? 'text-white' : s.color}>{s.icon}</span>
            {s.label}
          </button>
        ))}
      </div>

      {sectorData?.br_context && (
        <div className="bg-dark-800 border border-dark-600 rounded-lg p-4">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="font-semibold text-white">{sectorData.br_context.label}</h2>
              <p className="text-sm text-gray-400 mt-1">{sectorData.br_context.context}</p>
            </div>
            <div className="text-right">
              <div className="text-xs text-gray-500">Regulação</div>
              <div className="text-xs text-green-400 font-mono mt-0.5">{sectorData.br_context.regulation}</div>
            </div>
          </div>
          <div className="flex gap-4 mt-3">
            <div className="text-center">
              <div className="text-xl font-bold text-white">{sectorData.applicable_techniques}</div>
              <div className="text-xs text-gray-500">Técnicas</div>
            </div>
            <div className="text-center">
              <div className="text-xl font-bold text-red-400">{sectorData.critical_techniques}</div>
              <div className="text-xs text-gray-500">Críticas</div>
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-12"><Loader size={32} className="animate-spin text-red-500" /></div>
      ) : (
        <div className="space-y-3">
          {(sectorData?.techniques || []).map(tech => (
            <TechCard key={tech.id} tech={tech} />
          ))}
          {(sectorData?.techniques || []).length === 0 && (
            <div className="text-center py-12 text-gray-500">Nenhuma técnica para este setor</div>
          )}
        </div>
      )}
    </div>
  )
}
