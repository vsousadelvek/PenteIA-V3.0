import React, { useState, useEffect } from 'react'
import {
  Shield, Globe, Target, Play, ChevronRight, Loader,
  AlertTriangle, CheckCircle, ArrowRight, Crosshair, Layers,
  Users, MapPin, Tag, Info, Zap
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useToast } from '../components/Toast'
import api from '../api'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COUNTRY_FLAG = {
  lazarus:     '🇰🇵',
  apt28:       '🇷🇺',
  cobalt_group:'🌍',
  muddywater:  '🇮🇷',
  sandworm:    '🇷🇺',
  lapsus:      '🌎',
}

const FALLBACK_GROUPS = [
  {
    id: 'lazarus',
    name: 'Lazarus Group',
    origin_country: 'North Korea',
    target_sectors: ['Financeiro', 'Crypto', 'Defesa'],
    description: 'Grupo APT patrocinado pela Coreia do Norte focado em crimes financeiros e espionagem',
  },
  {
    id: 'apt28',
    name: 'APT28 / Fancy Bear',
    origin_country: 'Russia',
    target_sectors: ['Governo', 'Militar', 'Eleições'],
    description: 'Grupo de espionagem russo ligado ao GRU, foco em governo e setor militar',
  },
  {
    id: 'cobalt_group',
    name: 'Cobalt Group',
    origin_country: 'Eastern Europe',
    target_sectors: ['Bancos', 'ATM', 'FinTech'],
    description: 'Grupo criminoso focado em ataques a bancos, ATMs e sistemas SWIFT',
  },
  {
    id: 'muddywater',
    name: 'MuddyWater',
    origin_country: 'Iran',
    target_sectors: ['Governo', 'Telecom', 'Energia'],
    description: 'APT iraniano focado em governo e telecomunicações do Oriente Médio',
  },
  {
    id: 'sandworm',
    name: 'Sandworm Team',
    origin_country: 'Russia',
    target_sectors: ['Infraestrutura', 'ICS', 'Energia'],
    description: 'Grupo russo responsável por ataques a infraestrutura crítica e sistemas ICS/SCADA',
  },
  {
    id: 'lapsus',
    name: 'Lapsus$',
    origin_country: 'LATAM/Global',
    target_sectors: ['Tech', 'SaaS', 'Dados'],
    description: 'Grupo de extorsão de dados com origem LATAM, alvos em empresas de tecnologia globais',
  },
]

// Kill-chain phases per group (ordered tactic → technique)
const KILL_CHAIN = {
  lazarus: [
    { tactic: 'Reconhecimento',        technique: 'Coleta de inteligência OSINT sobre alvos financeiros' },
    { tactic: 'Acesso Inicial',        technique: 'Spear-phishing com documentos Office maliciosos' },
    { tactic: 'Execução',              technique: 'Macro VBA e PowerShell remoto' },
    { tactic: 'Persistência',          technique: 'Backdoor BLINDINGCAN / HOPLIGHT' },
    { tactic: 'Movimentação Lateral',  technique: 'Pass-the-Hash e Remote Services' },
    { tactic: 'Exfiltração',           technique: 'Transferência via SWIFT e exchanges de crypto' },
  ],
  apt28: [
    { tactic: 'Reconhecimento',        technique: 'Enumeração de subdomínios e scanning de portas' },
    { tactic: 'Acesso Inicial',        technique: 'Phishing com credential harvesting (X-Agent)' },
    { tactic: 'Execução',              technique: 'Scripts PowerShell e exploits de vulnerabilidade' },
    { tactic: 'Persistência',          technique: 'ScheduledTask e RunKeys no registro' },
    { tactic: 'Coleta',                technique: 'Keylogging e captura de screenshots' },
    { tactic: 'Comando e Controle',    technique: 'C2 via HTTP/S e DNS tunneling' },
    { tactic: 'Exfiltração',           technique: 'Exfiltração via canais criptografados' },
  ],
  cobalt_group: [
    { tactic: 'Reconhecimento',        technique: 'Mapeamento da rede bancária e SWIFT' },
    { tactic: 'Acesso Inicial',        technique: 'Spear-phishing para funcionários de banco' },
    { tactic: 'Execução',              technique: 'Cobalt Strike Beacon e Metasploit' },
    { tactic: 'Escalada de Privilégio','technique': 'Exploração de serviços locais vulneráveis' },
    { tactic: 'Movimentação Lateral',  technique: 'Acesso a sistemas ATM e SWIFT Alliance' },
    { tactic: 'Impacto',               technique: 'Saques fraudulentos em ATMs (jackpotting)' },
  ],
  muddywater: [
    { tactic: 'Reconhecimento',        technique: 'OSINT sobre alvos governamentais MENA' },
    { tactic: 'Acesso Inicial',        technique: 'Spear-phishing com anexos PDF maliciosos' },
    { tactic: 'Execução',              technique: 'Scripts Python/PowerShell (POWERSTATS)' },
    { tactic: 'Persistência',          technique: 'Chaves de registro e serviços falsos' },
    { tactic: 'Coleta',                technique: 'Roubo de credenciais e documentos sensíveis' },
    { tactic: 'Exfiltração',           technique: 'Exfiltração via Web shell e Dropbox API' },
  ],
  sandworm: [
    { tactic: 'Reconhecimento',        technique: 'Scanning de sistemas ICS/SCADA expostos' },
    { tactic: 'Acesso Inicial',        technique: 'Exploração de VPN e RDP expostos' },
    { tactic: 'Execução',              technique: 'BlackEnergy e Industroyer malware' },
    { tactic: 'Persistência',          technique: 'Firmware malicioso em PLCs e RTUs' },
    { tactic: 'Inibição de Resposta',  technique: 'Wiper KillDisk para destruir backups' },
    { tactic: 'Impacto',               technique: 'Desligamento de infraestrutura elétrica' },
  ],
  lapsus: [
    { tactic: 'Reconhecimento',        technique: 'Engenharia social e SIM swapping' },
    { tactic: 'Acesso Inicial',        technique: 'Compra de credenciais em fóruns underground' },
    { tactic: 'Escalada de Privilégio','technique': 'Acesso a Okta e ferramentas internas (Jira, Slack)' },
    { tactic: 'Coleta',                technique: 'Download massivo de repositórios e código-fonte' },
    { tactic: 'Impacto',               technique: 'Extorsão e vazamento público de dados' },
  ],
}

const DEFAULT_KILL_CHAIN = [
  { tactic: 'Reconhecimento',       technique: 'Coleta de informações sobre o alvo' },
  { tactic: 'Acesso Inicial',       technique: 'Exploração de vetor de entrada' },
  { tactic: 'Execução',             technique: 'Execução de payload malicioso' },
  { tactic: 'Persistência',         technique: 'Estabelecimento de backdoor' },
  { tactic: 'Movimentação Lateral', technique: 'Expansão de acesso na rede interna' },
  { tactic: 'Exfiltração',          technique: 'Exfiltração de dados sensíveis' },
]

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SectorBadge({ sector }) {
  return (
    <span className="text-[10px] px-1.5 py-0.5 rounded border border-dark-600 bg-dark-700 text-gray-400 font-mono">
      {sector}
    </span>
  )
}

function GroupCard({ group, selected, onSelect }) {
  const flag = COUNTRY_FLAG[group.id] || '🌐'
  const isSelected = selected?.id === group.id

  return (
    <div
      className={`card-dark cursor-pointer transition-all duration-200 flex flex-col gap-3 ${
        isSelected
          ? 'border-red-500 bg-red-900/10 shadow-lg shadow-red-900/20'
          : 'hover:border-dark-500 hover:bg-dark-700/50'
      }`}
      onClick={() => onSelect(group)}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-xl flex-shrink-0">{flag}</span>
          <div className="min-w-0">
            <h3 className="text-gray-100 font-semibold text-sm truncate">{group.name}</h3>
            <div className="flex items-center gap-1 mt-0.5">
              <MapPin className="w-3 h-3 text-gray-500 flex-shrink-0" />
              <span className="text-gray-400 text-xs truncate">{group.country || group.origin_country}</span>
            </div>
          </div>
        </div>
        {isSelected && (
          <div className="flex-shrink-0 w-5 h-5 rounded-full bg-red-500 flex items-center justify-center">
            <CheckCircle className="w-3 h-3 text-white" />
          </div>
        )}
      </div>

      {/* Sectors */}
      <div className="flex flex-wrap gap-1">
        {(group.target_sectors || []).map(s => (
          <SectorBadge key={s} sector={s} />
        ))}
      </div>

      {/* Description */}
      <p className="text-gray-400 text-xs leading-relaxed line-clamp-3">{group.description}</p>

      {/* Action */}
      <button
        className={`mt-auto w-full py-1.5 rounded text-xs font-medium transition flex items-center justify-center gap-1.5 ${
          isSelected
            ? 'bg-red-700 text-white'
            : 'bg-dark-700 text-gray-300 hover:bg-dark-600 border border-dark-600'
        }`}
        onClick={e => { e.stopPropagation(); onSelect(group) }}
      >
        {isSelected ? (
          <><CheckCircle className="w-3.5 h-3.5" /> Selecionado</>
        ) : (
          <><Target className="w-3.5 h-3.5" /> Selecionar</>
        )}
      </button>
    </div>
  )
}

function KillChainTimeline({ group }) {
  const steps = (group.kill_chain && group.kill_chain.length > 0) ? group.kill_chain : (KILL_CHAIN[group.id] || DEFAULT_KILL_CHAIN)

  return (
    <div className="flex flex-col gap-0">
      {steps.map((step, i) => (
        <div key={i} className="flex gap-3">
          {/* Connector column */}
          <div className="flex flex-col items-center flex-shrink-0">
            <div className="w-7 h-7 rounded-full bg-red-900/60 border border-red-700 flex items-center justify-center text-red-400 text-xs font-bold flex-shrink-0">
              {i + 1}
            </div>
            {i < steps.length - 1 && (
              <div className="w-px flex-1 bg-dark-600 my-1" style={{ minHeight: '16px' }} />
            )}
          </div>
          {/* Content */}
          <div className={`pb-4 ${i < steps.length - 1 ? '' : ''}`}>
            <span className="text-[10px] font-mono text-red-400 uppercase tracking-wider block">
              {step.tactic}
            </span>
            <span className="text-gray-300 text-xs">{step.technique}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

function DetailsPanel({ group, target, setTarget, onSimulate, simulating }) {
  const steps = (group.kill_chain && group.kill_chain.length > 0) ? group.kill_chain : (KILL_CHAIN[group.id] || DEFAULT_KILL_CHAIN)
  const flag = COUNTRY_FLAG[group.id] || '🌐'

  return (
    <div className="card-dark flex flex-col gap-5">
      {/* Group header */}
      <div className="flex items-center gap-3 pb-4 border-b border-dark-600">
        <span className="text-3xl">{flag}</span>
        <div className="flex-1 min-w-0">
          <h2 className="text-gray-100 font-bold text-base">{group.name}</h2>
          <div className="flex items-center gap-2 mt-0.5 flex-wrap">
            <span className="text-gray-400 text-xs flex items-center gap-1">
              <MapPin className="w-3 h-3" />{group.country || group.origin_country}
            </span>
            <span className="text-gray-600">•</span>
            <span className="bg-red-900/40 text-red-400 border border-red-800 text-xs px-2 py-0.5 rounded-full font-mono">
              {steps.length} técnicas
            </span>
          </div>
        </div>
      </div>

      {/* Sectors */}
      <div>
        <div className="flex items-center gap-1.5 mb-2">
          <Tag className="w-3.5 h-3.5 text-gray-500" />
          <span className="text-gray-400 text-xs font-medium uppercase tracking-wider">Setores Alvo</span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {(group.target_sectors || []).map(s => (
            <SectorBadge key={s} sector={s} />
          ))}
        </div>
      </div>

      {/* Description */}
      <div>
        <div className="flex items-center gap-1.5 mb-2">
          <Info className="w-3.5 h-3.5 text-gray-500" />
          <span className="text-gray-400 text-xs font-medium uppercase tracking-wider">Descrição</span>
        </div>
        <p className="text-gray-300 text-sm leading-relaxed">{group.description}</p>
      </div>

      {/* Kill chain */}
      <div>
        <div className="flex items-center gap-1.5 mb-3">
          <Layers className="w-3.5 h-3.5 text-gray-500" />
          <span className="text-gray-400 text-xs font-medium uppercase tracking-wider">Kill Chain</span>
        </div>
        <KillChainTimeline group={group} />
      </div>

      {/* Launch form */}
      <div className="pt-4 border-t border-dark-600 flex flex-col gap-3">
        <div className="flex items-center gap-1.5 mb-1">
          <Crosshair className="w-3.5 h-3.5 text-red-400" />
          <span className="text-gray-300 text-xs font-medium uppercase tracking-wider">Iniciar Simulação</span>
        </div>
        <input
          type="text"
          className="input-dark text-sm"
          placeholder="IP, hostname ou CIDR alvo (ex: 192.168.1.0/24)"
          value={target}
          onChange={e => setTarget(e.target.value)}
        />
        <button
          className="bg-red-700 hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold py-2.5 px-4 rounded transition flex items-center justify-center gap-2"
          onClick={onSimulate}
          disabled={simulating || !target.trim()}
        >
          {simulating ? (
            <><Loader className="w-4 h-4 animate-spin" /> Iniciando simulação...</>
          ) : (
            <><Zap className="w-4 h-4" /> Iniciar Simulação APT</>
          )}
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function APT() {
  const toast = useToast()
  const navigate = useNavigate()

  const [groups, setGroups]       = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [selected, setSelected]   = useState(null)
  const [target, setTarget]       = useState('')
  const [simulating, setSimulating] = useState(false)

  // Load groups from API; fall back to hardcoded list on failure
  useEffect(() => {
    setLoading(true)
    api.get('/api/apt/groups')
      .then(r => {
        const data = r.data?.groups || r.data
        if (Array.isArray(data) && data.length > 0) {
          setGroups(data)
        } else {
          setGroups(FALLBACK_GROUPS)
        }
      })
      .catch(() => {
        setGroups(FALLBACK_GROUPS)
        setError('API indisponível — exibindo grupos offline.')
      })
      .finally(() => setLoading(false))
  }, [])

  const handleSelect = (group) => {
    setSelected(prev => prev?.id === group.id ? null : group)
    setTarget('')
  }

  const handleSimulate = async () => {
    if (!selected || !target.trim()) return
    setSimulating(true)
    try {
      const res = await api.post(`/api/apt/simulate/${selected.id}`, { target: target.trim() })
      const { simulation_id, group_name, techniques_count } = res.data || {}
      toast(
        `Simulação ${group_name || selected.name} iniciada! ${techniques_count ?? '?'} técnicas em execução (ID: ${simulation_id ?? '?'})`,
        'success'
      )
      // Navigate to BAS after short delay so toast is visible
      setTimeout(() => navigate('/bas'), 1800)
    } catch (err) {
      const msg = err.response?.data?.detail || 'Erro ao iniciar simulação APT'
      toast(msg, 'error')
    } finally {
      setSimulating(false)
    }
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* ------------------------------------------------------------------ */}
      {/* Header                                                              */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <Shield className="w-6 h-6 text-red-400" />
            <h1 className="text-2xl font-bold text-gray-100">APT Emulation</h1>
          </div>
          <p className="text-gray-400 text-sm">
            Emule grupos APT reais contra seu ambiente
          </p>
        </div>

        {selected && (
          <div className="flex items-center gap-2 bg-red-900/20 border border-red-800/50 rounded-lg px-3 py-2">
            <Target className="w-4 h-4 text-red-400" />
            <span className="text-red-300 text-sm font-medium">
              {selected.name} selecionado
            </span>
          </div>
        )}
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Offline warning                                                     */}
      {/* ------------------------------------------------------------------ */}
      {error && (
        <div className="flex items-center gap-2 bg-yellow-900/20 border border-yellow-700/40 rounded-lg px-4 py-3">
          <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0" />
          <span className="text-yellow-300 text-sm">{error}</span>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Loading                                                             */}
      {/* ------------------------------------------------------------------ */}
      {loading ? (
        <div className="flex flex-col items-center justify-center h-64 gap-3">
          <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-gray-400 text-sm">Carregando grupos APT...</span>
        </div>
      ) : (
        <div className={`grid gap-6 ${selected ? 'lg:grid-cols-3' : 'grid-cols-1'}`}>
          {/* -------------------------------------------------------------- */}
          {/* Group cards grid                                                */}
          {/* -------------------------------------------------------------- */}
          <div className={`${selected ? 'lg:col-span-2' : ''}`}>
            <div className={`grid gap-4 ${selected ? 'sm:grid-cols-2' : 'sm:grid-cols-2 lg:grid-cols-3'}`}>
              {groups.map(group => (
                <GroupCard
                  key={group.id}
                  group={group}
                  selected={selected}
                  onSelect={handleSelect}
                />
              ))}
            </div>

            {/* Empty state */}
            {groups.length === 0 && (
              <div className="card-dark flex flex-col items-center justify-center h-48 gap-3">
                <Users className="w-10 h-10 text-gray-600" />
                <p className="text-gray-400 text-sm">Nenhum grupo APT disponível</p>
              </div>
            )}
          </div>

          {/* -------------------------------------------------------------- */}
          {/* Details panel (visible when a group is selected)               */}
          {/* -------------------------------------------------------------- */}
          {selected && (
            <div className="lg:col-span-1">
              <DetailsPanel
                group={selected}
                target={target}
                setTarget={setTarget}
                onSimulate={handleSimulate}
                simulating={simulating}
              />
            </div>
          )}
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Call-to-action when nothing selected yet                           */}
      {/* ------------------------------------------------------------------ */}
      {!loading && !selected && groups.length > 0 && (
        <div className="card-dark flex items-center gap-3 border-dashed">
          <div className="w-8 h-8 rounded-full bg-dark-700 border border-dark-600 flex items-center justify-center flex-shrink-0">
            <ArrowRight className="w-4 h-4 text-gray-500" />
          </div>
          <p className="text-gray-400 text-sm">
            Selecione um grupo APT acima para ver a kill chain detalhada e iniciar uma simulação contra seu ambiente.
          </p>
        </div>
      )}
    </div>
  )
}
