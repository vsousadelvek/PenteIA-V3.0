import React, { useState, useEffect } from 'react'
import { AlertTriangle, Play, Plus, X, Loader, BookOpen, ChevronRight, Info } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

const SEV_PT = { Low: 'Baixa', Medium: 'Média', High: 'Alta', Critical: 'Crítica' }
const SEV_COLOR = {
  Low: 'text-blue-400',
  Medium: 'text-yellow-400',
  High: 'text-orange-400',
  Critical: 'text-red-400',
}

const PLAYBOOK_TEMPLATES = [
  { name: 'Reconhecimento Inicial', severity: 'Low', techniques: 5, description: 'Simula a fase de coleta de informações que um invasor faz antes de atacar.' },
  { name: 'Movimentação Lateral', severity: 'High', techniques: 8, description: 'Testa se um invasor que já entrou na rede consegue se mover para outros sistemas.' },
  { name: 'Exfiltração de Dados', severity: 'Critical', techniques: 6, description: 'Simula um invasor tentando roubar arquivos e dados sensíveis da empresa.' },
  { name: 'Persistência no Sistema', severity: 'Medium', techniques: 4, description: 'Testa se técnicas para "ficar escondido" são detectadas pelas defesas.' },
]

export default function BAS() {
  const toast = useToast()
  const [playbooks, setPlaybooks] = useState([])
  const [simulations, setSimulations] = useState([])
  const [showNewPlaybook, setShowNewPlaybook] = useState(false)
  const [loading, setLoading] = useState(true)
  const [executingId, setExecutingId] = useState(null)
  const [newPlaybook, setNewPlaybook] = useState({ name: '', techniques: 5, severity: 'Medium', description: '' })
  const [creatingTemplate, setCreatingTemplate] = useState(null)

  useEffect(() => {
    fetchPlaybooks()
    fetchSimulations()
  }, [])

  const fetchPlaybooks = async () => {
    try {
      const res = await api.get('/api/bas/playbooks')
      setPlaybooks(res.data.playbooks || [])
    } catch (err) {
      console.error('Erro ao buscar playbooks:', err)
    } finally {
      setLoading(false)
    }
  }

  const fetchSimulations = async () => {
    try {
      const res = await api.get('/api/bas/simulations')
      setSimulations(res.data.simulations || [])
    } catch (err) {
      console.error('Erro ao buscar simulações:', err)
    }
  }

  const handleCreatePlaybook = async () => {
    if (!newPlaybook.name.trim()) {
      toast('Digite um nome para o roteiro de ataque', 'warning')
      return
    }
    try {
      await api.post('/api/bas/playbooks', {
        name: newPlaybook.name,
        techniques: newPlaybook.techniques,
        severity: newPlaybook.severity,
        description: newPlaybook.description,
      })
      setNewPlaybook({ name: '', techniques: 5, severity: 'Medium', description: '' })
      setShowNewPlaybook(false)
      await fetchPlaybooks()
      toast('Roteiro de ataque criado!', 'success')
    } catch (err) {
      toast('Erro ao criar roteiro: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  const handleCreateFromTemplate = async (tpl) => {
    setCreatingTemplate(tpl.name)
    try {
      await api.post('/api/bas/playbooks', {
        name: tpl.name,
        techniques: tpl.techniques,
        severity: tpl.severity,
        description: tpl.description,
      })
      await fetchPlaybooks()
      toast(`Roteiro "${tpl.name}" criado!`, 'success')
    } catch (err) {
      toast('Erro ao criar roteiro: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setCreatingTemplate(null)
    }
  }

  const handleExecutePlaybook = async (id) => {
    setExecutingId(id)
    try {
      await api.post('/api/bas/execute', { playbook_id: id, target: 'localhost' })
      await fetchSimulations()
      toast('Simulação executada! Veja os resultados abaixo.', 'success')
    } catch (err) {
      toast('Erro ao executar: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setExecutingId(null)
    }
  }

  const getSimPlaybookName = (sim) => {
    const pb = playbooks.find(p => p.id === sim.playbook_id)
    return pb?.name || sim.playbook_id || '-'
  }

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">Simulação de Ataques (BAS)</h1>
        <p className="text-gray-400">Testa as defesas da empresa simulando ataques reais de forma controlada</p>
      </div>

      {/* O que é BAS */}
      <div className="card-dark p-6 bg-blue-900/10 border-l-4 border-blue-600">
        <div className="flex items-center gap-2 mb-3">
          <BookOpen className="w-5 h-5 text-blue-400" />
          <h2 className="text-lg font-bold text-gray-100">O que é o BAS?</h2>
        </div>
        <p className="text-gray-300 text-sm mb-3 leading-relaxed">
          <strong>BAS (Breach &amp; Attack Simulation)</strong> é uma técnica que simula ataques reais de forma segura e controlada.
          Em vez de esperar que um hacker ataque a empresa, você mesmo faz os ataques em ambiente de teste para descobrir se as defesas funcionam.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
          {[
            { n: '1', t: 'Crie um Roteiro', d: 'Escolha um dos modelos prontos abaixo ou crie seu próprio roteiro de ataque.' },
            { n: '2', t: 'Execute a Simulação', d: 'Clique em "Executar" — a plataforma realiza os ataques de forma automática e segura.' },
            { n: '3', t: 'Analise os Resultados', d: 'Veja o score obtido e use as informações para melhorar as defesas.' },
          ].map(({ n, t, d }) => (
            <div key={n} className="flex gap-3 p-3 rounded bg-dark-700 border border-dark-600">
              <span className="text-blue-400 font-black text-xl w-6 flex-shrink-0">{n}</span>
              <div>
                <div className="font-semibold text-gray-100 text-xs mb-1">{t}</div>
                <div className="text-gray-400 text-xs leading-relaxed">{d}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4">
        <p className="text-red-400 text-sm">
          <strong>Aviso Legal:</strong> Execute apenas em ambientes que você tem autorização para testar. Nunca use em sistemas de terceiros sem permissão.
        </p>
      </div>

      {/* Modelos Prontos de Roteiro */}
      <div className="card-dark p-6">
        <div className="flex items-center gap-2 mb-2">
          <h2 className="text-2xl font-bold text-gray-100">Modelos Prontos de Roteiro</h2>
        </div>
        <p className="text-gray-400 text-sm mb-5">Clique em um modelo para criá-lo instantaneamente na sua lista de roteiros.</p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {PLAYBOOK_TEMPLATES.map(tpl => (
            <div key={tpl.name} className="bg-dark-700 border border-dark-600 rounded-lg p-4 hover:border-orange-600/50 transition">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <h3 className="font-bold text-gray-100">{tpl.name}</h3>
                  <p className="text-xs text-gray-400 mt-1 leading-relaxed">{tpl.description}</p>
                </div>
              </div>
              <div className="flex items-center justify-between mt-3">
                <div className="flex gap-3 text-xs">
                  <span className="text-gray-500">{tpl.techniques} técnicas</span>
                  <span className={SEV_COLOR[tpl.severity]}>Impacto {SEV_PT[tpl.severity]}</span>
                </div>
                <button
                  onClick={() => handleCreateFromTemplate(tpl)}
                  disabled={!!creatingTemplate}
                  className="flex items-center gap-1 text-xs px-3 py-1.5 bg-orange-700 hover:bg-orange-600 text-white rounded transition disabled:opacity-50"
                >
                  {creatingTemplate === tpl.name ? (
                    <Loader className="w-3 h-3 animate-spin" />
                  ) : (
                    <Plus className="w-3 h-3" />
                  )}
                  Usar este modelo
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Meus Roteiros */}
      <div className="card-dark p-6">
        <div className="flex justify-between items-center mb-2">
          <h2 className="text-2xl font-bold text-gray-100">Meus Roteiros de Ataque ({playbooks.length})</h2>
          <button onClick={() => setShowNewPlaybook(true)} className="btn-blue flex items-center gap-2">
            <Plus className="w-4 h-4" />
            Criar Roteiro
          </button>
        </div>
        <p className="text-gray-400 text-sm mb-5">
          Um <strong className="text-gray-300">roteiro de ataque</strong> é uma sequência de técnicas que serão executadas automaticamente no alvo.
        </p>

        {loading ? (
          <p className="text-gray-400">Carregando...</p>
        ) : playbooks.length === 0 ? (
          <div className="text-center py-10 border border-dashed border-dark-600 rounded-lg">
            <p className="text-gray-500 mb-3">Nenhum roteiro criado ainda.</p>
            <p className="text-gray-600 text-sm">Use os modelos prontos acima para começar rapidamente.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {playbooks.map(pb => (
              <div key={pb.id} className="bg-dark-700 border border-dark-600 rounded-lg p-4 hover:border-orange-600/50 transition">
                <h3 className="font-bold text-gray-100 mb-2">{pb.name}</h3>
                {pb.description && <p className="text-xs text-gray-400 mb-3 leading-relaxed">{pb.description}</p>}
                <div className="space-y-1 text-xs text-gray-400 mb-4">
                  <p>Técnicas de ataque: <span className="text-gray-300 font-semibold">{pb.techniques}</span></p>
                  <p>
                    Nível de impacto:{' '}
                    <span className={`font-semibold ${SEV_COLOR[pb.severity] || 'text-gray-300'}`}>
                      {SEV_PT[pb.severity] || pb.severity}
                    </span>
                  </p>
                </div>
                <button
                  onClick={() => handleExecutePlaybook(pb.id)}
                  disabled={!!executingId}
                  className="btn-red w-full text-sm flex justify-center items-center gap-2 disabled:opacity-50"
                >
                  {executingId === pb.id ? (
                    <><Loader className="w-3 h-3 animate-spin" /> Executando...</>
                  ) : (
                    <><Play className="w-3 h-3" /> Executar Simulação</>
                  )}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Histórico de Simulações */}
      <div className="card-dark p-6">
        <h2 className="text-2xl font-bold text-gray-100 mb-2">Histórico de Simulações ({simulations.length})</h2>
        <p className="text-gray-400 text-sm mb-5">
          O <strong className="text-gray-300">score</strong> indica a efetividade da simulação — quanto maior, mais técnicas foram executadas com sucesso.
        </p>
        {simulations.length === 0 ? (
          <div className="text-center py-8 border border-dashed border-dark-600 rounded-lg">
            <p className="text-gray-500 text-sm">Nenhuma simulação executada ainda.</p>
            <p className="text-gray-600 text-xs mt-1">Execute um roteiro acima para começar.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-600">
                  <th className="text-left py-3 text-gray-400 font-semibold">Roteiro Executado</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Alvo</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Resultado</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Score</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Data</th>
                </tr>
              </thead>
              <tbody>
                {simulations.map(sim => (
                  <tr key={sim.id} className="border-b border-dark-700 hover:bg-dark-700 transition">
                    <td className="py-3 text-gray-100">{getSimPlaybookName(sim)}</td>
                    <td className="py-3 text-gray-300">{sim.target}</td>
                    <td className="py-3">
                      <span className={`text-xs px-2 py-1 rounded ${sim.status === 'completed' ? 'bg-green-900/30 text-green-400' : 'bg-blue-900/30 text-blue-400'}`}>
                        {sim.status === 'completed' ? 'Concluída' : 'Executando...'}
                      </span>
                    </td>
                    <td className="py-3 text-gray-300 font-mono">{sim.score ?? '-'}</td>
                    <td className="py-3 text-gray-400">{sim.date ? new Date(sim.date).toLocaleString('pt-BR') : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal Novo Roteiro */}
      {showNewPlaybook && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 overflow-y-auto">
          <div className="card-dark max-w-md w-full my-auto">
            <div className="flex justify-between items-center p-6 border-b border-dark-600">
              <div>
                <h2 className="text-xl font-bold text-gray-100">Criar Roteiro de Ataque</h2>
                <p className="text-xs text-gray-400 mt-1">Defina o nome e características da simulação</p>
              </div>
              <button onClick={() => setShowNewPlaybook(false)} className="text-gray-400 hover:text-gray-100 transition">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Nome do Roteiro
                  <span className="text-gray-500 font-normal ml-1">(dê um nome descritivo)</span>
                </label>
                <input
                  type="text"
                  value={newPlaybook.name}
                  onChange={(e) => setNewPlaybook({ ...newPlaybook, name: e.target.value })}
                  placeholder="ex: Teste de Firewall - Rede Interna"
                  className="input-dark w-full"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Nº de Técnicas
                  </label>
                  <p className="text-xs text-gray-500 mb-2">Quantas técnicas de ataque usar</p>
                  <input
                    type="number"
                    value={newPlaybook.techniques}
                    onChange={(e) => setNewPlaybook({ ...newPlaybook, techniques: parseInt(e.target.value) || 0 })}
                    min="1" max="40"
                    className="input-dark w-full"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Nível de Impacto
                  </label>
                  <p className="text-xs text-gray-500 mb-2">Agressividade da simulação</p>
                  <select
                    value={newPlaybook.severity}
                    onChange={(e) => setNewPlaybook({ ...newPlaybook, severity: e.target.value })}
                    className="select-dark w-full"
                  >
                    <option value="Low">Baixo — impacto mínimo</option>
                    <option value="Medium">Médio — equilibrado</option>
                    <option value="High">Alto — agressivo</option>
                    <option value="Critical">Crítico — máximo</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Descrição <span className="text-gray-500 font-normal">(opcional)</span>
                </label>
                <textarea
                  value={newPlaybook.description}
                  onChange={(e) => setNewPlaybook({ ...newPlaybook, description: e.target.value })}
                  placeholder="Descreva o objetivo deste roteiro de ataque..."
                  className="input-dark w-full h-24 resize-none"
                />
              </div>

              <div className="bg-blue-900/20 border border-blue-700/40 rounded p-3 text-xs text-blue-300 flex gap-2">
                <Info className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>Após criar o roteiro, ele aparecerá na lista acima onde você poderá executá-lo a qualquer momento.</span>
              </div>
            </div>
            <div className="flex justify-end gap-2 p-6 border-t border-dark-600">
              <button onClick={() => setShowNewPlaybook(false)} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded transition">
                Cancelar
              </button>
              <button onClick={handleCreatePlaybook} className="btn-blue">
                Criar Roteiro
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
