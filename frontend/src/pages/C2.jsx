import React, { useState, useEffect } from 'react'
import { AlertTriangle, Radio, Plus, X, Trash2, BookOpen, Info, Wifi } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

function relativeTime(ts) {
  if (!ts) return 'nunca'
  const diff = Date.now() - new Date(ts).getTime()
  if (isNaN(diff)) return ts
  const min = Math.floor(diff / 60000)
  if (min < 1) return 'agora mesmo'
  if (min < 60) return `há ${min} min`
  const h = Math.floor(min / 60)
  if (h < 24) return `há ${h}h`
  return `há ${Math.floor(h / 24)} dias`
}

const PROTOCOL_INFO = {
  HTTP:  'Comunicação via web não criptografada — mais fácil de detectar, mas funciona em qualquer rede.',
  HTTPS: 'Comunicação web criptografada — dificulta a detecção ao se misturar com tráfego normal de sites.',
  DNS:   'Comunicação escondida em consultas de DNS — muito difícil de detectar pois DNS raramente é bloqueado.',
}

export default function C2() {
  const toast = useToast()
  const [listeners, setListeners] = useState([])
  const [beacons, setBeacons] = useState([])
  const [showNewListener, setShowNewListener] = useState(false)
  const [loading, setLoading] = useState(true)
  const [newListener, setNewListener] = useState({ name: '', host: '', port: 443, protocol: 'HTTPS' })

  useEffect(() => {
    fetchListeners()
    fetchBeacons()
    const interval = setInterval(fetchBeacons, 5000)
    return () => clearInterval(interval)
  }, [])

  const fetchListeners = async () => {
    try {
      const res = await api.get('/api/c2/listeners')
      setListeners(res.data.listeners || [])
    } catch (err) {
      console.error('Erro ao buscar listeners:', err)
    } finally {
      setLoading(false)
    }
  }

  const fetchBeacons = async () => {
    try {
      const res = await api.get('/api/c2/beacons')
      setBeacons(res.data.beacons || [])
    } catch (err) {
      console.error('Erro ao buscar beacons:', err)
    }
  }

  const handleCreateListener = async () => {
    if (!newListener.name.trim() || !newListener.host.trim()) {
      toast('Preencha o nome e o endereço do servidor', 'warning')
      return
    }
    try {
      await api.post('/api/c2/listeners', {
        name: newListener.name,
        host: newListener.host,
        port: newListener.port,
        protocol: newListener.protocol,
      })
      setNewListener({ name: '', host: '', port: 443, protocol: 'HTTPS' })
      setShowNewListener(false)
      await fetchListeners()
      toast('Servidor de escuta criado!', 'success')
    } catch (err) {
      toast('Erro ao criar servidor: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  const handleDeleteListener = async (id) => {
    if (!window.confirm('Deseja remover este servidor de escuta?')) return
    try {
      await api.delete(`/api/c2/listeners/${id}`)
      await fetchListeners()
      toast('Servidor de escuta removido!', 'success')
    } catch (err) {
      toast('Erro ao remover: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">Controle Remoto (C2)</h1>
        <p className="text-gray-400">Simula como um invasor controlaria computadores comprometidos à distância</p>
      </div>

      {/* O que é C2 */}
      <div className="card-dark p-6 bg-green-900/10 border-l-4 border-green-600">
        <div className="flex items-center gap-2 mb-3">
          <BookOpen className="w-5 h-5 text-green-400" />
          <h2 className="text-lg font-bold text-gray-100">Como funciona o C2?</h2>
        </div>
        <p className="text-gray-300 text-sm mb-4 leading-relaxed">
          <strong>C2 (Comando e Controle)</strong> simula o canal de comunicação que um invasor usa para controlar computadores que ele comprometeu.
          Em um ataque real, o invasor instala um "agente" no computador da vítima e usa esse canal para enviar comandos remotamente.
          Aqui você configura esse ambiente de forma controlada para testar se as defesas da empresa conseguem detectá-lo.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div className="p-4 rounded bg-dark-700 border border-dark-600">
            <div className="flex items-center gap-2 mb-2">
              <Wifi className="w-4 h-4 text-green-400" />
              <span className="font-bold text-gray-100">Servidor de Escuta</span>
              <span className="text-xs text-gray-500">(Listener)</span>
            </div>
            <p className="text-gray-400 text-xs leading-relaxed">
              É o servidor que fica esperando conexões dos agentes instalados no alvo.
              Você precisa criar pelo menos um servidor de escuta antes de receber conexões de agentes.
            </p>
          </div>
          <div className="p-4 rounded bg-dark-700 border border-dark-600">
            <div className="flex items-center gap-2 mb-2">
              <Radio className="w-4 h-4 text-blue-400" />
              <span className="font-bold text-gray-100">Agente Conectado</span>
              <span className="text-xs text-gray-500">(Beacon)</span>
            </div>
            <p className="text-gray-400 text-xs leading-relaxed">
              É o programa que foi instalado no computador alvo e que se conecta periodicamente ao servidor de escuta para receber comandos.
              Cada computador comprometido aparece como um agente na lista abaixo.
            </p>
          </div>
        </div>
      </div>

      <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4">
        <p className="text-red-400 text-sm">
          <strong>Aviso Legal:</strong> O módulo C2 é apenas para ambientes de teste autorizados. Uso ilegal resulta em processo criminal.
        </p>
      </div>

      {/* Servidores de Escuta */}
      <div className="card-dark p-6">
        <div className="flex justify-between items-center mb-2">
          <div>
            <h2 className="text-2xl font-bold text-gray-100">Servidores de Escuta ({listeners.length})</h2>
            <p className="text-gray-400 text-sm mt-1">Servidores aguardando conexões dos agentes instalados nos alvos</p>
          </div>
          <button onClick={() => setShowNewListener(true)} className="btn-blue flex items-center gap-2">
            <Plus className="w-4 h-4" />
            Novo Servidor
          </button>
        </div>

        {loading ? (
          <p className="text-gray-400 mt-4">Carregando...</p>
        ) : listeners.length === 0 ? (
          <div className="text-center py-10 border border-dashed border-dark-600 rounded-lg mt-4">
            <Wifi className="w-8 h-8 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-500 text-sm">Nenhum servidor de escuta criado ainda.</p>
            <p className="text-gray-600 text-xs mt-1">Clique em "Novo Servidor" para começar.</p>
          </div>
        ) : (
          <div className="overflow-x-auto mt-4">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-600">
                  <th className="text-left py-3 text-gray-400 font-semibold">Nome</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Endereço</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Porta</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Protocolo</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Status</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Ação</th>
                </tr>
              </thead>
              <tbody>
                {listeners.map(listener => (
                  <tr key={listener.id} className="border-b border-dark-700 hover:bg-dark-700 transition">
                    <td className="py-3 text-gray-100 font-medium">{listener.name}</td>
                    <td className="py-3 text-gray-300 font-mono text-xs">{listener.host}</td>
                    <td className="py-3 text-gray-300 font-mono">{listener.port}</td>
                    <td className="py-3">
                      <span className="text-xs bg-dark-600 text-gray-300 px-2 py-1 rounded">{listener.protocol}</span>
                    </td>
                    <td className="py-3"><span className="badge-green">Ativo</span></td>
                    <td className="py-3">
                      <button
                        onClick={() => handleDeleteListener(listener.id)}
                        className="text-red-400 hover:text-red-300 transition flex items-center gap-1 text-xs"
                      >
                        <Trash2 className="w-4 h-4" />
                        Remover
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Agentes Conectados */}
      <div className="card-dark p-6">
        <div className="mb-4">
          <h2 className="text-2xl font-bold text-gray-100">Agentes Conectados ({beacons.length})</h2>
          <p className="text-gray-400 text-sm mt-1">Computadores comprometidos que estão se comunicando com os servidores de escuta</p>
        </div>

        {beacons.length === 0 ? (
          <div className="text-center py-10 border border-dashed border-dark-600 rounded-lg">
            <Radio className="w-8 h-8 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-500 text-sm">Nenhum agente conectado no momento.</p>
            <p className="text-gray-600 text-xs mt-1">Agentes aparecerão aqui quando se conectarem ao servidor de escuta.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {beacons.map(beacon => (
              <div key={beacon.id} className="bg-dark-700 border border-dark-600 rounded-lg p-4 hover:border-green-600/30 transition">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <h3 className="font-bold text-gray-100">{beacon.hostname || 'Desconhecido'}</h3>
                    <p className="text-xs text-gray-400 font-mono mt-0.5">{beacon.ip}</p>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded ${beacon.status === 'active' ? 'bg-green-900/30 text-green-400' : 'bg-yellow-900/30 text-yellow-400'}`}>
                    {beacon.status === 'active' ? 'Ativo' : 'Inativo'}
                  </span>
                </div>
                <div className="space-y-1 text-xs text-gray-400">
                  <div className="flex gap-2">
                    <span className="text-gray-500 w-24">Usuário:</span>
                    <span className="text-gray-300">{beacon.user || '-'}</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-gray-500 w-24">Último contato:</span>
                    <span className="text-gray-300">{relativeTime(beacon.lastSeen)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Modal Novo Servidor de Escuta */}
      {showNewListener && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 overflow-y-auto">
          <div className="card-dark max-w-md w-full my-auto">
            <div className="flex justify-between items-center p-6 border-b border-dark-600">
              <div>
                <h2 className="text-xl font-bold text-gray-100">Criar Servidor de Escuta</h2>
                <p className="text-xs text-gray-400 mt-1">Configure o servidor que receberá conexões dos agentes</p>
              </div>
              <button onClick={() => setShowNewListener(false)} className="text-gray-400 hover:text-gray-100 transition">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Nome do Servidor
                  <span className="text-gray-500 font-normal ml-1">(para identificação)</span>
                </label>
                <input
                  type="text"
                  value={newListener.name}
                  onChange={(e) => setNewListener({ ...newListener, name: e.target.value })}
                  placeholder="ex: Servidor-Teste-01"
                  className="input-dark w-full"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Endereço IP do Servidor
                </label>
                <input
                  type="text"
                  value={newListener.host}
                  onChange={(e) => setNewListener({ ...newListener, host: e.target.value })}
                  placeholder="ex: 192.168.1.100"
                  className="input-dark w-full"
                />
                <p className="text-xs text-gray-500 mt-1">IP da máquina onde o servidor de escuta vai rodar</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Porta</label>
                  <input
                    type="number"
                    value={newListener.port}
                    onChange={(e) => setNewListener({ ...newListener, port: parseInt(e.target.value) || 443 })}
                    className="input-dark w-full"
                  />
                  <p className="text-xs text-gray-500 mt-1">443 = HTTPS, 80 = HTTP</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Protocolo</label>
                  <select
                    value={newListener.protocol}
                    onChange={(e) => setNewListener({ ...newListener, protocol: e.target.value })}
                    className="select-dark w-full"
                  >
                    <option value="HTTP">HTTP</option>
                    <option value="HTTPS">HTTPS (recomendado)</option>
                    <option value="DNS">DNS</option>
                  </select>
                </div>
              </div>

              {/* Descrição do protocolo selecionado */}
              {PROTOCOL_INFO[newListener.protocol] && (
                <div className="bg-dark-700 border border-dark-600 rounded p-3 flex gap-2">
                  <Info className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
                  <p className="text-xs text-gray-300">{PROTOCOL_INFO[newListener.protocol]}</p>
                </div>
              )}
            </div>
            <div className="flex justify-end gap-2 p-6 border-t border-dark-600">
              <button onClick={() => setShowNewListener(false)} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded transition">
                Cancelar
              </button>
              <button onClick={handleCreateListener} className="btn-blue">
                Criar Servidor
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
