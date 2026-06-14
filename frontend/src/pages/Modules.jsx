import React, { useState, useEffect } from 'react'
import { X, Info, CheckCircle, Package } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

const MODULE_DESCRIPTIONS = {
  recon:      'Coleta informações sobre alvos: resolve domínios, varre portas, consulta IPs e tenta descobrir servidores reais por trás de proteções como Cloudflare.',
  ddos:       'Simula ataques de sobrecarga para testar a resiliência de servidores e aplicações a volumes altos de requisições.',
  c2:         'Simula o canal de comunicação usado por invasores para controlar sistemas comprometidos remotamente.',
  bas:        'Executa sequências de ataques baseadas em técnicas reais do framework MITRE ATT&CK para testar a efetividade das defesas.',
  evasion:    'Testa técnicas avançadas para burlar antivírus, EDR e outros sistemas de proteção do endpoint.',
  reporting:  'Gera relatórios automatizados com os resultados dos testes em múltiplos formatos (PDF, DOCX, XLSX).',
  scanner:    'Módulo de análise e varredura inteligente com suporte a modelos de IA para detecção de padrões.',
  payload:    'Gerenciamento de arquivos de teste usados nas simulações de evasão e testes de detecção.',
  operations: 'Registro e monitoramento de todas as operações executadas na plataforma em tempo real.',
}

function getModuleDescription(key) {
  const k = key.toLowerCase().replace(/[^a-z]/g, '')
  for (const [mod, desc] of Object.entries(MODULE_DESCRIPTIONS)) {
    if (k.includes(mod)) return desc
  }
  return 'Componente do sistema de testes de segurança.'
}

export default function Modules() {
  const toast = useToast()
  const [modules, setModules] = useState([])
  const [selectedModule, setSelectedModule] = useState(null)
  const [config, setConfig] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const fetchModules = async () => {
      try {
        const res = await api.get('/api/modules/status')
        setModules(Object.entries(res.data.modules || {}))
      } catch (err) {
        toast('Erro ao carregar módulos', 'error')
        console.error(err)
      }
    }
    fetchModules()
  }, [])

  const openConfig = async (key) => {
    setLoading(true)
    setSelectedModule(key)
    setConfig(null)
    try {
      const res = await api.get(`/api/modules/config/${key}`)
      setConfig(res.data)
    } catch (err) {
      setConfig({ error: 'Não foi possível carregar as informações deste módulo.' })
    } finally {
      setLoading(false)
    }
  }

  const closeModal = () => {
    setSelectedModule(null)
    setConfig(null)
  }

  const selectedModuleData = modules.find(m => m[0] === selectedModule)

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">Módulos do Sistema</h1>
        <p className="text-gray-400">Visão geral de todos os componentes e seus status de funcionamento</p>
      </div>

      <div className="card-dark p-4 border-l-4 border-gray-600 flex gap-3">
        <Info className="w-5 h-5 text-gray-400 flex-shrink-0 mt-0.5" />
        <p className="text-gray-400 text-sm leading-relaxed">
          Esta página mostra todos os componentes instalados na plataforma. Clique em "Ver Detalhes" para ver as funcionalidades de cada módulo.
          Todos os módulos com o selo <span className="text-green-400 font-semibold">Pronto</span> estão operacionais e podem ser usados.
        </p>
      </div>

      {modules.length === 0 ? (
        <div className="text-center py-12">
          <Package className="w-10 h-10 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">Carregando módulos...</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {modules.map(([key, mod]) => (
            <div key={key} className="card-dark p-6 border-l-4 border-red-600/40 hover:border-red-500 transition group">
              <div className="flex items-start justify-between mb-3">
                <h3 className="text-lg font-bold text-gray-100 group-hover:text-red-400 transition">{mod.name}</h3>
                <span className="badge-green flex-shrink-0">Pronto</span>
              </div>
              <p className="text-gray-400 text-sm mb-2 leading-relaxed">{mod.description || getModuleDescription(key)}</p>
              <p className="text-xs text-gray-500 mb-4">{getModuleDescription(key)}</p>
              <button
                onClick={() => openConfig(key)}
                className="text-xs px-3 py-1.5 bg-dark-700 hover:bg-dark-600 text-blue-400 hover:text-blue-300 border border-dark-600 rounded transition font-medium"
              >
                Ver Detalhes
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Modal de Detalhes */}
      {selectedModule && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 overflow-y-auto">
          <div className="card-dark max-w-2xl w-full my-auto">
            <div className="flex justify-between items-center p-6 border-b border-dark-600">
              <div>
                <h2 className="text-xl font-bold text-gray-100">
                  {selectedModuleData?.[1]?.name || selectedModule}
                </h2>
                <p className="text-xs text-gray-400 mt-1">Detalhes e funcionalidades do módulo</p>
              </div>
              <button onClick={closeModal} className="text-gray-400 hover:text-gray-100 transition">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 max-h-[60vh] overflow-y-auto">
              {loading ? (
                <div className="text-center text-gray-400 py-8">Carregando informações...</div>
              ) : config?.error ? (
                <div className="text-red-400 text-sm">{config.error}</div>
              ) : config ? (
                <div className="space-y-5">
                  {/* Info básica */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-3 rounded bg-dark-700 border border-dark-600">
                      <p className="text-xs text-gray-500 mb-1">Nome</p>
                      <p className="text-gray-100 font-semibold text-sm">{config.name}</p>
                    </div>
                    <div className="p-3 rounded bg-dark-700 border border-dark-600">
                      <p className="text-xs text-gray-500 mb-1">Versão</p>
                      <p className="text-gray-100 font-semibold text-sm">{config.version || '—'}</p>
                    </div>
                    <div className="p-3 rounded bg-green-900/20 border border-green-700/40 col-span-2">
                      <div className="flex items-center gap-2">
                        <CheckCircle className="w-4 h-4 text-green-400" />
                        <p className="text-green-400 font-semibold text-sm">Status: Operacional</p>
                      </div>
                    </div>
                  </div>

                  {/* Descrição */}
                  <div>
                    <p className="text-sm font-medium text-gray-300 mb-2">O que este módulo faz?</p>
                    <p className="text-sm text-gray-400 leading-relaxed bg-dark-700 rounded p-3 border border-dark-600">
                      {config.description || getModuleDescription(selectedModule)}
                    </p>
                  </div>

                  {/* Funcionalidades */}
                  {config.features && config.features.length > 0 && (
                    <div>
                      <p className="text-sm font-medium text-gray-300 mb-3">Funcionalidades disponíveis</p>
                      <div className="space-y-2">
                        {config.features.map((feature, i) => (
                          <div key={i} className="flex items-start gap-2 p-2 rounded bg-dark-700 border border-dark-600">
                            <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                            <span className="text-sm text-gray-300">{feature}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : null}
            </div>

            <div className="flex justify-end gap-2 p-6 border-t border-dark-600">
              <button onClick={closeModal} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded transition">
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
