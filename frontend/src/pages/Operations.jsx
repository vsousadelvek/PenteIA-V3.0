import React, { useState, useEffect, useCallback } from 'react'
import { RefreshCw, Trash2, Activity, Info } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

function relativeTime(ts) {
  if (!ts) return ''
  const diff = Date.now() - new Date(ts).getTime()
  if (isNaN(diff)) return new Date(ts).toLocaleString('pt-BR')
  const sec = Math.floor(diff / 1000)
  if (sec < 60) return 'agora mesmo'
  const min = Math.floor(sec / 60)
  if (min < 60) return `há ${min} min`
  const h = Math.floor(min / 60)
  if (h < 24) return `há ${h}h`
  const d = Math.floor(h / 24)
  return `há ${d} dia${d > 1 ? 's' : ''}`
}

const MODULE_LABELS = {
  DDoS:   { label: 'Teste de Sobrecarga', color: 'text-red-400',    bg: 'bg-red-950/30 border-red-800/30' },
  Recon:  { label: 'Reconhecimento',      color: 'text-blue-400',   bg: 'bg-blue-950/30 border-blue-800/30' },
  C2:     { label: 'Controle Remoto',     color: 'text-green-400',  bg: 'bg-green-950/30 border-green-800/30' },
  BAS:    { label: 'Simulação de Ataque', color: 'text-yellow-400', bg: 'bg-yellow-950/20 border-yellow-800/30' },
  SYSTEM: { label: 'Sistema',             color: 'text-gray-400',   bg: 'bg-dark-700 border-dark-600' },
  ERROR:  { label: 'Erro',                color: 'text-red-500',    bg: 'bg-red-950/50 border-red-900/50' },
}

function getModuleInfo(module) {
  return MODULE_LABELS[module] || { label: module, color: 'text-gray-400', bg: 'bg-dark-700 border-dark-600' }
}

const FILTER_OPTIONS = [
  { key: null,     label: 'Todos' },
  { key: 'Recon',  label: 'Reconhecimento' },
  { key: 'DDoS',   label: 'DDoS' },
  { key: 'BAS',    label: 'Simulação' },
  { key: 'C2',     label: 'C2' },
  { key: 'ERROR',  label: 'Erros' },
]

export default function Operations() {
  const toast = useToast()
  const [operations, setOperations] = useState([])
  const [filter, setFilter] = useState(null)

  const fetchOps = useCallback(async () => {
    try {
      const res = await api.get('/api/operations?limit=50')
      if (res.status !== 200) throw new Error('Resposta inválida')
      setOperations(res.data.operations || [])
    } catch (err) {
      console.error('Erro ao buscar operações:', err)
    }
  }, [])

  useEffect(() => {
    fetchOps()
    const interval = setInterval(fetchOps, 5000)
    return () => clearInterval(interval)
  }, [fetchOps])

  const clearLogs = async () => {
    if (!window.confirm('Deseja limpar todo o histórico de operações?')) return
    try {
      await api.post('/api/operations/clear')
      setOperations([])
      toast('Histórico limpo.', 'info')
    } catch (err) {
      toast('Erro ao limpar histórico: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  const filtered = filter ? operations.filter(o => o.module === filter) : operations

  const counts = {
    total: operations.length,
    recon: operations.filter(o => o.module === 'Recon').length,
    ddos: operations.filter(o => o.module === 'DDoS').length,
    bas: operations.filter(o => o.module === 'BAS').length,
    errors: operations.filter(o => o.module === 'ERROR').length,
  }

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">Histórico de Operações</h1>
        <p className="text-gray-400">Registro completo de tudo que foi executado na plataforma</p>
      </div>

      {/* Explicação */}
      <div className="card-dark p-4 border-l-4 border-gray-600 flex gap-3">
        <Info className="w-5 h-5 text-gray-400 flex-shrink-0 mt-0.5" />
        <p className="text-gray-400 text-sm leading-relaxed">
          Cada entrada abaixo representa uma ação executada na plataforma — uma varredura iniciada, um teste concluído, um erro ocorrido, etc.
          O histórico é atualizado automaticamente a cada 5 segundos.
        </p>
      </div>

      {/* Contadores */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card-dark p-5 border-l-4 border-blue-600">
          <p className="text-gray-400 text-xs mb-1">Total de Operações</p>
          <p className="text-3xl font-bold text-gray-100">{counts.total}</p>
        </div>
        <div className="card-dark p-5 border-l-4 border-cyan-600">
          <p className="text-gray-400 text-xs mb-1">Reconhecimento</p>
          <p className="text-3xl font-bold text-gray-100">{counts.recon}</p>
        </div>
        <div className="card-dark p-5 border-l-4 border-red-600">
          <p className="text-gray-400 text-xs mb-1">Testes DDoS</p>
          <p className="text-3xl font-bold text-gray-100">{counts.ddos}</p>
        </div>
        <div className="card-dark p-5 border-l-4 border-orange-600">
          <p className="text-gray-400 text-xs mb-1">Erros Registrados</p>
          <p className="text-3xl font-bold text-gray-100">{counts.errors}</p>
        </div>
      </div>

      {/* Timeline */}
      <div className="card-dark p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-5">
          <div>
            <h2 className="text-2xl font-bold text-gray-100">Linha do Tempo</h2>
            <p className="text-sm text-gray-400 mt-1">Mostrando {filtered.length} de {counts.total} operações</p>
          </div>
          <div className="flex gap-2">
            <button onClick={fetchOps} className="btn-blue flex items-center gap-2 text-sm">
              <RefreshCw className="w-4 h-4" />
              Atualizar
            </button>
            <button onClick={clearLogs} className="btn-outline-red flex items-center gap-2 text-sm">
              <Trash2 className="w-4 h-4" />
              Limpar
            </button>
          </div>
        </div>

        {/* Filtros */}
        <div className="flex flex-wrap gap-2 mb-5">
          {FILTER_OPTIONS.map(({ key, label }) => (
            <button
              key={String(key)}
              onClick={() => setFilter(key)}
              className={`text-xs px-3 py-1.5 rounded-full transition border ${
                filter === key
                  ? 'bg-blue-600 border-blue-500 text-white'
                  : 'bg-dark-700 border-dark-600 text-gray-400 hover:text-gray-100 hover:border-gray-500'
              }`}
            >
              {label}
              {key !== null && (
                <span className="ml-1 opacity-60">({operations.filter(o => o.module === key).length})</span>
              )}
            </button>
          ))}
        </div>

        {filtered.length === 0 ? (
          <div className="text-center py-12 border border-dashed border-dark-600 rounded-lg">
            <Activity className="w-8 h-8 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-400 text-sm">Nenhuma operação registrada ainda.</p>
            <p className="text-gray-600 text-xs mt-1">As operações aparecerão aqui quando você executar testes na plataforma.</p>
          </div>
        ) : (
          <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
            {filtered.map((op, i) => {
              const info = getModuleInfo(op.module)
              return (
                <div key={i} className={`border rounded-lg p-4 text-sm ${info.bg}`}>
                  <div className="flex justify-between items-start gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className={`text-xs font-bold ${info.color}`}>[{info.label}]</span>
                        <span className="font-semibold text-gray-100">{op.action}</span>
                      </div>
                      {op.details && (
                        <p className="text-gray-400 text-xs leading-relaxed">{op.details}</p>
                      )}
                    </div>
                    <div className="text-right flex-shrink-0">
                      <p className="text-xs text-gray-300 whitespace-nowrap">{relativeTime(op.timestamp)}</p>
                      {op.timestamp && (
                        <p className="text-xs text-gray-600 whitespace-nowrap mt-0.5">
                          {new Date(op.timestamp).toLocaleTimeString('pt-BR')}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
