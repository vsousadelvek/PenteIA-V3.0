import React, { useState, useEffect, useCallback } from 'react'
import {
  Key, Plus, Trash2, Eye, EyeOff, Copy, RefreshCw, Shield, AlertTriangle
} from 'lucide-react'
import api from '../api'
import { useToast } from '../components/Toast'

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('pt-BR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function CopyButton({ text, label = '' }) {
  const toast = useToast()
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      toast(label ? `${label} copiado!` : 'Copiado!', 'success')
      setTimeout(() => setCopied(false), 2000)
    } catch {
      toast('Erro ao copiar', 'error')
    }
  }

  return (
    <button
      onClick={handleCopy}
      title="Copiar"
      className="p-1.5 rounded text-gray-400 hover:text-gray-100 hover:bg-dark-700 transition-colors"
    >
      <Copy className={`w-4 h-4 ${copied ? 'text-green-400' : ''}`} />
    </button>
  )
}

function NewKeyBanner({ keyValue, onDismiss }) {
  const toast = useToast()

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(keyValue)
      toast('Chave copiada!', 'success')
    } catch {
      toast('Erro ao copiar', 'error')
    }
  }

  return (
    <div className="border border-yellow-500/60 bg-yellow-900/20 rounded-lg p-4 space-y-3">
      <div className="flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <p className="text-yellow-300 font-semibold text-sm">
            Salve esta chave agora — ela nao sera exibida novamente
          </p>
          <p className="text-yellow-400/80 text-xs mt-0.5">
            Copie e armazene em local seguro antes de fechar esta janela.
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2 bg-dark-800 border border-yellow-600/30 rounded-lg px-3 py-2.5">
        <code className="text-yellow-300 text-sm font-mono flex-1 break-all select-all">
          {keyValue}
        </code>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-yellow-600 hover:bg-yellow-500 text-yellow-100 rounded text-xs font-medium transition-colors flex-shrink-0"
        >
          <Copy className="w-3.5 h-3.5" />
          Copiar
        </button>
      </div>
      <div className="flex justify-end">
        <button
          onClick={onDismiss}
          className="text-xs text-gray-400 hover:text-gray-200 transition-colors underline underline-offset-2"
        >
          Ja salvei, fechar aviso
        </button>
      </div>
    </div>
  )
}

function CreateKeyModal({ onClose, onCreated }) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [loading, setLoading] = useState(false)
  const [newKey, setNewKey] = useState(null)

  const handleCreate = async () => {
    if (!name.trim()) {
      toast('Informe um nome para a chave', 'warning')
      return
    }
    setLoading(true)
    try {
      const r = await api.post('/api/keys', { name: name.trim() })
      setNewKey(r.data)
      onCreated()
      toast('API Key criada com sucesso!', 'success')
    } catch (err) {
      toast('Erro: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !newKey) handleCreate()
    if (e.key === 'Escape') onClose()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-dark-800 border border-dark-600 rounded-xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-dark-600">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-blue-900/30 border border-blue-700/50 rounded-lg flex items-center justify-center">
              <Key className="w-4.5 h-4.5 text-blue-400" />
            </div>
            <h2 className="text-gray-100 font-semibold">Gerar Nova API Key</h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-100 transition-colors p-1 rounded"
          >
            <span className="sr-only">Fechar</span>
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-5 space-y-4">
          {!newKey ? (
            <>
              <div>
                <label className="block text-sm text-gray-400 mb-1.5">
                  Nome da chave <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  className="input-dark w-full"
                  placeholder="Ex: CI/CD Pipeline, SOAR Integration, Automacao"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  onKeyDown={handleKeyDown}
                  autoFocus
                  disabled={loading}
                />
                <p className="text-xs text-gray-500 mt-1.5">
                  Escolha um nome descritivo para identificar onde a chave sera usada.
                </p>
              </div>

              <div className="flex gap-3 pt-1">
                <button
                  onClick={onClose}
                  disabled={loading}
                  className="flex-1 px-4 py-2 rounded-lg border border-dark-600 text-gray-400 hover:text-gray-200 hover:border-dark-500 transition-colors text-sm"
                >
                  Cancelar
                </button>
                <button
                  onClick={handleCreate}
                  disabled={loading || !name.trim()}
                  className="flex-1 px-4 py-2 rounded-lg bg-blue-700 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium text-sm transition-colors flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Gerando...
                    </>
                  ) : (
                    <>
                      <Plus className="w-4 h-4" />
                      Gerar Chave
                    </>
                  )}
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="space-y-1">
                <p className="text-sm text-gray-300">
                  Chave criada: <span className="text-gray-100 font-medium">{newKey.name}</span>
                </p>
              </div>

              <NewKeyBanner
                keyValue={newKey.key}
                onDismiss={onClose}
              />

              <button
                onClick={onClose}
                className="w-full px-4 py-2 rounded-lg bg-dark-700 hover:bg-dark-600 text-gray-300 hover:text-gray-100 text-sm transition-colors border border-dark-600"
              >
                Fechar
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function DeleteConfirmModal({ keyItem, onClose, onConfirm, loading }) {
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-dark-800 border border-dark-600 rounded-xl w-full max-w-md shadow-2xl">
        <div className="p-6 space-y-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-red-900/30 border border-red-700/50 rounded-lg flex items-center justify-center flex-shrink-0">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h2 className="text-gray-100 font-semibold">Excluir API Key</h2>
              <p className="text-gray-400 text-sm">Esta acao nao pode ser desfeita</p>
            </div>
          </div>

          <div className="bg-dark-700 border border-dark-600 rounded-lg p-3">
            <p className="text-gray-300 text-sm">
              Voce esta prestes a excluir a chave{' '}
              <span className="text-gray-100 font-semibold">"{keyItem.name}"</span>
              {' '}(<code className="text-gray-400 text-xs">{keyItem.prefix}...</code>).
            </p>
            <p className="text-gray-400 text-xs mt-1.5">
              Qualquer servico usando esta chave perdera acesso imediatamente.
            </p>
          </div>

          <div className="flex gap-3">
            <button
              onClick={onClose}
              disabled={loading}
              className="flex-1 px-4 py-2 rounded-lg border border-dark-600 text-gray-400 hover:text-gray-200 hover:border-dark-500 transition-colors text-sm"
            >
              Cancelar
            </button>
            <button
              onClick={onConfirm}
              disabled={loading}
              className="flex-1 px-4 py-2 rounded-lg bg-red-700 hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium text-sm transition-colors flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Excluindo...
                </>
              ) : (
                <>
                  <Trash2 className="w-4 h-4" />
                  Excluir Chave
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function EmptyState({ onNew }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-16 h-16 bg-dark-700 border border-dark-600 rounded-2xl flex items-center justify-center mb-4">
        <Key className="w-8 h-8 text-gray-600" />
      </div>
      <h3 className="text-gray-300 font-semibold text-lg mb-2">Nenhuma API key criada</h3>
      <p className="text-gray-500 text-sm max-w-xs mb-6">
        Crie uma API key para integrar o PenteIA com pipelines CI/CD, plataformas SOAR e scripts de automacao.
      </p>
      <button
        onClick={onNew}
        className="flex items-center gap-2 px-4 py-2 bg-blue-700 hover:bg-blue-600 text-white rounded-lg text-sm font-medium transition-colors"
      >
        <Plus className="w-4 h-4" />
        Gerar Primeira API Key
      </button>
    </div>
  )
}

export default function ApiKeys() {
  const toast = useToast()
  const [keys, setKeys] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [deleting, setDeleting] = useState(false)
  const [showPrefixes, setShowPrefixes] = useState({})

  const fetchKeys = useCallback(async () => {
    try {
      const r = await api.get('/api/keys')
      setKeys(Array.isArray(r.data) ? r.data : (r.data?.keys || []))
    } catch (err) {
      toast('Erro ao carregar API keys: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => {
    fetchKeys()
  }, [fetchKeys])

  const handleDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await api.delete(`/api/keys/${deleteTarget.id}`)
      setKeys(prev => prev.filter(k => k.id !== deleteTarget.id))
      toast(`Chave "${deleteTarget.name}" excluida com sucesso`, 'success')
      setDeleteTarget(null)
    } catch (err) {
      toast('Erro ao excluir: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setDeleting(false)
    }
  }

  const togglePrefix = (id) => {
    setShowPrefixes(prev => ({ ...prev, [id]: !prev[id] }))
  }

  return (
    <div className="space-y-6 p-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2.5">
            <Key className="w-6 h-6 text-blue-400" />
            API Keys
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Acesso programatico ao PenteIA para integracao com SOAR e automacao
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-700 hover:bg-blue-600 text-white rounded-lg text-sm font-medium transition-colors flex-shrink-0 shadow-lg"
        >
          <Plus className="w-4 h-4" />
          Gerar Nova API Key
        </button>
      </div>

      {/* Code example */}
      <div className="card-dark p-4 space-y-3">
        <div className="flex items-center gap-2 text-gray-300 text-sm font-medium">
          <Shield className="w-4 h-4 text-blue-400" />
          Exemplo de uso
        </div>
        <div className="bg-dark-800 border border-dark-600 rounded-lg p-3 flex items-start gap-3">
          <div className="flex-1 min-w-0 overflow-x-auto">
            <code className="text-green-400 text-sm font-mono whitespace-nowrap">
              curl -H <span className="text-yellow-300">"X-API-Key: pk_live_..."</span>{' '}
              <span className="text-blue-300">https://your-domain/api/bas/simulations</span>
            </code>
          </div>
          <CopyButton
            text={'curl -H "X-API-Key: pk_live_..." https://your-domain/api/bas/simulations'}
            label="Comando"
          />
        </div>
        <p className="text-gray-500 text-xs">
          Substitua <code className="text-gray-400">pk_live_...</code> pela sua chave gerada abaixo.
          O header <code className="text-gray-400">X-API-Key</code> e obrigatorio em todas as requisicoes.
        </p>
      </div>

      {/* Rate limit info */}
      <div className="flex items-start gap-3 bg-blue-900/15 border border-blue-700/30 rounded-lg px-4 py-3">
        <Shield className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
        <div className="text-sm">
          <span className="text-blue-300 font-medium">Rate limit:</span>{' '}
          <span className="text-gray-400">
            1000 requests/hora por key. Autenticacao via header{' '}
            <code className="text-gray-300">X-API-Key</code>.
            Exceder o limite retorna HTTP 429.
          </span>
        </div>
      </div>

      {/* Keys list */}
      <div className="card-dark overflow-hidden">
        <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between">
          <h2 className="text-gray-100 font-semibold">
            Chaves ativas
            {!loading && (
              <span className="ml-2 text-xs font-normal text-gray-500">
                ({keys.length} {keys.length === 1 ? 'chave' : 'chaves'})
              </span>
            )}
          </h2>
          <button
            onClick={fetchKeys}
            disabled={loading}
            className="p-1.5 text-gray-400 hover:text-gray-100 hover:bg-dark-700 rounded transition-colors disabled:opacity-50"
            title="Atualizar"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-16">
            <div className="flex items-center gap-3 text-gray-400">
              <RefreshCw className="w-5 h-5 animate-spin" />
              <span className="text-sm">Carregando chaves...</span>
            </div>
          </div>
        ) : keys.length === 0 ? (
          <EmptyState onNew={() => setShowCreateModal(true)} />
        ) : (
          <>
            {/* Table header — desktop */}
            <div className="hidden md:grid grid-cols-[2fr_1.5fr_1fr_1.5fr_1fr_auto] gap-4 px-5 py-2.5 text-xs text-gray-500 uppercase tracking-wide border-b border-dark-600 bg-dark-800/50">
              <span>Nome</span>
              <span>Prefixo</span>
              <span>Status</span>
              <span>Ultimo uso</span>
              <span>Requests</span>
              <span>Acoes</span>
            </div>

            <div className="divide-y divide-dark-600">
              {keys.map(k => (
                <div
                  key={k.id}
                  className="px-5 py-4 hover:bg-dark-700/40 transition-colors"
                >
                  {/* Desktop row */}
                  <div className="hidden md:grid grid-cols-[2fr_1.5fr_1fr_1.5fr_1fr_auto] gap-4 items-center">
                    {/* Name */}
                    <div className="flex items-center gap-2 min-w-0">
                      <Key className="w-4 h-4 text-gray-500 flex-shrink-0" />
                      <span className="text-gray-100 text-sm font-medium truncate">{k.name}</span>
                    </div>

                    {/* Prefix */}
                    <div className="flex items-center gap-1.5 min-w-0">
                      <code className="text-gray-300 text-xs font-mono truncate">
                        {showPrefixes[k.id] ? k.prefix : k.prefix?.slice(0, 12) + '...'}
                      </code>
                      <button
                        onClick={() => togglePrefix(k.id)}
                        className="p-1 text-gray-500 hover:text-gray-300 transition-colors flex-shrink-0"
                        title={showPrefixes[k.id] ? 'Ocultar' : 'Mostrar'}
                      >
                        {showPrefixes[k.id]
                          ? <EyeOff className="w-3.5 h-3.5" />
                          : <Eye className="w-3.5 h-3.5" />
                        }
                      </button>
                      <CopyButton text={k.prefix} label="Prefixo" />
                    </div>

                    {/* Status */}
                    <div>
                      {k.enabled !== false ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-green-900/30 border border-green-700/40 text-green-400">
                          <span className="w-1.5 h-1.5 rounded-full bg-green-400 inline-block" />
                          Ativo
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-gray-800 border border-gray-700 text-gray-400">
                          <span className="w-1.5 h-1.5 rounded-full bg-gray-500 inline-block" />
                          Inativo
                        </span>
                      )}
                    </div>

                    {/* Last used */}
                    <span className="text-gray-400 text-xs">
                      {k.last_used ? formatDate(k.last_used) : 'Nunca usado'}
                    </span>

                    {/* Requests */}
                    <span className="text-gray-300 text-sm font-medium">
                      {(k.requests_count || 0).toLocaleString('pt-BR')}
                    </span>

                    {/* Actions */}
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => setDeleteTarget(k)}
                        className="p-1.5 rounded text-gray-500 hover:text-red-400 hover:bg-red-900/20 transition-colors"
                        title="Excluir chave"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {/* Mobile row */}
                  <div className="md:hidden space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Key className="w-4 h-4 text-gray-500" />
                        <span className="text-gray-100 text-sm font-medium">{k.name}</span>
                      </div>
                      {k.enabled !== false ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-green-900/30 border border-green-700/40 text-green-400">
                          Ativo
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-gray-800 border border-gray-700 text-gray-400">
                          Inativo
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <code className="text-gray-400 text-xs font-mono">
                        {k.prefix}...
                      </code>
                      <CopyButton text={k.prefix} label="Prefixo" />
                    </div>
                    <div className="flex items-center justify-between text-xs text-gray-500">
                      <span>Ultimo uso: {k.last_used ? formatDate(k.last_used) : 'Nunca'}</span>
                      <span>{(k.requests_count || 0).toLocaleString('pt-BR')} requests</span>
                    </div>
                    <div className="flex justify-end">
                      <button
                        onClick={() => setDeleteTarget(k)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded text-red-400 hover:bg-red-900/20 border border-red-700/30 text-xs transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        Excluir
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* Modals */}
      {showCreateModal && (
        <CreateKeyModal
          onClose={() => setShowCreateModal(false)}
          onCreated={fetchKeys}
        />
      )}

      {deleteTarget && (
        <DeleteConfirmModal
          keyItem={deleteTarget}
          onClose={() => setDeleteTarget(null)}
          onConfirm={handleDelete}
          loading={deleting}
        />
      )}
    </div>
  )
}
