import React, { useState, useEffect } from 'react'
import { Download, Upload, X, Loader, BookOpen, Info, Shield, Eye, EyeOff, Package } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

const CATEGORY_INFO = {
  'EDR Evasion': {
    label: 'Evasão de EDR',
    desc: 'Testa se o sistema de detecção avançada (EDR) consegue identificar técnicas usadas por atacantes reais para burlar proteções.',
    color: 'text-red-400',
    border: 'border-red-600/30',
  },
  'Memory Evasion': {
    label: 'Evasão em Memória',
    desc: 'Verifica se ataques que residem apenas na memória do computador (sem criar arquivos) são detectados pelo antivírus.',
    color: 'text-orange-400',
    border: 'border-orange-600/30',
  },
  'Telemetry Bypass': {
    label: 'Bypass de Telemetria',
    desc: 'Testa técnicas para desabilitar os mecanismos de monitoramento do Windows como AMSI, ETW e Sysmon.',
    color: 'text-yellow-400',
    border: 'border-yellow-600/30',
  },
  'Process Injection': {
    label: 'Injeção em Processos',
    desc: 'Simula ataques que se escondem dentro de processos legítimos do sistema operacional para evitar detecção.',
    color: 'text-purple-400',
    border: 'border-purple-600/30',
  },
}

function getCategoryInfo(category) {
  if (!category) return { label: category, desc: '', color: 'text-gray-400', border: 'border-dark-600' }
  for (const [key, val] of Object.entries(CATEGORY_INFO)) {
    if (category.toLowerCase().includes(key.toLowerCase())) return val
  }
  return { label: category, desc: '', color: 'text-gray-400', border: 'border-dark-600' }
}

function PayloadGenerator() {
  const toast = useToast()
  const [templates, setTemplates] = useState([])
  const [encoder, setEncoder] = useState('xor')
  const [fmt, setFmt] = useState('base64')
  const [xorKey, setXorKey] = useState('')
  const [iterations, setIterations] = useState(1)
  const [result, setResult] = useState(null)
  const [generating, setGenerating] = useState(false)

  useEffect(() => {
    api.get('/api/payload/templates').then(r => setTemplates(r.data.templates || [])).catch(() => {})
  }, [])

  const generate = () => {
    setGenerating(true)
    api.post('/api/payload/generate', {
      payload_type: 'test_eicar',
      encoder,
      output_format: fmt,
      xor_key: xorKey || undefined,
      iterations,
    }).then(r => {
      setResult(r.data)
      toast('Payload gerado com sucesso', 'success')
    }).catch(e => toast(e.response?.data?.detail || 'Erro ao gerar payload', 'error'))
    .finally(() => setGenerating(false))
  }

  const copyStub = () => {
    if (result?.stub) { navigator.clipboard.writeText(result.stub); toast('Copiado!', 'success') }
  }

  return (
    <div className="card-dark p-6">
      <div className="flex items-center gap-2 mb-1">
        <Shield className="w-5 h-5 text-purple-400" />
        <h2 className="text-2xl font-bold text-gray-100">Gerador de Payloads</h2>
      </div>
      <p className="text-gray-400 text-sm mb-5">Gera artefatos de teste codificados (XOR/AES) para validar detecção de EDR/AV. Todos os payloads são inofensivos.</p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Encoder</label>
          <select className="select-dark w-full" value={encoder} onChange={e => setEncoder(e.target.value)}>
            <option value="xor">XOR</option>
            <option value="aes">AES-CBC (simulado)</option>
            <option value="b64_multi">Base64 Multi-layer</option>
            <option value="rot13">ROT13 hex</option>
            <option value="none">Nenhum (raw)</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Formato de saída</label>
          <select className="select-dark w-full" value={fmt} onChange={e => setFmt(e.target.value)}>
            <option value="base64">Base64</option>
            <option value="hex">Hex</option>
            <option value="python">Stub Python</option>
            <option value="powershell">Stub PowerShell</option>
            <option value="csharp">Stub C#</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Iterações (1–5)</label>
          <input type="number" min={1} max={5} className="input-dark w-full" value={iterations} onChange={e => setIterations(Number(e.target.value))} />
        </div>
      </div>
      {encoder === 'xor' && (
        <div className="mb-4">
          <label className="block text-xs text-gray-400 mb-1">XOR Key <span className="text-gray-600">(deixe vazio para gerar aleatória)</span></label>
          <input className="input-dark w-full font-mono" placeholder="ex: mysecretkey" value={xorKey} onChange={e => setXorKey(e.target.value)} />
        </div>
      )}
      <button onClick={generate} disabled={generating} className="btn-blue flex items-center gap-2 disabled:opacity-50">
        {generating ? <Loader className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
        {generating ? 'Gerando...' : 'Gerar Payload'}
      </button>
      {result && (
        <div className="mt-5 space-y-3">
          <div className="grid grid-cols-3 gap-3 text-xs">
            <div className="card-dark p-3"><p className="text-gray-500">Encoder</p><p className="text-gray-100 font-mono">{result.encoder}</p></div>
            <div className="card-dark p-3"><p className="text-gray-500">Tamanho</p><p className="text-gray-100 font-mono">{result.size_bytes}B</p></div>
            <div className="card-dark p-3"><p className="text-gray-500">SHA-256</p><p className="text-gray-100 font-mono truncate">{result.hash_sha256?.slice(0,16)}...</p></div>
          </div>
          {result.key_info && (
            <div className="bg-dark-700 rounded p-3 text-xs font-mono text-gray-300">
              <p className="text-gray-500 mb-1">Key info:</p>
              {Object.entries(result.key_info).map(([k, v]) => <p key={k}><span className="text-gray-500">{k}:</span> {String(v)}</p>)}
            </div>
          )}
          <div className="relative">
            <pre className="bg-dark-900 border border-dark-600 rounded p-3 text-xs text-green-300 font-mono overflow-x-auto max-h-48 overflow-y-auto">
              {result.stub || result.payload_b64}
            </pre>
            <button onClick={copyStub} className="absolute top-2 right-2 text-[10px] px-2 py-1 bg-dark-700 hover:bg-dark-600 text-gray-400 rounded">
              Copiar
            </button>
          </div>
          <p className="text-[10px] text-gray-600 italic">{result.note}</p>
        </div>
      )}
    </div>
  )
}

export default function Evasion() {
  const toast = useToast()
  const [techniques, setTechniques] = useState([])
  const [payloads, setPayloads] = useState([])
  const [showUploadModal, setShowUploadModal] = useState(false)
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [uploadFile, setUploadFile] = useState(null)
  const [uploadName, setUploadName] = useState('')
  const [expandedTech, setExpandedTech] = useState(null)

  useEffect(() => {
    fetchTechniques()
    fetchPayloads()
  }, [])

  const fetchTechniques = async () => {
    try {
      const res = await api.get('/api/evasion/techniques')
      setTechniques(res.data.techniques || [])
    } catch (err) {
      console.error('Erro ao buscar técnicas:', err)
    } finally {
      setLoading(false)
    }
  }

  const fetchPayloads = async () => {
    try {
      const res = await api.get('/api/evasion/payloads')
      setPayloads(res.data.payloads || [])
    } catch (err) {
      console.error('Erro ao buscar payloads:', err)
    }
  }

  const handleUploadPayload = async () => {
    if (!uploadFile || !uploadName.trim()) {
      toast('Selecione um arquivo e dê um nome a ele', 'warning')
      return
    }

    const formData = new FormData()
    formData.append('file', uploadFile)
    formData.append('name', uploadName)
    formData.append('payload_type', uploadFile.name.split('.').pop() || 'bin')

    setUploading(true)
    try {
      await api.post('/api/evasion/payloads', formData, {
        params: { name: uploadName, payload_type: uploadFile.name.split('.').pop() || 'bin' },
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      setUploadFile(null)
      setUploadName('')
      setShowUploadModal(false)
      await fetchPayloads()
      toast('Arquivo enviado com sucesso!', 'success')
    } catch (err) {
      toast('Erro ao enviar arquivo: ' + (err.response?.data?.detail || err.message), 'error')
    } finally {
      setUploading(false)
    }
  }

  const handleDownloadPayload = async (payloadId) => {
    try {
      const res = await api.get(`/api/evasion/payloads/${payloadId}/download`, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `payload-${payloadId}`)
      document.body.appendChild(link)
      link.click()
      link.parentNode.removeChild(link)
      window.URL.revokeObjectURL(url)
    } catch (err) {
      toast('Erro ao baixar arquivo: ' + (err.response?.data?.detail || err.message), 'error')
    }
  }

  const closeUploadModal = () => {
    if (!uploading) {
      setShowUploadModal(false)
      setUploadFile(null)
      setUploadName('')
    }
  }

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">Evasão de Defesas</h1>
        <p className="text-gray-400">Testa se o antivírus e sistemas de proteção conseguem detectar técnicas avançadas de ataque</p>
      </div>

      {/* O que é Evasão */}
      <div className="card-dark p-6 bg-purple-900/10 border-l-4 border-purple-600">
        <div className="flex items-center gap-2 mb-3">
          <BookOpen className="w-5 h-5 text-purple-400" />
          <h2 className="text-lg font-bold text-gray-100">O que é Evasão de Defesas?</h2>
        </div>
        <p className="text-gray-300 text-sm mb-4 leading-relaxed">
          Hackers reais usam técnicas especiais para <strong>passar pelo antivírus sem serem detectados</strong>.
          Este módulo testa exatamente isso: ele executa essas mesmas técnicas no ambiente alvo e verifica quais são detectadas
          e quais passam despercebidas. Se uma técnica <strong>não</strong> é detectada, isso indica uma falha nas defesas que precisa ser corrigida.
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Object.values(CATEGORY_INFO).map(({ label, color }) => (
            <div key={label} className="text-center p-2 rounded bg-dark-700 border border-dark-600">
              <Shield className={`w-5 h-5 ${color} mx-auto mb-1`} />
              <span className="text-xs text-gray-300">{label}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4">
        <p className="text-red-400 text-sm">
          <strong>Aviso Legal:</strong> Use apenas em sistemas de teste autorizados. As técnicas testadas aqui são idênticas às usadas por atacantes reais.
        </p>
      </div>

      {/* Técnicas Disponíveis */}
      <div className="card-dark p-6">
        <h2 className="text-2xl font-bold text-gray-100 mb-2">Técnicas de Evasão Disponíveis ({techniques.length})</h2>
        <p className="text-gray-400 text-sm mb-5">
          Cada categoria agrupa técnicas relacionadas. Clique em uma categoria para ver os detalhes das técnicas disponíveis.
        </p>
        {loading ? (
          <p className="text-gray-400">Carregando técnicas...</p>
        ) : techniques.length === 0 ? (
          <p className="text-gray-500 text-sm">Nenhuma técnica disponível no momento.</p>
        ) : (
          <div className="space-y-4">
            {techniques.map(tech => {
              const catInfo = getCategoryInfo(tech.category)
              const isExpanded = expandedTech === tech.id
              return (
                <div key={tech.id} className={`bg-dark-700 border rounded-lg overflow-hidden transition ${catInfo.border}`}>
                  <button
                    onClick={() => setExpandedTech(isExpanded ? null : tech.id)}
                    className="w-full p-4 text-left hover:bg-dark-600/50 transition"
                  >
                    <div className="flex justify-between items-start">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-1">
                          <h3 className="font-bold text-gray-100">{tech.name}</h3>
                          <span className="badge-green text-xs">Pronto</span>
                        </div>
                        <p className={`text-xs font-semibold ${catInfo.color}`}>{catInfo.label || tech.category}</p>
                        {catInfo.desc && (
                          <p className="text-xs text-gray-400 mt-1 leading-relaxed">{catInfo.desc}</p>
                        )}
                      </div>
                      <div className="flex items-center gap-2 ml-4">
                        {tech.techniques?.length > 0 && (
                          <span className="text-xs text-gray-500">{tech.techniques.length} técnicas</span>
                        )}
                        {isExpanded ? (
                          <EyeOff className="w-4 h-4 text-gray-400" />
                        ) : (
                          <Eye className="w-4 h-4 text-gray-400" />
                        )}
                      </div>
                    </div>
                  </button>

                  {isExpanded && tech.techniques?.length > 0 && (
                    <div className="px-4 pb-4 border-t border-dark-600 pt-3">
                      <p className="text-xs text-gray-500 mb-2">Técnicas específicas nesta categoria:</p>
                      <div className="space-y-2">
                        {tech.techniques.map((t, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs p-2 rounded bg-dark-800 border border-dark-700">
                            <span className="w-2 h-2 rounded-full bg-purple-500 mt-1 flex-shrink-0" />
                            <div>
                              <span className="text-gray-200 font-medium">{t}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                      <div className="mt-3 p-2 rounded bg-blue-900/20 border border-blue-700/30">
                        <p className="text-xs text-blue-300 flex gap-2">
                          <Info className="w-3 h-3 flex-shrink-0 mt-0.5" />
                          <span>Estas técnicas são executadas automaticamente quando você inicia uma simulação BAS com foco em evasão.</span>
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Payload Generator */}
      <PayloadGenerator />

      {/* Arquivos de Teste (Payloads) */}
      <div className="card-dark p-6">
        <div className="flex justify-between items-center mb-2">
          <div>
            <h2 className="text-2xl font-bold text-gray-100">Arquivos de Teste ({payloads.length})</h2>
            <p className="text-gray-400 text-sm mt-1">
              <strong className="text-gray-300">Arquivos de teste</strong> são executáveis usados para verificar se o antivírus detecta ameaças.
              Faça upload de amostras de teste (EICAR, stubs, etc.) — nunca malware real.
            </p>
          </div>
          <button onClick={() => setShowUploadModal(true)} className="btn-blue flex items-center gap-2 flex-shrink-0">
            <Upload className="w-4 h-4" />
            Enviar Arquivo
          </button>
        </div>

        <div className="mt-4 bg-yellow-900/20 border border-yellow-700/40 rounded p-3 mb-4 flex gap-2">
          <Info className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-yellow-300">
            <strong>O que enviar?</strong> Envie apenas arquivos de teste legítimos (ex: EICAR test file) ou stubs inofensivos criados para validar a detecção.
            Nunca faça upload de malware real ou código malicioso funcional.
          </p>
        </div>

        {payloads.length === 0 ? (
          <div className="text-center py-8 border border-dashed border-dark-600 rounded-lg">
            <p className="text-gray-500 text-sm">Nenhum arquivo de teste enviado ainda.</p>
            <p className="text-gray-600 text-xs mt-1">Clique em "Enviar Arquivo" para adicionar arquivos de teste.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-600">
                  <th className="text-left py-3 text-gray-400 font-semibold">Nome do Arquivo</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Tipo</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Tamanho</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Data de Upload</th>
                  <th className="text-left py-3 text-gray-400 font-semibold">Ação</th>
                </tr>
              </thead>
              <tbody>
                {payloads.map(payload => (
                  <tr key={payload.id} className="border-b border-dark-700 hover:bg-dark-700 transition">
                    <td className="py-3 text-gray-100 font-medium">{payload.name}</td>
                    <td className="py-3">
                      <span className="text-xs bg-dark-600 text-gray-300 px-2 py-1 rounded font-mono">{payload.type}</span>
                    </td>
                    <td className="py-3 text-gray-300">{payload.size}</td>
                    <td className="py-3 text-gray-400">{payload.created_at ? new Date(payload.created_at).toLocaleDateString('pt-BR') : '-'}</td>
                    <td className="py-3">
                      <button
                        onClick={() => handleDownloadPayload(payload.id)}
                        className="text-blue-400 hover:text-blue-300 transition flex items-center gap-1 text-xs"
                      >
                        <Download className="w-4 h-4" />
                        Baixar
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal Upload */}
      {showUploadModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 overflow-y-auto">
          <div className="card-dark max-w-md w-full my-auto">
            <div className="flex justify-between items-center p-6 border-b border-dark-600">
              <div>
                <h2 className="text-xl font-bold text-gray-100">Enviar Arquivo de Teste</h2>
                <p className="text-xs text-gray-400 mt-1">Adicione um arquivo executável para testes de evasão</p>
              </div>
              <button onClick={closeUploadModal} disabled={uploading} className="text-gray-400 hover:text-gray-100 transition disabled:opacity-50">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div className="bg-yellow-900/20 border border-yellow-700/40 rounded p-3 flex gap-2">
                <Info className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
                <p className="text-xs text-yellow-300">Envie apenas arquivos de teste — nunca malware real ou código malicioso funcional.</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Nome do Arquivo de Teste
                  <span className="text-gray-500 font-normal ml-1">(para identificação)</span>
                </label>
                <input
                  type="text"
                  value={uploadName}
                  onChange={(e) => setUploadName(e.target.value)}
                  placeholder="ex: EICAR Test File v1"
                  className="input-dark w-full"
                  disabled={uploading}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Selecione o Arquivo
                </label>
                <input
                  type="file"
                  onChange={(e) => setUploadFile(e.target.files[0])}
                  className="input-dark w-full"
                  disabled={uploading}
                />
                {uploadFile && (
                  <p className="text-xs text-gray-400 mt-2">
                    Arquivo selecionado: <span className="text-gray-300">{uploadFile.name}</span> ({(uploadFile.size / 1024).toFixed(2)} KB)
                  </p>
                )}
              </div>
            </div>
            <div className="flex justify-end gap-2 p-6 border-t border-dark-600">
              <button onClick={closeUploadModal} disabled={uploading} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded transition disabled:opacity-50">
                Cancelar
              </button>
              <button onClick={handleUploadPayload} disabled={uploading} className="btn-blue flex items-center gap-2 disabled:opacity-50">
                {uploading ? <><Loader className="w-4 h-4 animate-spin" /> Enviando...</> : <><Upload className="w-4 h-4" /> Enviar</>}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
