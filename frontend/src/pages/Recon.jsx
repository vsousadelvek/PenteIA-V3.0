import React, { useState } from 'react'
import { Search, AlertTriangle, Loader } from 'lucide-react'

export default function Recon() {
  const [resolveTarget, setResolveTarget] = useState('localhost')
  const [scanTarget, setScanTarget] = useState('localhost')
  const [scanPorts, setScanPorts] = useState('top')
  const [scanTimeout, setScanTimeout] = useState(1.0)
  const [scanWorkers, setScanWorkers] = useState(50)
  const [resolveResult, setResolveResult] = useState(null)
  const [scanResult, setScanResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const resolveDomain = async () => {
    if (!resolveTarget.trim()) {
      alert('Digite um alvo!')
      return
    }
    setLoading(true)
    try {
      const res = await fetch(`/api/recon/resolve?target=${encodeURIComponent(resolveTarget)}`, {
        method: 'POST'
      })
      const data = await res.json()
      setResolveResult(data)
    } catch (err) {
      console.error('Erro:', err)
      alert('Erro ao resolver domínio')
    } finally {
      setLoading(false)
    }
  }

  const scanPorts2 = async () => {
    if (!scanTarget.trim()) {
      alert('Digite um alvo!')
      return
    }
    setLoading(true)
    try {
      const params = new URLSearchParams({
        target: scanTarget,
        ports: scanPorts,
        timeout: scanTimeout,
        workers: scanWorkers
      })
      const res = await fetch(`/api/recon/scan?${params}`, { method: 'POST' })
      const data = await res.json()
      setScanResult(data)
    } catch (err) {
      console.error('Erro:', err)
      alert('Erro ao fazer varredura')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">
          🔍 Reconhecimento
        </h1>
        <p className="text-gray-400">Resolução de domínio e varredura de portas</p>
      </div>

      {/* Alert */}
      <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4 flex gap-3">
        <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-red-400 font-semibold">Apenas testes autorizados</p>
          <p className="text-red-300 text-sm">Use apenas em hosts que você tem permissão explícita para testar.</p>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Resolução de Domínio */}
        <div className="space-y-4">
          <div className="card-dark border-blue-600/30 p-6">
            <h2 className="text-xl font-bold text-gray-100 mb-4">Resolução de Domínio</h2>

            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Alvo (Domínio, URL ou IP)
                </label>
                <input
                  type="text"
                  value={resolveTarget}
                  onChange={(e) => setResolveTarget(e.target.value)}
                  placeholder="exemplo.com.br ou 192.168.1.1"
                  className="input-dark w-full"
                />
              </div>

              <button
                onClick={resolveDomain}
                disabled={loading}
                className="btn-blue w-full flex justify-center items-center gap-2"
              >
                {loading ? (
                  <Loader className="w-4 h-4 animate-spin" />
                ) : (
                  <Search className="w-4 h-4" />
                )}
                {loading ? 'Resolvendo...' : 'Resolver'}
              </button>
            </div>
          </div>

          {/* Resultado */}
          {resolveResult && (
            <div className="card-dark border-blue-600/30 p-6">
              <h3 className="font-semibold text-gray-100 mb-4">Resultado</h3>
              {resolveResult.erro ? (
                <div className="text-red-400 text-sm">{resolveResult.erro}</div>
              ) : (
                <div className="space-y-2 text-sm">
                  <div>
                    <span className="text-gray-400">Host:</span>
                    <span className="text-gray-100 ml-2">{resolveResult.host}</span>
                  </div>
                  {resolveResult.ips && resolveResult.ips.length > 0 && (
                    <div>
                      <span className="text-gray-400">IP(s):</span>
                      <div className="ml-2 mt-1">
                        {resolveResult.ips.map((ip, i) => (
                          <div key={i} className="text-green-400">{ip}</div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Varredura de Portas */}
        <div className="space-y-4">
          <div className="card-dark border-yellow-600/30 p-6">
            <h2 className="text-xl font-bold text-gray-100 mb-4">Varredura de Portas</h2>

            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Alvo (IP ou Domínio)
                </label>
                <input
                  type="text"
                  value={scanTarget}
                  onChange={(e) => setScanTarget(e.target.value)}
                  placeholder="127.0.0.1 ou localhost"
                  className="input-dark w-full"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Portas
                </label>
                <select
                  value={scanPorts}
                  onChange={(e) => setScanPorts(e.target.value)}
                  className="select-dark w-full"
                >
                  <option value="top">Top Portas (23 mais comuns)</option>
                  <option value="1-1024">1-1024</option>
                  <option value="1-65535">Todas (1-65535)</option>
                  <option value="80,443">Web (80, 443)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1">
                    Timeout (s)
                  </label>
                  <input
                    type="number"
                    value={scanTimeout}
                    onChange={(e) => setScanTimeout(parseFloat(e.target.value))}
                    min="0.1"
                    max="10"
                    step="0.1"
                    className="input-dark w-full text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-300 mb-1">
                    Workers
                  </label>
                  <input
                    type="number"
                    value={scanWorkers}
                    onChange={(e) => setScanWorkers(parseInt(e.target.value))}
                    min="1"
                    max="500"
                    className="input-dark w-full text-sm"
                  />
                </div>
              </div>

              <button
                onClick={scanPorts2}
                disabled={loading}
                className="btn-red w-full flex justify-center items-center gap-2"
              >
                {loading ? (
                  <Loader className="w-4 h-4 animate-spin" />
                ) : (
                  <Search className="w-4 h-4" />
                )}
                {loading ? 'Varrendo...' : 'Escanear'}
              </button>
            </div>
          </div>

          {/* Resultado da Varredura */}
          {scanResult && (
            <div className="card-dark border-yellow-600/30 p-6">
              <h3 className="font-semibold text-gray-100 mb-4">Resultado</h3>
              <div className="space-y-3 text-sm">
                <div>
                  <span className="text-gray-400">Alvo:</span>
                  <span className="text-gray-100 ml-2">{scanResult.target}</span>
                </div>
                <div>
                  <span className="text-gray-400">Portas varridas:</span>
                  <span className="text-gray-100 ml-2">{scanResult.ports_scanned}</span>
                </div>
                {scanResult.open_ports && scanResult.open_ports.length > 0 && (
                  <div>
                    <span className="text-gray-400">Portas abertas:</span>
                    <div className="ml-2 mt-2">
                      {scanResult.open_ports.map((item, i) => (
                        <div key={i} className="text-green-400">
                          {item.porta} ({item.servico})
                          {item.banner && <span className="text-gray-500"> - {item.banner}</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {(!scanResult.open_ports || scanResult.open_ports.length === 0) && (
                  <div className="text-blue-400">Nenhuma porta aberta encontrada</div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
