import React from 'react'
import { AlertTriangle, Zap } from 'lucide-react'

export default function DDoS() {
  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">
          ⚡ Teste DDoS
        </h1>
        <p className="text-gray-400">Teste de resiliência contra ataques DDoS</p>
      </div>

      <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4 flex gap-3">
        <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-red-400 font-semibold">Apenas localhost e IPs privados</p>
          <p className="text-red-300 text-sm">Testes DDoS sem autorização são ilegais. Use apenas em ambientes controlados.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="card-dark p-6">
          <h2 className="text-xl font-bold text-gray-100 mb-4">Métodos Disponíveis</h2>
          <div className="space-y-2">
            {['SYN Flood', 'UDP Flood', 'HTTP Flood', 'Slowloris', 'DNS Amplification'].map(method => (
              <div key={method} className="flex items-center gap-2 p-3 bg-dark-700 rounded">
                <Zap className="w-4 h-4 text-red-600" />
                <span className="text-gray-100">{method}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card-dark p-6">
          <h2 className="text-xl font-bold text-gray-100 mb-4">Configuração</h2>
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Host Alvo
              </label>
              <input type="text" placeholder="127.0.0.1" className="input-dark w-full" />
            </div>
            <button className="btn-red w-full">Iniciar Teste</button>
          </div>
        </div>
      </div>
    </div>
  )
}
