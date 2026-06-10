import React, { useState, useEffect } from 'react'
import { AlertTriangle } from 'lucide-react'

export default function Modules() {
  const [modules, setModules] = useState([])

  useEffect(() => {
    const fetch2 = async () => {
      try {
        const res = await fetch('/api/modules/status')
        const data = await res.json()
        setModules(Object.entries(data.modules || {}))
      } catch (err) {
        console.error('Erro:', err)
      }
    }
    fetch2()
  }, [])

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">🧩 Módulos</h1>
        <p className="text-gray-400">Gerenciamento de módulos PenteIA v4.0</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {modules.map(([key, mod]) => (
          <div key={key} className="card-dark p-6 border-l-4 border-red-600">
            <h3 className="text-lg font-bold text-gray-100 mb-2">{mod.name}</h3>
            <p className="text-gray-400 text-sm mb-3">{mod.description}</p>
            <div className="flex justify-between items-center">
              <span className="badge-green">Pronto</span>
              <button className="text-xs px-3 py-1 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded transition">
                Config
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
