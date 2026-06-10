import React, { useState, useEffect } from 'react'
import { Shield, Zap, Cube, AlertCircle, Activity, Users } from 'lucide-react'
import StatCard from '../components/StatCard'
import ModuleCard from '../components/ModuleCard'

export default function Dashboard() {
  const [stats, setStats] = useState({
    status: 'online',
    modules: 9,
    operations: 0
  })

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch('/api/status')
        const data = await res.json()
        setStats({
          status: data.status,
          modules: Object.keys(data.modules).length,
          operations: data.active_operations
        })
      } catch (err) {
        console.error('Erro ao buscar status:', err)
      }
    }
    fetchStats()
    const interval = setInterval(fetchStats, 10000)
    return () => clearInterval(interval)
  }, [])

  const modules = [
    { name: 'Evasão EDR', icon: Shield, color: 'red', description: 'ROP gadgets, syscalls' },
    { name: 'Evasão de Memória', icon: Zap, color: 'yellow', description: 'Sleep obfuscation' },
    { name: 'Bypass de Telemetria', icon: AlertCircle, color: 'blue', description: 'AMSI, ETW, Sysmon' },
    { name: 'Framework C2', icon: Users, color: 'green', description: 'Beacon management' },
    { name: 'Pós-Exploração', icon: Shield, color: 'purple', description: 'COFF, BOF, .NET' },
    { name: 'Motor BAS', icon: Cube, color: 'orange', description: '40+ técnicas' },
    { name: 'Teste DDoS', icon: Zap, color: 'red', description: '5 métodos de ataque' },
    { name: 'Reconhecimento', icon: Activity, color: 'cyan', description: 'DNS, port scan' },
  ]

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-2">
          Painel <span className="text-red-600">PenteIA v4.0</span>
        </h1>
        <p className="text-gray-400">Plataforma Red Team - Apenas testes autorizados</p>
      </div>

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard
          title="Status do Sistema"
          value={stats.status === 'online' ? '🟢 Online' : '🔴 Offline'}
          icon={Activity}
          color="green"
        />
        <StatCard
          title="Módulos Ativos"
          value={stats.modules}
          icon={Cube}
          color="blue"
        />
        <StatCard
          title="Operações"
          value={stats.operations}
          icon={AlertCircle}
          color="yellow"
        />
      </div>

      {/* Quick Access */}
      <div>
        <h2 className="text-2xl font-bold text-gray-100 mb-4">Acesso Rápido</h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <a href="/recon" className="card-dark p-4 hover:border-red-600 transition group">
            <div className="text-2xl mb-2">🔍</div>
            <h3 className="font-semibold text-gray-100 group-hover:text-red-600">Reconhecimento</h3>
            <p className="text-sm text-gray-400">Resolução e scan</p>
          </a>
          <a href="/ddos" className="card-dark p-4 hover:border-red-600 transition group">
            <div className="text-2xl mb-2">⚡</div>
            <h3 className="font-semibold text-gray-100 group-hover:text-red-600">Teste DDoS</h3>
            <p className="text-sm text-gray-400">5 métodos</p>
          </a>
          <a href="/modules" className="card-dark p-4 hover:border-red-600 transition group">
            <div className="text-2xl mb-2">🧩</div>
            <h3 className="font-semibold text-gray-100 group-hover:text-red-600">Módulos</h3>
            <p className="text-sm text-gray-400">9 disponíveis</p>
          </a>
          <a href="/c2" className="card-dark p-4 hover:border-red-600 transition group">
            <div className="text-2xl mb-2">📡</div>
            <h3 className="font-semibold text-gray-100 group-hover:text-red-600">C2 Beacon</h3>
            <p className="text-sm text-gray-400">Framework C2</p>
          </a>
        </div>
      </div>

      {/* Available Modules */}
      <div>
        <h2 className="text-2xl font-bold text-gray-100 mb-4">Módulos Disponíveis</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {modules.map((module, i) => (
            <ModuleCard key={i} {...module} />
          ))}
        </div>
      </div>

      {/* Alert */}
      <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4">
        <p className="text-red-400 text-sm">
          ⚠️ <strong>Aviso Legal:</strong> Use apenas em ambientes autorizados. Testes sem permissão são ilegais em muitas jurisdições.
        </p>
      </div>
    </div>
  )
}
