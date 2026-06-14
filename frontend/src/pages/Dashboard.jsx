import React, { useState, useEffect } from 'react'
import { Shield, Zap, AlertCircle, Activity, Users, Compass, BookOpen, Search, BarChart2, Lock, Eye, FileText } from 'lucide-react'
import StatCard from '../components/StatCard'
import api from '../api'

const MODULE_INFO = [
  {
    name: 'Reconhecimento',
    icon: Search,
    color: 'cyan',
    href: '/recon',
    tip: 'Comece aqui',
    description: 'Descobre informações sobre o alvo: endereços IP, quais portas estão abertas, que serviços estão rodando e se o site usa proteção CDN ou Cloudflare.',
  },
  {
    name: 'Teste de Sobrecarga (DDoS)',
    icon: Zap,
    color: 'red',
    href: '/ddos',
    tip: '6 métodos',
    description: 'Simula ataques de sobrecarga para verificar se o servidor aguenta um grande volume de requisições simultâneas sem cair ou degradar.',
  },
  {
    name: 'Simulação de Ataques (BAS)',
    icon: Compass,
    color: 'orange',
    href: '/bas',
    tip: '40+ técnicas',
    description: 'Executa sequências de ataques reais de forma controlada para testar se as defesas conseguem detectar e bloquear invasões automaticamente.',
  },
  {
    name: 'Controle Remoto (C2)',
    icon: Users,
    color: 'green',
    href: '/c2',
    tip: 'Framework C2',
    description: 'Simula como um invasor controlaria computadores comprometidos à distância. Testa se as defesas detectam esse tipo de comunicação maliciosa.',
  },
  {
    name: 'Evasão de Defesas',
    icon: Shield,
    color: 'purple',
    href: '/evasion',
    tip: 'Anti-AV / EDR',
    description: 'Testa se o antivírus e sistema de proteção (EDR) do alvo consegue detectar e bloquear técnicas avançadas usadas por atacantes reais.',
  },
  {
    name: 'Relatórios',
    icon: FileText,
    color: 'blue',
    href: '/reporting',
    tip: 'PDF, DOCX',
    description: 'Gera relatórios formatados com os resultados dos testes para apresentar às equipes de TI, segurança e gestores da empresa.',
  },
  {
    name: 'Histórico de Operações',
    icon: Activity,
    color: 'yellow',
    href: '/operations',
    tip: 'Log completo',
    description: 'Mostra tudo que foi executado na plataforma: cada varredura, teste e simulação fica registrado com data, hora e resultado.',
  },
  {
    name: 'Módulos do Sistema',
    icon: Eye,
    color: 'gray',
    href: '/modules',
    tip: 'Status',
    description: 'Visão geral de todos os componentes disponíveis na plataforma e seus status de funcionamento atual.',
  },
]

const COLOR_MAP = {
  cyan:   { border: 'border-l-4 border-cyan-600/40',   text: 'text-cyan-400',   hover: 'hover:border-cyan-500' },
  red:    { border: 'border-l-4 border-red-600/40',    text: 'text-red-400',    hover: 'hover:border-red-500' },
  orange: { border: 'border-l-4 border-orange-600/40', text: 'text-orange-400', hover: 'hover:border-orange-500' },
  green:  { border: 'border-l-4 border-green-600/40',  text: 'text-green-400',  hover: 'hover:border-green-500' },
  purple: { border: 'border-l-4 border-purple-600/40', text: 'text-purple-400', hover: 'hover:border-purple-500' },
  blue:   { border: 'border-l-4 border-blue-600/40',   text: 'text-blue-400',   hover: 'hover:border-blue-500' },
  yellow: { border: 'border-l-4 border-yellow-600/40', text: 'text-yellow-400', hover: 'hover:border-yellow-500' },
  gray:   { border: 'border-l-4 border-gray-600/40',   text: 'text-gray-400',   hover: 'hover:border-gray-500' },
}

export default function Dashboard() {
  const [stats, setStats] = useState({ status: 'online', modules: 9, operations: 0 })
  const username = localStorage.getItem('username') || 'Pesquisador'

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await api.get('/api/status')
        setStats({
          status: res.data.status,
          modules: Object.keys(res.data.modules || {}).length,
          operations: res.data.active_operations ?? 0,
        })
      } catch {
        setStats(s => ({ ...s, status: 'offline' }))
      }
    }
    fetchStats()
    const interval = setInterval(fetchStats, 10000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="space-y-8">
      <div className="slide-in">
        <h1 className="text-4xl font-bold text-gray-100 mb-1">
          Bem-vindo, <span className="text-red-500">{username}</span>
        </h1>
        <p className="text-gray-400">Plataforma de testes de segurança — PenteIA v4.0 · Apenas ambientes autorizados</p>
      </div>

      {/* Aviso Legal em destaque */}
      <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4 flex gap-3">
        <Lock className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
        <p className="text-red-300 text-sm">
          <strong>Uso exclusivo em ambientes autorizados.</strong> Todos os testes devem ter autorização prévia e por escrito do proprietário do sistema. Testes não autorizados são ilegais e podem resultar em processo criminal.
        </p>
      </div>

      {/* Status do Sistema */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard
          title="Status da Plataforma"
          value={stats.status === 'online' ? 'Online' : 'Offline'}
          icon={Activity}
          color={stats.status === 'online' ? 'green' : 'red'}
        />
        <StatCard title="Módulos Disponíveis" value={stats.modules} icon={Compass} color="blue" />
        <StatCard title="Operações Registradas" value={stats.operations} icon={AlertCircle} color="yellow" />
      </div>

      {/* Por onde começar */}
      <div className="card-dark p-6 border-l-4 border-blue-600">
        <div className="flex items-center gap-2 mb-5">
          <BookOpen className="w-5 h-5 text-blue-400" />
          <h2 className="text-xl font-bold text-gray-100">Por onde começar?</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            {
              step: '1',
              title: 'Faça o Reconhecimento',
              desc: 'Antes de qualquer teste, descubra informações sobre o alvo: endereços IP, portas abertas e quais serviços estão rodando.',
              href: '/recon',
              color: 'text-blue-400',
              borderColor: 'border-blue-600/40',
            },
            {
              step: '2',
              title: 'Execute os Testes',
              desc: 'Escolha o módulo adequado: DDoS para testar sobrecarga, BAS para simular ataques completos, ou Evasão para testar o antivírus.',
              href: '/bas',
              color: 'text-yellow-400',
              borderColor: 'border-yellow-600/40',
            },
            {
              step: '3',
              title: 'Gere o Relatório',
              desc: 'Após os testes, gere um relatório profissional com todos os resultados e recomendações de correção para apresentar à equipe.',
              href: '/reporting',
              color: 'text-green-400',
              borderColor: 'border-green-600/40',
            },
          ].map(({ step, title, desc, href, color, borderColor }) => (
            <a
              key={step}
              href={href}
              className={`bg-dark-700 border ${borderColor} rounded-lg p-5 hover:bg-dark-600 transition group`}
            >
              <div className={`text-4xl font-black ${color} mb-3 group-hover:scale-110 inline-block transition-transform`}>
                {step}
              </div>
              <h3 className="font-bold text-gray-100 mb-2">{title}</h3>
              <p className="text-sm text-gray-400 leading-relaxed">{desc}</p>
            </a>
          ))}
        </div>
      </div>

      {/* Módulos da Plataforma */}
      <div>
        <h2 className="text-2xl font-bold text-gray-100 mb-4">Módulos da Plataforma</h2>
        <p className="text-gray-400 text-sm mb-4">Clique em qualquer módulo para acessá-lo e ver as instruções de uso.</p>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {MODULE_INFO.map((mod) => {
            const Icon = mod.icon
            const c = COLOR_MAP[mod.color]
            return (
              <a
                key={mod.name}
                href={mod.href}
                className={`card-dark p-5 ${c.border} ${c.hover} transition group`}
              >
                <div className="flex items-start justify-between mb-3">
                  <Icon className={`w-6 h-6 ${c.text}`} />
                  <span className="text-xs bg-dark-700 text-gray-400 px-2 py-0.5 rounded border border-dark-600">{mod.tip}</span>
                </div>
                <h3 className={`font-bold text-gray-100 mb-2 group-hover:${c.text} transition text-sm`}>{mod.name}</h3>
                <p className="text-xs text-gray-400 leading-relaxed">{mod.description}</p>
              </a>
            )
          })}
        </div>
      </div>
    </div>
  )
}
