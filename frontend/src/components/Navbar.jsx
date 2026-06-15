import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Menu, X, Zap, BarChart3, Radar, Layers, Radio, Target, Shield, CheckSquare, FileText, LogOut, Crown, FlaskConical, Settings, Monitor } from 'lucide-react'
import { useEnv, saveEnv } from '../hooks/useEnv'

export default function Navbar({ systemStatus, onLogout, isAdmin }) {
  const [isOpen, setIsOpen] = useState(false)
  const [envOpen, setEnvOpen] = useState(false)
  const navigate = useNavigate()
  const env = useEnv()
  const [draft, setDraft] = useState({ name: '', host: '', port: '', protocol: 'http', notes: '' })

  const openEnv = () => {
    setDraft({ name: env.name || '', host: env.host || '', port: env.port || '', protocol: env.protocol || 'http', notes: env.notes || '' })
    setEnvOpen(true)
  }
  const saveEnvDraft = () => {
    saveEnv(draft)
    setEnvOpen(false)
  }
  const clearEnv = () => {
    saveEnv({})
    setEnvOpen(false)
  }

  const navItems = [
    { path: '/', label: 'Painel', Icon: BarChart3 },
    { path: '/recon', label: 'Reconhecimento', Icon: Radar },
    { path: '/ddos', label: 'DDoS', Icon: Zap },
    { path: '/modules', label: 'Módulos', Icon: Layers },
    { path: '/c2', label: 'C2', Icon: Radio },
    { path: '/bas', label: 'BAS', Icon: Target },
    { path: '/evasion', label: 'Evasão', Icon: Shield },
    { path: '/operations', label: 'Operações', Icon: CheckSquare },
    { path: '/reporting', label: 'Relatórios', Icon: FileText },
    { path: '/campaign', label: 'Campanha', Icon: FlaskConical },
    { path: '/agents',   label: 'Agentes',  Icon: Monitor },
    ...(isAdmin ? [{ path: '/admin', label: 'Admin', Icon: Crown }] : []),
  ]

  const handleLogout = () => {
    onLogout()
    navigate('/login')
  }

  return (
    <>
    <nav className="bg-dark-800 border-b border-dark-700 sticky top-0 z-50">
      <div className="container mx-auto px-4">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-2 font-bold text-lg group">
            <Zap className="w-6 h-6 text-red-600 group-hover:text-red-400 transition" />
            <span className="text-gray-100">PenteIA</span>
            <span className="text-gray-500 text-sm">v4.0</span>
          </Link>

          {/* Desktop Menu */}
          <div className="hidden lg:flex items-center gap-0">
            {navItems.map(item => {
              const Icon = item.Icon
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className="px-3 py-2 text-gray-400 hover:text-red-600 transition text-sm font-medium flex items-center gap-1.5"
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </Link>
              )
            })}
          </div>

          {/* Status & Logout */}
          <div className="flex items-center gap-3">
            {/* Ambiente de ataque */}
            <button onClick={openEnv} title="Configurar ambiente de ataque"
              className={`hidden md:flex items-center gap-1.5 px-2.5 py-1.5 rounded border text-xs font-mono transition ${
                env.host
                  ? 'border-red-700/60 bg-red-950/30 text-red-400 hover:border-red-600'
                  : 'border-dark-600 bg-dark-700 text-gray-500 hover:border-dark-500'
              }`}>
              <Target className="w-3 h-3" />
              <span>{env.host ? `${env.host}${env.port ? ':'+env.port : ''}` : 'Sem alvo'}</span>
              <Settings className="w-3 h-3 opacity-50" />
            </button>

            <div className="flex items-center gap-2">
              <div className={`w-3 h-3 rounded-full ${systemStatus === 'online' ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-xs text-gray-400 hidden sm:inline">
                {systemStatus === 'online' ? 'Online' : 'Offline'}
              </span>
            </div>

            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-3 py-2 text-gray-400 hover:text-red-600 transition text-sm font-medium"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
              <span className="hidden sm:inline">Sair</span>
            </button>

            {/* Mobile Menu Button */}
            <button
              onClick={() => setIsOpen(!isOpen)}
              className="lg:hidden text-gray-400 hover:text-gray-100"
            >
              {isOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Menu */}
        {isOpen && (
          <div className="lg:hidden bg-dark-700 border-t border-dark-600 py-4 space-y-2">
            {navItems.map(item => {
              const Icon = item.Icon
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => setIsOpen(false)}
                  className="flex items-center gap-2 px-4 py-2 text-gray-400 hover:text-red-600 hover:bg-dark-600 rounded transition"
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </Link>
              )
            })}
            <button
              onClick={() => {
                handleLogout()
                setIsOpen(false)
              }}
              className="flex items-center gap-2 px-4 py-2 text-gray-400 hover:text-red-600 hover:bg-dark-600 rounded transition w-full"
            >
              <LogOut className="w-4 h-4" />
              <span>Sair</span>
            </button>
          </div>
        )}
      </div>
    </nav>

    {/* Modal Ambiente de Ataque */}
    {envOpen && (
      <div className="fixed inset-0 bg-black/60 z-[100] flex items-center justify-center p-4">
        <div className="bg-dark-800 border border-dark-600 rounded-xl shadow-2xl w-full max-w-md">
          <div className="flex justify-between items-center p-5 border-b border-dark-600">
            <div>
              <h2 className="text-lg font-bold text-gray-100 flex items-center gap-2">
                <Target className="w-5 h-5 text-red-400" /> Ambiente de Ataque
              </h2>
              <p className="text-xs text-gray-400 mt-0.5">Alvo padrão usado por todos os módulos</p>
            </div>
            <button onClick={() => setEnvOpen(false)} className="text-gray-500 hover:text-gray-100">
              <X className="w-5 h-5" />
            </button>
          </div>
          <div className="p-5 space-y-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Nome do ambiente</label>
              <input className="input-dark w-full" placeholder="ex: Servidor de Teste, Cliente XYZ..."
                value={draft.name} onChange={e => setDraft(d => ({ ...d, name: e.target.value }))} />
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <label className="block text-xs text-gray-400 mb-1">Host / IP alvo</label>
                <input className="input-dark w-full font-mono" placeholder="192.168.1.10 ou site.com"
                  value={draft.host} onChange={e => setDraft(d => ({ ...d, host: e.target.value }))} />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Porta padrão</label>
                <input className="input-dark w-full font-mono" placeholder="80" type="number"
                  value={draft.port} onChange={e => setDraft(d => ({ ...d, port: e.target.value }))} />
              </div>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Protocolo</label>
              <select className="select-dark w-full" value={draft.protocol}
                onChange={e => setDraft(d => ({ ...d, protocol: e.target.value }))}>
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Notas <span className="text-gray-600">(opcional)</span></label>
              <textarea className="input-dark w-full h-16 resize-none text-xs" placeholder="Credenciais, escopo, observações..."
                value={draft.notes} onChange={e => setDraft(d => ({ ...d, notes: e.target.value }))} />
            </div>
            {draft.host && (
              <div className="bg-dark-700 rounded p-3 text-xs font-mono text-gray-300">
                Alvo: <span className="text-red-400">{draft.protocol}://{draft.host}{draft.port ? ':'+draft.port : ''}</span>
              </div>
            )}
          </div>
          <div className="flex justify-between items-center p-5 border-t border-dark-600">
            <button onClick={clearEnv} className="text-xs text-gray-600 hover:text-red-400 transition">
              Limpar ambiente
            </button>
            <div className="flex gap-2">
              <button onClick={() => setEnvOpen(false)} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded text-sm transition">
                Cancelar
              </button>
              <button onClick={saveEnvDraft} className="btn-blue text-sm">
                Salvar ambiente
              </button>
            </div>
          </div>
        </div>
      </div>
    )}
  </>
  )
}
