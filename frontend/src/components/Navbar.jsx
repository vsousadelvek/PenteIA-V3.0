import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Menu, X, Zap, BarChart3, Radar, Layers, Radio, Target, Shield, CheckSquare, FileText, LogOut, Crown, FlaskConical } from 'lucide-react'

export default function Navbar({ systemStatus, onLogout, isAdmin }) {
  const [isOpen, setIsOpen] = useState(false)
  const navigate = useNavigate()

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
    ...(isAdmin ? [{ path: '/admin', label: 'Admin', Icon: Crown }] : []),
  ]

  const handleLogout = () => {
    onLogout()
    navigate('/login')
  }

  return (
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
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div
                className={`w-3 h-3 rounded-full ${systemStatus === 'online' ? 'bg-green-500' : 'bg-red-500'}`}
              />
              <span className="text-xs text-gray-400">
                {systemStatus === 'online' ? 'Online' : 'Offline'}
              </span>
            </div>

            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-3 py-2 text-gray-400 hover:text-red-600 transition text-sm font-medium"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
              <span>Sair</span>
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
  )
}
