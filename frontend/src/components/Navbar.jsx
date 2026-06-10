import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { Menu, X, Terminal, Circle } from 'lucide-react'

export default function Navbar({ systemStatus }) {
  const [isOpen, setIsOpen] = useState(false)

  const navItems = [
    { path: '/', label: 'Painel', icon: '📊' },
    { path: '/recon', label: 'Reconhecimento', icon: '🔍' },
    { path: '/ddos', label: 'Teste DDoS', icon: '⚡' },
    { path: '/modules', label: 'Módulos', icon: '🧩' },
    { path: '/c2', label: 'C2 Beacon', icon: '📡' },
    { path: '/bas', label: 'BAS', icon: '🎯' },
    { path: '/evasion', label: 'Evasão', icon: '🛡️' },
    { path: '/operations', label: 'Operações', icon: '📋' },
    { path: '/reporting', label: 'Relatórios', icon: '📄' },
  ]

  return (
    <nav className="bg-dark-800 border-b border-dark-700 sticky top-0 z-50">
      <div className="container mx-auto px-4">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-2 font-bold text-lg group">
            <Terminal className="w-6 h-6 text-red-600 group-hover:text-red-400 transition" />
            <span className="text-gray-100">PenteIA</span>
            <span className="text-gray-500 text-sm">v4.0</span>
          </Link>

          {/* Desktop Menu */}
          <div className="hidden lg:flex items-center gap-1">
            {navItems.map(item => (
              <Link
                key={item.path}
                to={item.path}
                className="px-3 py-2 text-gray-400 hover:text-red-600 transition text-sm font-medium"
              >
                <span>{item.icon}</span> {item.label}
              </Link>
            ))}
          </div>

          {/* Status */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Circle
                className={`w-3 h-3 fill-current ${systemStatus === 'online' ? 'text-green-500' : 'text-red-500'}`}
              />
              <span className="text-xs text-gray-400">
                {systemStatus === 'online' ? 'Online' : 'Offline'}
              </span>
            </div>

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
            {navItems.map(item => (
              <Link
                key={item.path}
                to={item.path}
                onClick={() => setIsOpen(false)}
                className="block px-4 py-2 text-gray-400 hover:text-red-600 hover:bg-dark-600 rounded transition"
              >
                <span>{item.icon}</span> {item.label}
              </Link>
            ))}
          </div>
        )}
      </div>
    </nav>
  )
}
