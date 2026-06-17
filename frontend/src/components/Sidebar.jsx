import React, { useState, useEffect } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  Zap, BarChart3, Radar, Layers, Radio, Target, Shield,
  CheckSquare, FileText, LogOut, Crown, FlaskConical, Monitor,
  ChevronLeft, ChevronRight, X, Crosshair, Bell, Database, Grid,
  Globe, Package, Mail, ShieldCheck, Wrench, Link2, DollarSign, Fingerprint, Brain,
  Key, Building2, BookOpen, Swords, Calendar, Flag, Terminal, Users,
  Server, Briefcase,
} from 'lucide-react'
import { useEnv, saveEnv } from '../hooks/useEnv'
import api from '../api'

const GROUPS = [
  {
    label: 'Visão Geral',
    items: [
      { path: '/', label: 'Painel', Icon: BarChart3 },
      { path: '/modules', label: 'Módulos', Icon: Layers },
      { path: '/operations', label: 'Operações', Icon: CheckSquare },
    ],
  },
  {
    label: 'Reconhecimento',
    items: [
      { path: '/recon', label: 'Recon', Icon: Radar },
      { path: '/cloud', label: 'Cloud Recon', Icon: Globe },
      { path: '/cloud-identity', label: 'Cloud Identity', Icon: Fingerprint },
    ],
  },
  {
    label: 'Ataque',
    items: [
      { path: '/bas', label: 'BAS / MITRE', Icon: Target },
      { path: '/real-execution', label: 'Real Execution', Icon: Terminal },
      { path: '/attck-matrix', label: 'ATT&CK Matrix', Icon: Grid },
      { path: '/vulndb', label: 'VulnDB', Icon: Database },
      { path: '/ddos', label: 'DDoS', Icon: Zap },
      { path: '/campaign', label: 'Campanha', Icon: FlaskConical },
      { path: '/apt', label: 'APT Emulation', Icon: Crosshair },
      { path: '/ad-attacks', label: 'AD Attacks', Icon: Server },
      { path: '/playbook-builder', label: 'Playbook Builder', Icon: Layers },
      { path: '/br-fiscal', label: 'BAS Brasil 🇧🇷', Icon: Package },
    ],
  },
  {
    label: 'C2 & Agentes',
    items: [
      { path: '/c2', label: 'C2 Framework', Icon: Radio },
      { path: '/agents', label: 'Agentes', Icon: Monitor },
    ],
  },
  {
    label: 'Human & SOC',
    items: [
      { path: '/phishing', label: 'Phishing Sim.', Icon: Mail },
      { path: '/soc-validation', label: 'SOC Validation', Icon: ShieldCheck },
      { path: '/purple-team', label: 'Purple Team', Icon: Swords },
      { path: '/remediation', label: 'Remediation', Icon: Wrench },
    ],
  },
  {
    label: 'Evasão & Payloads',
    items: [
      { path: '/evasion', label: 'Evasão', Icon: Shield },
    ],
  },
  {
    label: 'IA & ML',
    items: [
      { path: '/ai', label: 'IA / ML', Icon: Brain },
      { path: '/ai-scenarios', label: 'AI Scenarios', Icon: Zap },
    ],
  },
  {
    label: 'Resultados',
    items: [
      { path: '/reporting', label: 'Relatórios', Icon: FileText },
      { path: '/integrations', label: 'Integrações', Icon: Link2 },
      { path: '/api-keys', label: 'API Keys', Icon: Key },
    ],
  },
  {
    label: 'Automação',
    items: [
      { path: '/scheduled-bas', label: 'BAS Agendado', Icon: Calendar },
    ],
  },
  {
    label: 'Conformidade',
    items: [
      { path: '/compliance', label: 'Compliance BR', Icon: Shield },
      { path: '/br-fiscal', label: 'BR Exclusivo 🇧🇷', Icon: Flag },
    ],
  },
  {
    label: 'Admin MSSP',
    items: [
      { path: '/tenants', label: 'Organização', Icon: Building2 },
      { path: '/mssp', label: 'Portal MSSP', Icon: Briefcase },
    ],
  },
]

export default function Sidebar({ systemStatus, onLogout, isAdmin, onCollapse }) {
  const location = useLocation()
  const navigate = useNavigate()
  const env = useEnv()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('sidebar_collapsed') === 'true')
  const [envOpen, setEnvOpen] = useState(false)
  const [draft, setDraft] = useState({ name: '', host: '', port: '', protocol: 'http', notes: '' })
  const [unread, setUnread] = useState(0)
  const [notifOpen, setNotifOpen] = useState(false)
  const [notifications, setNotifications] = useState([])

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) return
    const poll = () => {
      api.get('/api/notifications').then(r => {
        setUnread(r.data.unread_count || 0)
        setNotifications(r.data.notifications || [])
      }).catch(() => {})
    }
    poll()
    const interval = setInterval(poll, 30000)
    return () => clearInterval(interval)
  }, [])

  const markAllRead = () => {
    api.post('/api/notifications/mark-all-read').then(() => {
      setUnread(0)
      setNotifications(n => n.map(x => ({ ...x, read: true })))
    }).catch(() => {})
  }

  const toggle = () => {
    const next = !collapsed
    setCollapsed(next)
    localStorage.setItem('sidebar_collapsed', String(next))
    onCollapse?.(next)
  }

  const openEnv = () => {
    setDraft({ name: env.name || '', host: env.host || '', port: env.port || '', protocol: env.protocol || 'http', notes: env.notes || '' })
    setEnvOpen(true)
  }
  const saveEnvDraft = () => { saveEnv(draft); setEnvOpen(false) }
  const clearEnv = () => { saveEnv({}); setEnvOpen(false) }

  const allAdminItems = isAdmin ? [{ path: '/admin', label: 'Admin', Icon: Crown }] : []

  const isActive = (path) => path === '/' ? location.pathname === '/' || location.pathname === '/dashboard' : location.pathname === path || location.pathname.startsWith(path + '/')

  const W = collapsed ? 56 : 220

  return (
    <>
      <aside
        style={{ width: W, minWidth: W }}
        className="fixed left-0 top-0 h-full bg-dark-800 border-r border-dark-700 z-40 flex flex-col transition-all duration-200 overflow-hidden"
      >
        {/* Logo + toggle */}
        <div className="flex items-center justify-between px-3 h-14 border-b border-dark-700 flex-shrink-0">
          {!collapsed && (
            <Link to="/" className="flex items-center gap-2 font-bold group min-w-0">
              <Zap className="w-5 h-5 text-red-500 flex-shrink-0" />
              <span className="text-gray-100 truncate">PenteIA</span>
              <span className="text-gray-600 text-xs">v4.0</span>
            </Link>
          )}
          {collapsed && (
            <Link to="/" className="mx-auto">
              <Zap className="w-5 h-5 text-red-500" />
            </Link>
          )}
          {!collapsed && (
            <button onClick={toggle} className="text-gray-500 hover:text-gray-300 flex-shrink-0 ml-1">
              <ChevronLeft className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Ambiente de ataque badge */}
        <button
          onClick={openEnv}
          title="Configurar ambiente de ataque"
          className={`flex items-center gap-2 mx-2 mt-3 mb-1 px-2 py-1.5 rounded border text-xs font-mono transition ${
            env.host
              ? 'border-red-700/60 bg-red-950/30 text-red-400 hover:border-red-500'
              : 'border-dark-600 bg-dark-700/50 text-gray-600 hover:border-dark-500'
          } ${collapsed ? 'justify-center px-0' : ''}`}
        >
          <Crosshair className="w-3.5 h-3.5 flex-shrink-0" />
          {!collapsed && (
            <span className="truncate">{env.host ? `${env.host}${env.port ? ':' + env.port : ''}` : 'Sem alvo'}</span>
          )}
        </button>

        {/* Nav groups */}
        <nav className="flex-1 overflow-y-auto py-2 space-y-1 scrollbar-none">
          {GROUPS.map(group => (
            <div key={group.label}>
              {!collapsed && (
                <p className="px-3 pt-3 pb-1 text-[10px] font-semibold text-gray-600 uppercase tracking-widest truncate">
                  {group.label}
                </p>
              )}
              {collapsed && <div className="my-1 mx-2 border-t border-dark-700" />}
              {group.items.map(({ path, label, Icon }) => {
                const active = isActive(path)
                return (
                  <Link
                    key={path}
                    to={path}
                    title={collapsed ? label : undefined}
                    className={`flex items-center gap-3 mx-2 px-2 py-2 rounded-lg text-sm transition-all ${
                      active
                        ? 'bg-red-950/40 text-red-400 border border-red-800/40'
                        : 'text-gray-400 hover:bg-dark-700 hover:text-gray-200'
                    } ${collapsed ? 'justify-center' : ''}`}
                  >
                    <Icon className={`w-4 h-4 flex-shrink-0 ${active ? 'text-red-400' : ''}`} />
                    {!collapsed && <span className="truncate">{label}</span>}
                  </Link>
                )
              })}
            </div>
          ))}

          {/* Admin */}
          {allAdminItems.map(({ path, label, Icon }) => {
            const active = isActive(path)
            return (
              <Link
                key={path}
                to={path}
                title={collapsed ? label : undefined}
                className={`flex items-center gap-3 mx-2 px-2 py-2 rounded-lg text-sm transition-all mt-1 ${
                  active
                    ? 'bg-yellow-950/40 text-yellow-400 border border-yellow-800/40'
                    : 'text-yellow-600 hover:bg-dark-700 hover:text-yellow-400'
                } ${collapsed ? 'justify-center' : ''}`}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                {!collapsed && <span className="truncate">{label}</span>}
              </Link>
            )
          })}
        </nav>

        {/* Footer: status + toggle expand + logout */}
        <div className="flex-shrink-0 border-t border-dark-700 p-2 space-y-1">
          {/* Notification bell */}
          <button
            onClick={() => { setNotifOpen(o => !o); if (unread > 0) markAllRead() }}
            className={`relative flex items-center gap-2 w-full px-2 py-2 rounded-lg text-sm text-gray-500 hover:text-gray-300 hover:bg-dark-700 transition ${collapsed ? 'justify-center' : ''}`}
            title="Notificações"
          >
            <Bell className="w-4 h-4 flex-shrink-0" />
            {!collapsed && <span>Notificações</span>}
            {unread > 0 && (
              <span className="absolute top-1 left-5 w-4 h-4 bg-red-600 text-white text-[10px] font-bold rounded-full flex items-center justify-center">
                {unread > 9 ? '9+' : unread}
              </span>
            )}
          </button>

          {/* Status */}
          <div className={`flex items-center gap-2 px-2 py-1.5 ${collapsed ? 'justify-center' : ''}`}>
            <div className={`w-2 h-2 rounded-full flex-shrink-0 ${systemStatus === 'online' ? 'bg-green-500' : 'bg-red-500'}`} />
            {!collapsed && <span className="text-xs text-gray-500">{systemStatus === 'online' ? 'API Online' : 'API Offline'}</span>}
          </div>

          {/* Expand button (only when collapsed) */}
          {collapsed && (
            <button
              onClick={toggle}
              className="flex items-center justify-center w-full py-1.5 text-gray-600 hover:text-gray-400 transition"
              title="Expandir menu"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          )}

          {/* Logout */}
          <button
            onClick={() => { onLogout(); navigate('/login') }}
            className={`flex items-center gap-2 w-full px-2 py-2 rounded-lg text-sm text-gray-500 hover:text-red-400 hover:bg-dark-700 transition ${collapsed ? 'justify-center' : ''}`}
            title="Sair"
          >
            <LogOut className="w-4 h-4 flex-shrink-0" />
            {!collapsed && <span>Sair</span>}
          </button>
        </div>
      </aside>

      {/* Notification panel */}
      {notifOpen && (
        <div className="fixed left-0 top-0 h-full z-[90] flex" style={{ paddingLeft: W }}>
          <div className="w-80 bg-dark-800 border-r border-dark-600 shadow-2xl flex flex-col h-full">
            <div className="flex items-center justify-between p-4 border-b border-dark-600">
              <h3 className="font-semibold text-gray-100 flex items-center gap-2">
                <Bell className="w-4 h-4 text-red-400" /> Notificações
              </h3>
              <div className="flex items-center gap-2">
                {unread > 0 && (
                  <button onClick={markAllRead} className="text-xs text-gray-500 hover:text-gray-300">Marcar lidas</button>
                )}
                <button onClick={() => setNotifOpen(false)} className="text-gray-500 hover:text-gray-100">
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto">
              {notifications.length === 0 ? (
                <div className="p-8 text-center text-gray-500 text-sm">
                  <Bell className="w-8 h-8 mx-auto mb-2 text-gray-700" />
                  Nenhuma notificação
                </div>
              ) : (
                <div className="divide-y divide-dark-700">
                  {notifications.map(n => (
                    <div key={n.id} className={`p-4 ${n.read ? '' : 'bg-dark-700/50'}`}>
                      <div className="flex items-start gap-2">
                        <span className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${
                          n.type === 'critical' ? 'bg-red-500' :
                          n.type === 'warning' ? 'bg-yellow-500' :
                          n.type === 'success' ? 'bg-green-500' : 'bg-blue-500'
                        }`} />
                        <div className="min-w-0">
                          <p className={`text-sm font-medium ${n.read ? 'text-gray-400' : 'text-gray-100'}`}>{n.title}</p>
                          <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{n.message}</p>
                          <p className="text-[10px] text-gray-600 mt-1">{n.created_at?.slice(0, 16).replace('T', ' ')}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
          <div className="flex-1" onClick={() => setNotifOpen(false)} />
        </div>
      )}

      {/* Modal Ambiente de Ataque */}
      {envOpen && (
        <div className="fixed inset-0 bg-black/60 z-[100] flex items-center justify-center p-4">
          <div className="bg-dark-800 border border-dark-600 rounded-xl shadow-2xl w-full max-w-md">
            <div className="flex justify-between items-center p-5 border-b border-dark-600">
              <div>
                <h2 className="text-lg font-bold text-gray-100 flex items-center gap-2">
                  <Crosshair className="w-5 h-5 text-red-400" /> Ambiente de Ataque
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
                  Alvo: <span className="text-red-400">{draft.protocol}://{draft.host}{draft.port ? ':' + draft.port : ''}</span>
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
