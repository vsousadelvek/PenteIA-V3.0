import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Zap, Target, Eye, Terminal, Globe, Lock, CheckCircle,
  ArrowRight, Activity, Layers, Radio, Brain, BarChart3, FileText,
  Briefcase, Play, Star, TrendingUp, Server, Cpu, Network, Database,
  Code2, GitBranch, AlertTriangle, Users, Crosshair, Swords, BookOpen,
  ChevronRight, Building2, Landmark, Package, Wifi, Bug, FlaskConical,
} from 'lucide-react'

// ─── Keyframes injected once ────────────────────────────────────────────────
const GLOBAL_STYLES = `
@keyframes grid-move {
  0%   { transform: translateY(0); }
  100% { transform: translateY(40px); }
}
@keyframes ticker-slide {
  0%   { opacity: 0; transform: translateY(12px); }
  15%  { opacity: 1; transform: translateY(0); }
  80%  { opacity: 1; transform: translateY(0); }
  100% { opacity: 0; transform: translateY(-12px); }
}
@keyframes glow-pulse {
  0%, 100% { box-shadow: 0 0 20px rgba(220,38,38,0.3); }
  50%       { box-shadow: 0 0 40px rgba(220,38,38,0.6); }
}
@keyframes float-up {
  0%   { opacity:0; transform:translateY(30px); }
  100% { opacity:1; transform:translateY(0); }
}
@keyframes badge-scroll {
  0%   { transform: translateX(0); }
  100% { transform: translateX(-50%); }
}
@keyframes dot-blink {
  0%, 100% { opacity:1; }
  50%       { opacity:0.2; }
}
.animate-glow-pulse  { animation: glow-pulse 2s ease-in-out infinite; }
.animate-badge-scroll{ animation: badge-scroll 30s linear infinite; }
.animate-float-up    { animation: float-up 0.7s ease forwards; }
.ticker-item         { animation: ticker-slide 2s ease-in-out forwards; }
.dot-blink           { animation: dot-blink 1.2s ease-in-out infinite; }
`

// ─── Hooks ───────────────────────────────────────────────────────────────────
function useCountUp(end, duration = 1400, start = false) {
  const [count, setCount] = useState(0)
  useEffect(() => {
    if (!start || !end) return
    let startTime = null
    const step = (ts) => {
      if (!startTime) startTime = ts
      const progress = Math.min((ts - startTime) / duration, 1)
      const ease = 1 - Math.pow(1 - progress, 3)
      setCount(Math.floor(ease * end))
      if (progress < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [start, end, duration])
  return count
}

function useInView(ref, threshold = 0.2) {
  const [visible, setVisible] = useState(false)
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) setVisible(true) }, { threshold })
    if (ref.current) obs.observe(ref.current)
    return () => obs.disconnect()
  }, [threshold])
  return visible
}

// ─── Sub-components ───────────────────────────────────────────────────────────
function StatCounter({ value, suffix = '', label, start }) {
  const n = useCountUp(value, 1400, start)
  return (
    <div className="text-center px-6">
      <div className="text-5xl font-black text-white tabular-nums">
        {n.toLocaleString('pt-BR')}{suffix}
      </div>
      <div className="text-sm text-gray-500 mt-2 uppercase tracking-widest font-medium">{label}</div>
    </div>
  )
}

function ModuleCard({ icon: Icon, name, desc, badge, color }) {
  return (
    <div className="group relative bg-dark-800 border border-dark-700 rounded-2xl p-5 hover:border-red-800 hover:bg-dark-700 transition-all duration-300 cursor-default overflow-hidden">
      <div className={`absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 ${color} rounded-2xl`} style={{ background: 'radial-gradient(ellipse at top left, rgba(220,38,38,0.06) 0%, transparent 70%)' }} />
      <div className="relative z-10">
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center mb-3 ${color}`}>
          <Icon size={20} className="text-white" />
        </div>
        <div className="flex items-start justify-between gap-2 mb-1">
          <span className="text-sm font-semibold text-white leading-tight">{name}</span>
          {badge && (
            <span className="shrink-0 text-xs px-2 py-0.5 rounded-full bg-red-900/50 text-red-400 border border-red-800/60 font-mono">
              {badge}
            </span>
          )}
        </div>
        <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
      </div>
    </div>
  )
}

function PricingCard({ plan, price, users, sims, features, highlighted, onCta }) {
  return (
    <div className={`relative flex flex-col rounded-2xl p-8 transition-all duration-300 ${
      highlighted
        ? 'bg-dark-800 border-2 border-red-600 animate-glow-pulse scale-105'
        : 'bg-dark-800 border border-dark-700 hover:border-dark-600'
    }`}>
      {highlighted && (
        <div className="absolute -top-4 left-1/2 -translate-x-1/2 bg-red-600 text-white text-xs font-bold px-4 py-1.5 rounded-full uppercase tracking-wider">
          Mais Popular
        </div>
      )}
      <div className="mb-6">
        <h3 className="text-lg font-bold text-white mb-1">{plan}</h3>
        <div className="flex items-baseline gap-1 mt-3">
          {price ? (
            <>
              <span className="text-gray-400 text-sm">R$</span>
              <span className="text-4xl font-black text-white">{price}</span>
              <span className="text-gray-500 text-sm">/mês</span>
            </>
          ) : (
            <span className="text-3xl font-black text-white">Sob consulta</span>
          )}
        </div>
        <p className="text-xs text-gray-500 mt-2">{users} · {sims}</p>
      </div>
      <ul className="flex-1 space-y-3 mb-8">
        {features.map((f, i) => (
          <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
            <CheckCircle size={15} className="text-green-500 shrink-0 mt-0.5" />
            {f}
          </li>
        ))}
      </ul>
      <button
        onClick={onCta}
        className={`w-full py-3 rounded-xl font-semibold text-sm transition-all duration-200 ${
          highlighted
            ? 'bg-red-600 hover:bg-red-500 text-white'
            : 'bg-dark-700 hover:bg-dark-600 text-gray-200 border border-dark-600'
        }`}
      >
        {price ? 'Começar Agora' : 'Falar com Vendas'}
      </button>
    </div>
  )
}

function TestimonialCard({ quote, name, role, company, initials, color }) {
  return (
    <div className="bg-dark-800 border border-dark-700 rounded-2xl p-7 flex flex-col gap-4 hover:border-dark-600 transition-all duration-300">
      <div className="flex gap-1 mb-1">
        {[...Array(5)].map((_, i) => <Star key={i} size={13} className="fill-yellow-500 text-yellow-500" />)}
      </div>
      <p className="text-gray-300 text-sm leading-relaxed italic">"{quote}"</p>
      <div className="flex items-center gap-3 mt-auto pt-2 border-t border-dark-700">
        <div className={`w-10 h-10 rounded-full ${color} flex items-center justify-center text-white font-bold text-sm shrink-0`}>
          {initials}
        </div>
        <div>
          <div className="text-white text-sm font-semibold">{name}</div>
          <div className="text-gray-500 text-xs">{role} · {company}</div>
        </div>
      </div>
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function Landing() {
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)
  const [tickerIndex, setTickerIndex] = useState(0)
  const [tickerKey, setTickerKey] = useState(0)
  const statsRef = useRef(null)
  const statsVisible = useInView(statsRef, 0.3)

  const TICKER_ITEMS = [
    { label: 'T1059.001 PowerShell', status: 'EXEC', color: 'text-green-400' },
    { label: 'K8S-001 Container Escape', status: 'PASS', color: 'text-green-400' },
    { label: 'ICS-T0812 Loss of Control', status: 'EXEC', color: 'text-yellow-400' },
    { label: 'APT28 Fancy Bear TTPs', status: 'PASS', color: 'text-green-400' },
    { label: 'T1190 Exploit Public-Facing', status: 'EXEC', color: 'text-red-400' },
    { label: 'PIX/DREX Fraud Sim', status: 'PASS', color: 'text-green-400' },
    { label: 'T1078 Valid Accounts AD', status: 'EXEC', color: 'text-yellow-400' },
    { label: 'CVE-2024-3094 XZ Backdoor', status: 'PASS', color: 'text-green-400' },
    { label: 'OT-T0820 Rootkit ICS', status: 'EXEC', color: 'text-red-400' },
    { label: 'OWASP API-01 Auth Bypass', status: 'PASS', color: 'text-green-400' },
  ]

  useEffect(() => {
    const id = setInterval(() => {
      setTickerIndex(i => (i + 1) % TICKER_ITEMS.length)
      setTickerKey(k => k + 1)
    }, 2200)
    return () => clearInterval(id)
  }, [])

  const goLogin = useCallback(() => navigate('/login'), [navigate])

  const MODULES = [
    { icon: Shield,       name: 'BAS / MITRE ATT&CK', desc: 'Simulações baseadas em TTPs reais mapeadas ao ATT&CK Enterprise.', badge: 'v14', color: 'bg-red-700' },
    { icon: Server,       name: 'K8s Security',        desc: 'Testes de escape, RBAC poisoning e cluster takeover.', badge: 'K8S', color: 'bg-blue-700' },
    { icon: Globe,        name: 'API Security OWASP',  desc: 'OWASP API Top-10 automatizado com fuzzing e broken auth.', badge: 'OWASP', color: 'bg-purple-700' },
    { icon: Wifi,         name: 'OT / ICS / SCADA',   desc: 'Ataques a Modbus, DNP3, PROFINET e PLCs industriais.', badge: 'ICS', color: 'bg-orange-700' },
    { icon: Radio,        name: 'Threat Intel',        desc: 'Feeds de MISP e OpenCTI convertidos em cenários executáveis.', badge: 'TIP', color: 'bg-cyan-700' },
    { icon: GitBranch,    name: 'BSaC CI/CD',          desc: 'Ataques em pipelines GitHub Actions, Jenkins e supply chain.', badge: 'CI/CD', color: 'bg-green-700' },
    { icon: BarChart3,    name: 'CISO Dashboard',      desc: 'Relatórios executivos, scorecard de resiliência e KPIs em tempo real.', badge: 'EXEC', color: 'bg-indigo-700' },
    { icon: Network,      name: 'AD Attacks',          desc: 'Pass-the-Hash, Kerberoasting, DCSync e Golden Ticket.', badge: 'AD', color: 'bg-red-800' },
    { icon: Swords,       name: 'APT Emulation',       desc: 'Emulação de APT28, APT29, Lazarus, Lapsus$ e grupos BR.', badge: 'APT', color: 'bg-rose-700' },
    { icon: Users,        name: 'Purple Team',         desc: 'Exercícios colaborativos Red vs Blue com scoring automático.', badge: 'PURPLE', color: 'bg-violet-700' },
    { icon: Cpu,          name: 'Execution Engine',    desc: 'Orquestrador de ataques distribuídos com agentes stealth.', badge: 'CORE', color: 'bg-slate-700' },
    { icon: Landmark,     name: 'BR Fiscal',           desc: 'Ataques a NF-e, DREX, PIX e infraestrutura bancária BR.', badge: 'BR', color: 'bg-yellow-700' },
  ]

  const INTEGRATIONS = [
    'SentinelOne', 'Microsoft Defender', 'CrowdStrike', 'Wazuh',
    'Jira', 'Slack', 'MISP', 'OpenCTI', 'Tenable', 'Qualys',
    'GitHub Actions', 'Jenkins',
    'SentinelOne', 'Microsoft Defender', 'CrowdStrike', 'Wazuh',
    'Jira', 'Slack', 'MISP', 'OpenCTI', 'Tenable', 'Qualys',
    'GitHub Actions', 'Jenkins',
  ]

  const PRICING = [
    {
      plan: 'Starter',
      price: '990',
      users: '5 usuários',
      sims: '50 simulações/mês',
      highlighted: false,
      features: [
        'Módulos BAS e MITRE ATT&CK',
        'CISO Dashboard básico',
        'Relatórios PDF',
        'Suporte via email',
        'SLA 48h',
      ],
    },
    {
      plan: 'Professional',
      price: '2.490',
      users: '20 usuários',
      sims: 'Simulações ilimitadas',
      highlighted: true,
      features: [
        'Todos os 12 módulos ativos',
        'APT Emulation + Purple Team',
        'Integrações SIEM/SOAR',
        'Relatórios executivos CISO',
        'API completa + webhooks',
        'Suporte prioritário 12×5',
        'SLA 4h',
      ],
    },
    {
      plan: 'Enterprise',
      price: null,
      users: 'Usuários ilimitados',
      sims: 'Tudo ilimitado',
      highlighted: false,
      features: [
        'White-label para MSSP',
        'Deploy on-premise ou cloud privada',
        'Agentes customizados',
        'Multi-tenant isolado',
        'Suporte dedicado 24×7',
        'SLA 1h garantido',
        'Treinamento in-company',
      ],
    },
  ]

  const TESTIMONIALS = [
    {
      quote: 'O PenteIA reduziu nosso tempo de detecção de 72h para menos de 4h. Os relatórios automatizados economizam horas de trabalho toda semana.',
      name: 'Rafael Mendonça',
      role: 'Head de SOC',
      company: 'Itamaraty Seguros',
      initials: 'RM',
      color: 'bg-red-700',
    },
    {
      quote: 'Finalmente um BAS que entende o contexto regulatório brasileiro. O módulo de NF-e e PIX foi decisivo para nossa auditoria PCI-DSS.',
      name: 'Camila Torres',
      role: 'CISO',
      company: 'BancoFlux S.A.',
      initials: 'CT',
      color: 'bg-blue-700',
    },
    {
      quote: 'A emulação de APT28 gerou 47 alertas no SentinelOne. Com o PenteIA identificamos 12 gaps críticos antes que o adversário real o fizesse.',
      name: 'Diego Albuquerque',
      role: 'Gerente de Cybersegurança',
      company: 'EnergiaBR Utilities',
      initials: 'DA',
      color: 'bg-green-700',
    },
  ]

  return (
    <>
      <style>{GLOBAL_STYLES}</style>

      <div className="min-h-screen bg-dark-900 text-white overflow-x-hidden" style={{ backgroundColor: '#0a0a0f' }}>

        {/* ── NAV ──────────────────────────────────────────────────────────── */}
        <nav className="fixed top-0 left-0 right-0 z-50 border-b border-white/5"
          style={{ backdropFilter: 'blur(20px)', backgroundColor: 'rgba(10,10,15,0.85)' }}>
          <div className="max-w-7xl mx-auto px-4 sm:px-6 flex items-center justify-between h-16">
            <a href="#hero" className="flex items-center gap-1 select-none">
              <span className="text-2xl font-black tracking-tight text-white font-mono">PENTE</span>
              <span className="text-2xl font-black tracking-tight text-red-500 font-mono">[IA]</span>
            </a>

            <div className="hidden md:flex items-center gap-8">
              {['#platform', '#modules', '#pricing'].map((href, i) => (
                <a key={i} href={href}
                  className="text-sm text-gray-400 hover:text-white transition-colors duration-200 font-medium">
                  {['Plataforma', 'Módulos', 'Preços'][i]}
                </a>
              ))}
            </div>

            <div className="hidden md:flex items-center gap-3">
              <button onClick={goLogin}
                className="text-sm text-gray-300 hover:text-white transition-colors px-4 py-2 rounded-lg hover:bg-white/5">
                Entrar
              </button>
              <button onClick={goLogin}
                className="text-sm bg-red-600 hover:bg-red-500 text-white px-5 py-2 rounded-lg font-semibold transition-all duration-200 hover:shadow-lg hover:shadow-red-900/50">
                Demo Grátis
              </button>
            </div>

            <button className="md:hidden text-gray-400 hover:text-white p-2"
              onClick={() => setMenuOpen(o => !o)}>
              <div className="w-5 h-0.5 bg-current mb-1.5" />
              <div className="w-5 h-0.5 bg-current mb-1.5" />
              <div className="w-5 h-0.5 bg-current" />
            </button>
          </div>

          {menuOpen && (
            <div className="md:hidden border-t border-white/5 px-4 py-4 space-y-3" style={{ backgroundColor: 'rgba(10,10,15,0.98)' }}>
              {['#platform', '#modules', '#pricing'].map((href, i) => (
                <a key={i} href={href} onClick={() => setMenuOpen(false)}
                  className="block text-sm text-gray-300 hover:text-white py-2">
                  {['Plataforma', 'Módulos', 'Preços'][i]}
                </a>
              ))}
              <button onClick={goLogin} className="w-full bg-red-600 text-white py-2.5 rounded-lg font-semibold text-sm mt-2">
                Demo Grátis
              </button>
            </div>
          )}
        </nav>

        {/* ── HERO ─────────────────────────────────────────────────────────── */}
        <section id="hero" className="relative min-h-screen flex items-center pt-16 overflow-hidden">
          {/* Grid background */}
          <div className="absolute inset-0 pointer-events-none" style={{ zIndex: 0 }}>
            <div style={{
              position: 'absolute', inset: 0,
              backgroundImage: `
                linear-gradient(rgba(220,38,38,0.07) 1px, transparent 1px),
                linear-gradient(90deg, rgba(220,38,38,0.07) 1px, transparent 1px)
              `,
              backgroundSize: '40px 40px',
              animation: 'grid-move 4s linear infinite',
            }} />
            <div style={{
              position: 'absolute', inset: 0,
              background: 'radial-gradient(ellipse 80% 60% at 50% 0%, rgba(220,38,38,0.12) 0%, transparent 60%)',
            }} />
            <div style={{
              position: 'absolute', bottom: 0, left: 0, right: 0, height: '200px',
              background: 'linear-gradient(to top, #0a0a0f, transparent)',
            }} />
          </div>

          <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 w-full py-24">
            <div className="flex flex-col lg:flex-row items-center gap-16">
              {/* Left */}
              <div className="flex-1 text-center lg:text-left animate-float-up">
                <div className="inline-flex items-center gap-2 bg-red-950/60 border border-red-800/60 rounded-full px-4 py-1.5 text-xs text-red-400 font-mono mb-8">
                  <span className="dot-blink inline-block w-2 h-2 rounded-full bg-red-500" />
                  v4.0 · BAS Enterprise com IA · Round 5
                </div>

                <h1 className="text-5xl sm:text-6xl lg:text-7xl font-black leading-tight tracking-tight mb-6">
                  <span className="text-white">Simule qualquer</span>
                  <br />
                  <span className="text-white">ataque.</span>
                  <br />
                  <span style={{ background: 'linear-gradient(135deg, #dc2626, #f87171)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                    Antes que alguém
                  </span>
                  <br />
                  <span style={{ background: 'linear-gradient(135deg, #dc2626, #f87171)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                    o faça.
                  </span>
                </h1>

                <p className="text-lg text-gray-400 max-w-xl mx-auto lg:mx-0 mb-10 leading-relaxed">
                  Plataforma BAS enterprise com IA generativa — emule APTs reais, valide controles de segurança
                  e entregue relatórios executivos automáticos. Do SOC ao CISO, em minutos.
                </p>

                <div className="flex flex-col sm:flex-row gap-4 justify-center lg:justify-start mb-12">
                  <button onClick={goLogin}
                    className="group flex items-center justify-center gap-2 bg-red-600 hover:bg-red-500 text-white px-8 py-4 rounded-xl font-bold text-base transition-all duration-200 hover:shadow-2xl hover:shadow-red-900/60 hover:scale-[1.02]">
                    Começar Agora
                    <ArrowRight size={18} className="group-hover:translate-x-1 transition-transform" />
                  </button>
                  <button onClick={goLogin}
                    className="group flex items-center justify-center gap-2 bg-white/5 hover:bg-white/10 border border-white/10 text-white px-8 py-4 rounded-xl font-bold text-base transition-all duration-200">
                    <Play size={16} className="text-red-400" />
                    Ver Demo
                  </button>
                </div>

                <div className="inline-flex items-center gap-2 text-xs text-gray-500 border border-white/10 rounded-full px-4 py-2">
                  <Shield size={13} className="text-green-500" />
                  Trusted by SOC teams across Brazil
                  <span className="flex gap-1 ml-1">
                    {['🔴', '🟡', '🟢'].map((e, i) => <span key={i}>{e}</span>)}
                  </span>
                </div>
              </div>

              {/* Right — Attack Ticker */}
              <div className="lg:w-96 w-full max-w-sm mx-auto">
                <div className="bg-dark-800 border border-dark-700 rounded-2xl overflow-hidden"
                  style={{ backgroundColor: 'rgba(15,15,20,0.9)', backdropFilter: 'blur(10px)' }}>
                  {/* Terminal header */}
                  <div className="flex items-center gap-2 px-4 py-3 border-b border-white/5">
                    <div className="w-3 h-3 rounded-full bg-red-500/80" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                    <div className="w-3 h-3 rounded-full bg-green-500/80" />
                    <span className="ml-2 text-xs text-gray-500 font-mono">penteia — execution engine</span>
                  </div>
                  <div className="px-4 py-5 font-mono text-xs space-y-2 min-h-[260px]">
                    <div className="text-gray-500">$ penteia run --profile apt28 --target lab</div>
                    <div className="text-gray-600">Initializing attack engine v4.0...</div>
                    <div className="text-green-500">✓ Agent deployed (stealth mode)</div>
                    <div className="text-gray-600">Loading MITRE ATT&CK framework...</div>
                    <div className="text-green-500">✓ 248 techniques loaded</div>
                    <div className="h-px bg-white/5 my-3" />
                    <div className="text-gray-500 mb-3">Running simulations:</div>

                    {/* Ticker */}
                    <div className="relative h-24 overflow-hidden">
                      {TICKER_ITEMS.slice(0, 5).map((item, i) => {
                        const isActive = i === tickerIndex % 5
                        const past = i < tickerIndex % 5
                        return (
                          <div key={i}
                            className="flex items-center justify-between py-1.5 transition-all duration-500"
                            style={{ opacity: isActive ? 1 : past ? 0.35 : 0.15 }}>
                            <span className="text-gray-400">→ {item.label.substring(0, 24)}</span>
                            <span className={`${item.color} font-bold text-xs ml-2 shrink-0`}>[{item.status}]</span>
                          </div>
                        )
                      })}
                    </div>

                    {/* Live ticker */}
                    <div className="border-t border-white/5 pt-3 mt-2">
                      <div key={tickerKey} className="ticker-item flex items-center justify-between bg-red-950/30 border border-red-900/40 rounded-lg px-3 py-2">
                        <div className="flex items-center gap-2">
                          <span className="dot-blink inline-block w-1.5 h-1.5 rounded-full bg-red-500" />
                          <span className="text-red-300 text-xs">{TICKER_ITEMS[tickerIndex].label}</span>
                        </div>
                        <span className={`${TICKER_ITEMS[tickerIndex].color} text-xs font-bold`}>
                          [{TICKER_ITEMS[tickerIndex].status}]
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ── STATS ─────────────────────────────────────────────────────────── */}
        <section ref={statsRef} id="platform" className="py-20 border-y border-white/5"
          style={{ background: 'linear-gradient(180deg, rgba(220,38,38,0.04) 0%, transparent 100%)' }}>
          <div className="max-w-5xl mx-auto px-4 sm:px-6">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8 divide-x-0 md:divide-x divide-white/5">
              <StatCounter value={248}  suffix=""    label="Endpoints cobertos"    start={statsVisible} />
              <StatCounter value={40}   suffix="+"   label="Módulos ativos"        start={statsVisible} />
              <StatCounter value={10}   suffix=""    label="Rounds de dev"         start={statsVisible} />
              <StatCounter value={150}  suffix="+"   label="Testes automatizados"  start={statsVisible} />
            </div>
          </div>
        </section>

        {/* ── MODULES ───────────────────────────────────────────────────────── */}
        <section id="modules" className="py-24 max-w-7xl mx-auto px-4 sm:px-6">
          <div className="text-center mb-14">
            <div className="inline-flex items-center gap-2 text-xs text-red-400 font-mono bg-red-950/40 border border-red-900/40 rounded-full px-4 py-1.5 mb-5">
              <Layers size={12} />
              12 módulos enterprise
            </div>
            <h2 className="text-4xl sm:text-5xl font-black text-white mb-4">
              Uma plataforma.<br />
              <span className="text-gray-500">Todas as ameaças.</span>
            </h2>
            <p className="text-gray-400 max-w-xl mx-auto">
              Do ambiente industrial ao Kubernetes, do PIX ao APT — cobertura total de superfície de ataque.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {MODULES.map((m, i) => <ModuleCard key={i} {...m} />)}
          </div>
        </section>

        {/* ── HOW IT WORKS ──────────────────────────────────────────────────── */}
        <section className="py-24 border-y border-white/5"
          style={{ background: 'linear-gradient(180deg, transparent 0%, rgba(220,38,38,0.03) 50%, transparent 100%)' }}>
          <div className="max-w-5xl mx-auto px-4 sm:px-6">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-black text-white mb-3">Como funciona</h2>
              <p className="text-gray-400">Três passos. Zero configuração manual.</p>
            </div>

            <div className="flex flex-col md:flex-row items-center gap-4 md:gap-0">
              {[
                { step: '01', icon: Target,   title: 'Configure o alvo', desc: 'Defina o escopo, selecione o perfil de ameaça (APT, ransomware, insider) e conecte seus ativos via agente ou API.' },
                { step: '02', icon: Zap,      title: 'Execute simulações', desc: 'O engine distribui ataques stealth mapeados ao MITRE ATT&CK. Logs em tempo real, sem impacto em produção.' },
                { step: '03', icon: FileText, title: 'Receba relatório CISO', desc: 'Dashboard executivo com scorecard de resiliência, CVEs exploradas, lacunas críticas e plano de remediação priorizado.' },
              ].map((s, i) => (
                <React.Fragment key={i}>
                  <div className="flex-1 text-center px-6">
                    <div className="relative inline-block mb-6">
                      <div className="w-20 h-20 rounded-2xl bg-dark-800 border border-dark-700 flex items-center justify-center mx-auto"
                        style={i === 1 ? { borderColor: 'rgba(220,38,38,0.5)', boxShadow: '0 0 30px rgba(220,38,38,0.2)' } : {}}>
                        <s.icon size={32} className={i === 1 ? 'text-red-500' : 'text-gray-400'} />
                      </div>
                      <span className="absolute -top-2 -right-2 w-6 h-6 rounded-full bg-red-600 text-white text-xs font-black flex items-center justify-center">
                        {i + 1}
                      </span>
                    </div>
                    <h3 className="text-lg font-bold text-white mb-2">{s.title}</h3>
                    <p className="text-sm text-gray-400 leading-relaxed">{s.desc}</p>
                  </div>
                  {i < 2 && (
                    <div className="hidden md:flex items-center text-gray-700">
                      <ChevronRight size={28} />
                    </div>
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>
        </section>

        {/* ── INTEGRATIONS ─────────────────────────────────────────────────── */}
        <section className="py-20 overflow-hidden">
          <div className="text-center mb-10">
            <p className="text-sm text-gray-500 uppercase tracking-widest font-medium">Integra com o que você já usa</p>
          </div>
          <div className="relative">
            <div className="absolute left-0 top-0 bottom-0 w-24 z-10"
              style={{ background: 'linear-gradient(to right, #0a0a0f, transparent)' }} />
            <div className="absolute right-0 top-0 bottom-0 w-24 z-10"
              style={{ background: 'linear-gradient(to left, #0a0a0f, transparent)' }} />
            <div className="flex gap-4 animate-badge-scroll" style={{ width: 'max-content' }}>
              {INTEGRATIONS.map((name, i) => (
                <div key={i}
                  className="shrink-0 bg-dark-800 border border-dark-700 rounded-xl px-5 py-2.5 text-sm text-gray-400 font-medium whitespace-nowrap hover:border-dark-600 hover:text-gray-300 transition-colors">
                  {name}
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── PRICING ──────────────────────────────────────────────────────── */}
        <section id="pricing" className="py-24 max-w-6xl mx-auto px-4 sm:px-6">
          <div className="text-center mb-16">
            <div className="inline-flex items-center gap-2 text-xs text-red-400 font-mono bg-red-950/40 border border-red-900/40 rounded-full px-4 py-1.5 mb-5">
              <Briefcase size={12} />
              Planos transparentes
            </div>
            <h2 className="text-4xl sm:text-5xl font-black text-white mb-4">Preços</h2>
            <p className="text-gray-400">Sem surpresas. Cancele quando quiser.</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
            {PRICING.map((p, i) => (
              <PricingCard key={i} {...p} onCta={goLogin} />
            ))}
          </div>
        </section>

        {/* ── SOCIAL PROOF ─────────────────────────────────────────────────── */}
        <section className="py-24 border-t border-white/5"
          style={{ background: 'linear-gradient(180deg, transparent 0%, rgba(220,38,38,0.03) 50%, transparent 100%)' }}>
          <div className="max-w-6xl mx-auto px-4 sm:px-6">
            <div className="text-center mb-14">
              <h2 className="text-4xl font-black text-white mb-3">O que dizem os times de segurança</h2>
              <p className="text-gray-400">Profissionais reais. Resultados reais.</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {TESTIMONIALS.map((t, i) => <TestimonialCard key={i} {...t} />)}
            </div>
          </div>
        </section>

        {/* ── CTA FINAL ────────────────────────────────────────────────────── */}
        <section className="py-24 max-w-5xl mx-auto px-4 sm:px-6">
          <div className="relative rounded-3xl overflow-hidden text-center px-8 py-16"
            style={{
              background: 'linear-gradient(135deg, #1a0505 0%, #2d0a0a 50%, #1a0505 100%)',
              border: '1px solid rgba(220,38,38,0.3)',
              boxShadow: '0 0 80px rgba(220,38,38,0.15)',
            }}>
            <div className="absolute inset-0 pointer-events-none" style={{
              backgroundImage: `linear-gradient(rgba(220,38,38,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(220,38,38,0.08) 1px, transparent 1px)`,
              backgroundSize: '30px 30px',
            }} />
            <div className="relative z-10">
              <div className="inline-flex items-center gap-2 bg-red-600/20 border border-red-600/40 rounded-full px-4 py-1.5 text-xs text-red-400 font-mono mb-6">
                <Crosshair size={12} />
                Zero-day simulation ready
              </div>
              <h2 className="text-4xl sm:text-5xl font-black text-white mb-4">
                Pronto para simular<br />seu próximo ataque?
              </h2>
              <p className="text-gray-300 text-lg mb-10 max-w-lg mx-auto">
                Configure sua primeira simulação em menos de 5 minutos.
                Sem cartão de crédito.
              </p>
              <button onClick={goLogin}
                className="inline-flex items-center gap-3 bg-white text-gray-900 hover:bg-gray-100 px-10 py-4 rounded-xl font-black text-lg transition-all duration-200 hover:scale-[1.03] hover:shadow-2xl">
                Solicitar Demo
                <ArrowRight size={20} />
              </button>
            </div>
          </div>
        </section>

        {/* ── FOOTER ───────────────────────────────────────────────────────── */}
        <footer className="border-t border-white/5 py-12"
          style={{ backgroundColor: 'rgba(6,6,10,0.9)' }}>
          <div className="max-w-6xl mx-auto px-4 sm:px-6">
            <div className="flex flex-col md:flex-row items-center justify-between gap-8 mb-8">
              <div className="flex items-center gap-1">
                <span className="text-xl font-black text-white font-mono">PENTE</span>
                <span className="text-xl font-black text-red-500 font-mono">[IA]</span>
                <span className="text-gray-600 text-sm ml-3 font-mono">v4.0</span>
              </div>

              <div className="flex flex-wrap justify-center gap-x-8 gap-y-2">
                {['Privacidade', 'Termos de Uso', 'LGPD', 'Segurança', 'Documentação', 'Status'].map((l, i) => (
                  <a key={i} href="#" className="text-sm text-gray-500 hover:text-gray-300 transition-colors">{l}</a>
                ))}
              </div>
            </div>

            <div className="flex flex-col md:flex-row items-center justify-between gap-4 pt-6 border-t border-white/5">
              <p className="text-xs text-gray-600">
                Desenvolvido por{' '}
                <a href="https://sec365.com.br" target="_blank" rel="noopener noreferrer"
                  className="text-red-500 hover:text-red-400 transition-colors font-medium">
                  sec365.com.br
                </a>
              </p>
              <p className="text-xs text-gray-700">
                © 2026 PenteIA. Todos os direitos reservados. Para uso ético e autorizado.
              </p>
            </div>
          </div>
        </footer>

      </div>
    </>
  )
}
