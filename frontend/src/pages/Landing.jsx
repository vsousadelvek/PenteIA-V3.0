import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Zap, Target, Eye, Terminal, Globe, Lock, CheckCircle,
  ArrowRight, ChevronDown, Activity, Layers, Radio, Brain,
  BarChart3, FileText, Crown, Briefcase, Play, Star, TrendingUp,
  AlertTriangle, Server, Cpu, Network, Database, Code2,
} from 'lucide-react'

// ─── Helpers ────────────────────────────────────────────────────────────────

function useCountUp(end, duration = 1500, start = false) {
  const [count, setCount] = useState(0)
  useEffect(() => {
    if (!start || !end) return
    let startTime = null
    const step = (ts) => {
      if (!startTime) startTime = ts
      const progress = Math.min((ts - startTime) / duration, 1)
      setCount(Math.floor(progress * end))
      if (progress < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [start, end, duration])
  return count
}

function useInView(ref) {
  const [visible, setVisible] = useState(false)
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) setVisible(true) }, { threshold: 0.2 })
    if (ref.current) obs.observe(ref.current)
    return () => obs.disconnect()
  }, [])
  return visible
}

// ─── Componentes ─────────────────────────────────────────────────────────────

function GlowDot({ color = 'bg-red-500' }) {
  return <span className={`inline-block w-2 h-2 rounded-full ${color} animate-pulse mr-2`} />
}

function StatCounter({ value, suffix = '', label, start }) {
  const n = useCountUp(value, 1200, start)
  return (
    <div className="text-center">
      <div className="text-4xl font-black text-white">{n.toLocaleString()}{suffix}</div>
      <div className="text-sm text-gray-500 mt-1">{label}</div>
    </div>
  )
}

function FeatureCard({ Icon, title, desc, color = 'text-red-400', badge }) {
  return (
    <div className="group relative bg-dark-800 border border-dark-700 hover:border-dark-500 rounded-2xl p-6 transition-all duration-300 hover:-translate-y-1 hover:shadow-xl hover:shadow-black/40">
      {badge && (
        <span className="absolute top-4 right-4 text-xs bg-red-900/40 text-red-400 border border-red-800/50 rounded-full px-2 py-0.5 font-semibold">
          {badge}
        </span>
      )}
      <div className={`w-10 h-10 rounded-xl bg-dark-700 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform ${color}`}>
        <Icon className="w-5 h-5" />
      </div>
      <h3 className="font-bold text-gray-100 mb-2">{title}</h3>
      <p className="text-sm text-gray-500 leading-relaxed">{desc}</p>
    </div>
  )
}

function PricingCard({ plan, onCTA }) {
  const featured = plan.featured
  return (
    <div className={`relative rounded-2xl p-6 flex flex-col border-2 transition-all duration-300 ${featured ? 'border-red-600 bg-gradient-to-b from-red-950/30 to-dark-800 shadow-2xl shadow-red-900/20 scale-105' : 'border-dark-600 bg-dark-800 hover:border-dark-500'}`}>
      {featured && (
        <div className="absolute -top-4 left-1/2 -translate-x-1/2 bg-red-600 text-white text-xs font-bold px-4 py-1 rounded-full shadow-lg">
          MAIS POPULAR
        </div>
      )}
      <div className="flex items-center gap-2 mb-2">
        <plan.Icon className={`w-5 h-5 ${plan.color}`} />
        <span className={`font-bold text-lg ${plan.color}`}>{plan.name}</span>
      </div>
      <div className="mb-1">
        <span className="text-4xl font-black text-white">{plan.price}</span>
        {plan.period && <span className="text-gray-500 text-sm ml-1">{plan.period}</span>}
      </div>
      <p className="text-xs text-gray-600 mb-5">{plan.desc}</p>

      <ul className="space-y-2.5 mb-6 flex-1">
        {plan.features.map((f, i) => (
          <li key={i} className="flex items-start gap-2 text-sm text-gray-400">
            <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
            {f}
          </li>
        ))}
      </ul>

      <div className="space-y-2">
        <div className="text-xs text-gray-600 border-t border-dark-700 pt-3 mb-2">Limites de ataque</div>
        {plan.limits.map((l, i) => (
          <div key={i} className="flex justify-between text-xs">
            <span className="text-gray-600">{l.label}</span>
            <span className={`font-mono font-semibold ${plan.color}`}>{l.value}</span>
          </div>
        ))}
      </div>

      <button
        onClick={() => onCTA(plan)}
        className={`mt-5 w-full py-3 rounded-xl font-bold text-sm transition-all ${featured ? 'bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-900/30' : 'bg-dark-700 hover:bg-dark-600 text-gray-200 border border-dark-600'}`}
      >
        {plan.cta}
      </button>
    </div>
  )
}

function TechBadge({ label }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-mono bg-dark-800 border border-dark-700 text-gray-400 px-3 py-1.5 rounded-lg">
      <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
      {label}
    </span>
  )
}

// ─── Data ────────────────────────────────────────────────────────────────────

const FEATURES = [
  { Icon: Target, title: 'BAS — Breach & Attack Simulation', desc: 'Simule APTs, ransomware e kill chains completas com cobertura MITRE ATT&CK. Score em tempo real, grafo de ataque e benchmark por setor.', badge: 'Core', color: 'text-red-400' },
  { Icon: Zap, title: 'DDoS Testing', desc: 'HTTP Flood, UDP Flood, Slowloris, SYN Flood e ICMP Flood contra alvos autorizados. Controle por threads, PPS e duração.', color: 'text-orange-400' },
  { Icon: Eye, title: 'Reconhecimento', desc: 'Port scan paralelo, DNS recon, CDN fingerprint, cloud asset discovery (AWS, Azure, GCP) e subdomain enumeration.', color: 'text-yellow-400' },
  { Icon: Radio, title: 'C2 Framework', desc: 'Servidor de comando e controle integrado. Agentes multi-plataforma, beacon configurável e canal HTTPS cifrado.', color: 'text-green-400' },
  { Icon: Globe, title: 'Phishing & Human Sim', desc: 'Campanhas de phishing, clonagem de páginas, rastreamento de cliques e simulação de engenharia social por email.', color: 'text-cyan-400' },
  { Icon: Brain, title: 'IA & Cenários', desc: 'Geração automática de cenários de ataque via LLM. Sugestões de TTPs por setor, análise de risco e mitigação automatizada.', badge: 'IA', color: 'text-purple-400' },
  { Icon: Shield, title: 'Purple Team', desc: 'Pipeline ataque → detecção → resposta. Valida a cadeia SOC completa e mede MTTD/MTTR do seu time defensivo.', color: 'text-blue-400' },
  { Icon: Lock, title: 'Compliance & BACEN', desc: 'Checklist LGPD, ISO 27001, CIS Controls e framework BACEN 4.557 para instituições financeiras brasileiras.', color: 'text-pink-400' },
  { Icon: Terminal, title: 'Execution Engine', desc: 'Execução real de técnicas MITRE com evasão EDR: AMSI bypass, process hollowing, reflective DLL e mais.', badge: 'Avançado', color: 'text-red-300' },
  { Icon: BarChart3, title: 'Relatórios Executivos', desc: 'PDF, DOCX, XLSX com score, heatmap ATT&CK, cronograma e recomendações. Pronto para apresentar ao board.', color: 'text-indigo-400' },
  { Icon: Layers, title: 'APT Simulation', desc: 'Emula grupos APT reais (Lazarus, Cozy Bear, TA505) com TTPs históricos documentados e IoCs associados.', color: 'text-orange-300' },
  { Icon: Activity, title: 'EPSS & VulnDB', desc: 'Score de exploitabilidade em tempo real (EPSS), CVE feed do CISA KEV e correlação automática com ativos.', color: 'text-teal-400' },
]

const TECH_STACK = [
  'MITRE ATT&CK v14', 'CISA KEV', 'EPSS', 'CVSS 3.1', 'OWASP Top 10',
  'ISO 27001', 'LGPD', 'BACEN 4.557', 'CIS Controls v8',
  'NIST CSF', 'Wazuh Rules', 'Sigma Rules',
]

const PLANS = [
  {
    name: 'Free',
    price: 'R$ 0',
    period: '',
    desc: '10 min vitalícios — teste e explore a plataforma',
    Icon: Zap,
    color: 'text-gray-400',
    cta: 'Começar grátis',
    features: [
      'Todas as ferramentas desbloqueadas',
      '1 ataque simultâneo',
      'BAS, DDoS, Recon, C2, Phishing',
      'Relatórios PDF',
    ],
    limits: [
      { label: 'Threads', value: '50' },
      { label: 'Pacotes/s', value: '1.000' },
      { label: 'Duração máx', value: '60s' },
    ],
  },
  {
    name: 'Researcher',
    price: 'R$ 49',
    period: '/mês',
    desc: 'Para pesquisadores e pentesters individuais',
    Icon: Shield,
    color: 'text-blue-400',
    cta: 'Assinar via PIX',
    features: [
      '20 horas de ataque por mês',
      '2 ataques simultâneos',
      'Todas as ferramentas desbloqueadas',
      'Relatórios PDF/DOCX/XLSX',
      'Suporte via email',
    ],
    limits: [
      { label: 'Threads', value: '200' },
      { label: 'Pacotes/s', value: '10.000' },
      { label: 'Duração máx', value: '300s' },
    ],
  },
  {
    name: 'Pro',
    price: 'R$ 149',
    period: '/mês',
    desc: 'Para equipes de segurança e red teams',
    Icon: Crown,
    color: 'text-red-400',
    cta: 'Assinar via PIX',
    featured: true,
    features: [
      '80 horas de ataque por mês',
      '5 ataques simultâneos',
      'Todas as ferramentas desbloqueadas',
      'APT + Execution Engine avançado',
      'Horas extras disponíveis',
    ],
    limits: [
      { label: 'Threads', value: '500' },
      { label: 'Pacotes/s', value: '50.000' },
      { label: 'Duração máx', value: '600s' },
    ],
  },
  {
    name: 'Business',
    price: 'R$ 499',
    period: '/mês',
    desc: 'Para MSSPs e grandes equipes de segurança',
    Icon: Briefcase,
    color: 'text-yellow-400',
    cta: 'Assinar via PIX',
    features: [
      'Tempo ilimitado de ataque',
      '15 ataques simultâneos',
      'Multi-tenant (MSSP)',
      'Compliance BACEN + relatórios auditoria',
      'Suporte prioritário',
    ],
    limits: [
      { label: 'Threads', value: '1.000' },
      { label: 'Pacotes/s', value: '200.000' },
      { label: 'Duração máx', value: '3.600s' },
    ],
  },
]

const HOW_IT_WORKS = [
  { step: '01', title: 'Cadastre-se e acesse', desc: 'Crie sua conta grátis. Todas as ferramentas já estão disponíveis — sem configuração.' },
  { step: '02', title: 'Configure o alvo', desc: 'Informe o host autorizado, selecione o playbook ou configure manualmente o ataque.' },
  { step: '03', title: 'Analise e reporte', desc: 'Resultados em tempo real. Score MITRE, grafo de ataque e relatório executivo em PDF.' },
]

// ─── Landing ─────────────────────────────────────────────────────────────────

export default function Landing() {
  const navigate = useNavigate()
  const statsRef = useRef(null)
  const statsVisible = useInView(statsRef)
  const [menuOpen, setMenuOpen] = useState(false)

  const handleCTA = (plan) => {
    if (plan.name === 'Free') {
      navigate('/login')
    } else {
      localStorage.setItem('pending_plan', plan.name.toLowerCase())
      navigate('/login')
    }
  }

  return (
    <div className="min-h-screen bg-dark-900 text-gray-100 overflow-x-hidden">

      {/* ── Nav ─────────────────────────────────────────────────────────────── */}
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-dark-700/50 bg-dark-900/80 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-red-600 rounded-lg flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="text-lg font-black tracking-tight">
              Pente<span className="text-red-500">IA</span>
              <span className="text-xs text-gray-600 font-normal ml-1">v4.0</span>
            </span>
          </div>

          <div className="hidden md:flex items-center gap-8 text-sm text-gray-400">
            <a href="#features" className="hover:text-gray-200 transition">Funcionalidades</a>
            <a href="#how" className="hover:text-gray-200 transition">Como funciona</a>
            <a href="#pricing" className="hover:text-gray-200 transition">Planos</a>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/login')}
              className="hidden md:block text-sm text-gray-400 hover:text-gray-200 transition"
            >
              Entrar
            </button>
            <button
              onClick={() => navigate('/login')}
              className="text-sm bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded-lg font-semibold transition"
            >
              Criar conta grátis
            </button>
          </div>
        </div>
      </nav>

      {/* ── Hero ────────────────────────────────────────────────────────────── */}
      <section className="relative pt-32 pb-24 px-6 overflow-hidden">
        {/* Background grid */}
        <div className="absolute inset-0 opacity-[0.03]" style={{
          backgroundImage: 'linear-gradient(#ff4444 1px, transparent 1px), linear-gradient(90deg, #ff4444 1px, transparent 1px)',
          backgroundSize: '60px 60px',
        }} />
        {/* Glow */}
        <div className="absolute top-20 left-1/2 -translate-x-1/2 w-[600px] h-[400px] bg-red-600/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative max-w-5xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 text-xs bg-dark-800 border border-dark-600 rounded-full px-4 py-2 mb-8">
            <GlowDot color="bg-green-500" />
            <span className="text-gray-400">Plataforma online · Sem instalação · Pagamento via PIX</span>
          </div>

          <h1 className="text-5xl md:text-7xl font-black leading-tight tracking-tight mb-6">
            A plataforma de
            <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-orange-400">
              segurança ofensiva
            </span>
            <br />
            do time defensivo
          </h1>

          <p className="text-xl text-gray-400 max-w-2xl mx-auto mb-10 leading-relaxed">
            BAS, DDoS Testing, C2, Phishing, APT Simulation e muito mais —
            tudo em uma plataforma. Pague por tempo de uso, não por feature.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
            <button
              onClick={() => navigate('/login')}
              className="flex items-center gap-2 bg-red-600 hover:bg-red-500 text-white px-8 py-4 rounded-xl font-bold text-base transition-all hover:scale-105 shadow-xl shadow-red-900/30"
            >
              <Play className="w-5 h-5" />
              Começar grátis agora
            </button>
            <a
              href="#pricing"
              className="flex items-center gap-2 border border-dark-600 hover:border-dark-400 text-gray-300 px-8 py-4 rounded-xl font-semibold text-base transition-all"
            >
              Ver planos e preços
              <ChevronDown className="w-4 h-4" />
            </a>
          </div>

          {/* Terminal mockup */}
          <div className="max-w-2xl mx-auto bg-dark-800 border border-dark-700 rounded-2xl overflow-hidden shadow-2xl shadow-black/60 text-left">
            <div className="flex items-center gap-2 px-4 py-3 bg-dark-700 border-b border-dark-600">
              <div className="w-3 h-3 rounded-full bg-red-500" />
              <div className="w-3 h-3 rounded-full bg-yellow-500" />
              <div className="w-3 h-3 rounded-full bg-green-500" />
              <span className="ml-3 text-xs text-gray-600 font-mono">penteia — BAS simulation</span>
            </div>
            <div className="p-5 font-mono text-sm space-y-2">
              <p><span className="text-red-400">❯</span> <span className="text-gray-300">penteia bas run --target 192.168.1.0/24 --playbook apt-lazarus</span></p>
              <p className="text-gray-600"># Iniciando simulação APT Lazarus Group...</p>
              <p><span className="text-green-400">✓</span> <span className="text-gray-400">Recon completo: 14 hosts descobertos</span></p>
              <p><span className="text-green-400">✓</span> <span className="text-gray-400">Lateral movement: T1021.002 (SMB) executado</span></p>
              <p><span className="text-green-400">✓</span> <span className="text-gray-400">Credential dumping: T1003.001 detectado</span></p>
              <p><span className="text-yellow-400">⚠</span> <span className="text-gray-400">C2 beacon: T1071.001 — EDR não detectou</span></p>
              <p><span className="text-red-400">✗</span> <span className="text-gray-400">Exfiltration: T1041 bloqueado pelo DLP</span></p>
              <p className="pt-2"><span className="text-purple-400">Score de exposição:</span> <span className="text-white font-bold">73.4/100</span> <span className="text-gray-600">— Alto risco</span></p>
              <p className="text-gray-600 text-xs mt-1 animate-pulse">■ Gerando relatório executivo...</p>
            </div>
          </div>
        </div>
      </section>

      {/* ── Stats ───────────────────────────────────────────────────────────── */}
      <div ref={statsRef} className="border-y border-dark-700 bg-dark-800/50 py-12">
        <div className="max-w-5xl mx-auto px-6 grid grid-cols-2 md:grid-cols-4 gap-8">
          <StatCounter value={300} suffix="+" label="Técnicas MITRE ATT&CK" start={statsVisible} />
          <StatCounter value={12} suffix="+" label="Módulos de ataque" start={statsVisible} />
          <StatCounter value={4} suffix="" label="Grupos APT emulados" start={statsVisible} />
          <StatCounter value={99} suffix="%" label="Uptime da plataforma" start={statsVisible} />
        </div>
      </div>

      {/* ── Features ────────────────────────────────────────────────────────── */}
      <section id="features" className="py-24 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <div className="inline-block text-xs font-semibold text-red-400 bg-red-950/40 border border-red-900/40 rounded-full px-4 py-1.5 mb-4">
              12 MÓDULOS INTEGRADOS
            </div>
            <h2 className="text-4xl md:text-5xl font-black mb-4">
              Tudo que um red team precisa,<br />
              <span className="text-gray-500">em uma plataforma só</span>
            </h2>
            <p className="text-gray-500 max-w-xl mx-auto">
              Sem instalar ferramentas. Sem gerenciar infraestrutura.
              Acesse do navegador e comece em minutos.
            </p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {FEATURES.map((f, i) => <FeatureCard key={i} {...f} />)}
          </div>
        </div>
      </section>

      {/* ── Tech compliance ─────────────────────────────────────────────────── */}
      <div className="border-y border-dark-700 py-10 px-6 bg-dark-800/30">
        <div className="max-w-5xl mx-auto">
          <p className="text-center text-xs text-gray-600 uppercase tracking-widest mb-6">Frameworks & Padrões suportados</p>
          <div className="flex flex-wrap justify-center gap-2">
            {TECH_STACK.map((t, i) => <TechBadge key={i} label={t} />)}
          </div>
        </div>
      </div>

      {/* ── How it works ────────────────────────────────────────────────────── */}
      <section id="how" className="py-24 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-black mb-4">Como funciona</h2>
            <p className="text-gray-500">Três passos do cadastro ao relatório</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 relative">
            <div className="hidden md:block absolute top-10 left-1/3 right-1/3 h-px bg-gradient-to-r from-transparent via-dark-600 to-transparent" />
            {HOW_IT_WORKS.map((h, i) => (
              <div key={i} className="relative text-center bg-dark-800 border border-dark-700 rounded-2xl p-8">
                <div className="w-14 h-14 mx-auto rounded-2xl bg-dark-700 border border-dark-600 flex items-center justify-center mb-4">
                  <span className="text-2xl font-black text-red-400">{h.step}</span>
                </div>
                <h3 className="font-bold text-lg text-gray-100 mb-2">{h.title}</h3>
                <p className="text-sm text-gray-500 leading-relaxed">{h.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Ataque force info ───────────────────────────────────────────────── */}
      <section className="py-16 px-6 bg-dark-800/30 border-y border-dark-700">
        <div className="max-w-4xl mx-auto">
          <div className="flex flex-col md:flex-row items-start gap-12">
            <div className="flex-1">
              <div className="text-xs font-semibold text-orange-400 mb-3 uppercase tracking-widest">Por que limitar a força?</div>
              <h3 className="text-2xl font-black text-gray-100 mb-4">
                Intensidade controlada, resultados reais
              </h3>
              <p className="text-gray-500 text-sm leading-relaxed mb-4">
                Cada plano tem um cap de força de ataque (threads, pacotes/s, duração). Isso protege
                a infraestrutura compartilhada e garante que testes não causem dano não autorizado.
              </p>
              <p className="text-gray-500 text-sm leading-relaxed">
                O plano <strong className="text-gray-300">Free</strong> já tem potência suficiente para derrubar um
                servidor simples de teste. Planos pagos escalam linearmente para
                infraestrutura enterprise.
              </p>
            </div>
            <div className="flex-1 space-y-3">
              {[
                { plan: 'Free', color: 'bg-gray-600', pct: 5, threads: '50', pps: '1.000' },
                { plan: 'Researcher', color: 'bg-blue-600', pct: 20, threads: '200', pps: '10.000' },
                { plan: 'Pro', color: 'bg-red-600', pct: 50, threads: '500', pps: '50.000' },
                { plan: 'Business', color: 'bg-yellow-500', pct: 100, threads: '1.000', pps: '200.000' },
              ].map(row => (
                <div key={row.plan}>
                  <div className="flex justify-between text-xs text-gray-500 mb-1">
                    <span className="font-semibold text-gray-300">{row.plan}</span>
                    <span className="font-mono">{row.threads} threads · {row.pps} pps</span>
                  </div>
                  <div className="h-2 bg-dark-700 rounded-full overflow-hidden">
                    <div className={`h-2 rounded-full ${row.color} transition-all duration-1000`} style={{ width: `${row.pct}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── Pricing ─────────────────────────────────────────────────────────── */}
      <section id="pricing" className="py-24 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-6">
            <div className="inline-block text-xs font-semibold text-green-400 bg-green-950/40 border border-green-900/40 rounded-full px-4 py-1.5 mb-4">
              PAGUE VIA PIX · SEM CARTÃO · SEM ASSINATURA AUTOMÁTICA
            </div>
            <h2 className="text-4xl md:text-5xl font-black mb-4">Preços simples e honestos</h2>
            <p className="text-gray-500 max-w-lg mx-auto">
              Pague por <strong className="text-gray-300">tempo de uso</strong>, não por feature.
              Todas as funcionalidades disponíveis em qualquer plano.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6 items-start mt-12">
            {PLANS.map((plan, i) => (
              <PricingCard key={i} plan={plan} onCTA={handleCTA} />
            ))}
          </div>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-6 text-sm text-gray-600">
            <span className="flex items-center gap-1.5"><CheckCircle className="w-4 h-4 text-green-500" /> Renovação manual via PIX</span>
            <span className="flex items-center gap-1.5"><CheckCircle className="w-4 h-4 text-green-500" /> Sem cobrança automática</span>
            <span className="flex items-center gap-1.5"><CheckCircle className="w-4 h-4 text-green-500" /> Horas extras disponíveis</span>
            <span className="flex items-center gap-1.5"><CheckCircle className="w-4 h-4 text-green-500" /> Cancele quando quiser</span>
          </div>
        </div>
      </section>

      {/* ── CTA Final ───────────────────────────────────────────────────────── */}
      <section className="py-24 px-6 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-red-950/10 to-transparent pointer-events-none" />
        <div className="relative max-w-3xl mx-auto text-center">
          <div className="w-16 h-16 mx-auto rounded-2xl bg-red-600/20 border border-red-600/30 flex items-center justify-center mb-6">
            <Shield className="w-8 h-8 text-red-400" />
          </div>
          <h2 className="text-4xl md:text-5xl font-black mb-4">
            Pronto para testar sua segurança?
          </h2>
          <p className="text-gray-500 mb-10 text-lg">
            Crie sua conta grátis e tenha 10 minutos de ataque sem custo.
            Sem cartão. Sem burocracia.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <button
              onClick={() => navigate('/login')}
              className="flex items-center gap-2 bg-red-600 hover:bg-red-500 text-white px-10 py-4 rounded-xl font-bold text-base transition-all hover:scale-105 shadow-xl shadow-red-900/30"
            >
              Criar conta grátis
              <ArrowRight className="w-5 h-5" />
            </button>
          </div>
          <p className="mt-6 text-xs text-gray-700">
            Uso exclusivo em ambientes autorizados. Consulte os termos de uso.
          </p>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────────────────────── */}
      <footer className="border-t border-dark-700 py-12 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 bg-red-600 rounded-lg flex items-center justify-center">
                <Shield className="w-4 h-4 text-white" />
              </div>
              <span className="font-black">Pente<span className="text-red-500">IA</span></span>
              <span className="text-gray-700 text-sm">v4.0</span>
            </div>

            <div className="flex gap-6 text-sm text-gray-600">
              <a href="#features" className="hover:text-gray-400 transition">Funcionalidades</a>
              <a href="#pricing" className="hover:text-gray-400 transition">Preços</a>
              <button onClick={() => navigate('/login')} className="hover:text-gray-400 transition">Login</button>
            </div>

            <div className="text-xs text-gray-700 text-center md:text-right">
              <p>Plataforma de segurança ofensiva para uso autorizado.</p>
              <p className="mt-1">© 2026 PenteIA · Todos os direitos reservados</p>
            </div>
          </div>
        </div>
      </footer>

    </div>
  )
}
