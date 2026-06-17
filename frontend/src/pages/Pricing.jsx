import React from 'react'
import { Check, Zap, Shield, Building2, Star } from 'lucide-react'

const PLANS = [
  {
    name: 'Free',
    price: 'R$ 0',
    period: '/mês',
    description: 'Para explorar a plataforma e projetos pessoais',
    Icon: Zap,
    color: 'border-dark-600',
    headerColor: 'text-gray-300',
    btn: 'Começar grátis',
    btnClass: 'bg-dark-700 hover:bg-dark-600 text-gray-200',
    features: [
      '1 usuário',
      '10 simulações BAS/mês',
      '5 técnicas MITRE por simulação',
      'Reconhecimento básico (DNS, IP)',
      'Relatório PDF simples',
      'VulnDB (últimos 30 dias)',
      'Suporte via comunidade',
    ],
    limits: ['Sem C2 Framework', 'Sem módulo DDoS', 'Sem exportação Wazuh'],
  },
  {
    name: 'Pro',
    price: 'R$ 490',
    period: '/mês',
    description: 'Para pentesters e equipes de segurança',
    Icon: Shield,
    color: 'border-red-700',
    headerColor: 'text-red-400',
    btn: 'Iniciar trial 14 dias',
    btnClass: 'bg-red-700 hover:bg-red-600 text-white',
    badge: 'Mais popular',
    features: [
      'Até 5 usuários',
      'Simulações BAS ilimitadas',
      'Todas as técnicas MITRE (17+)',
      'Recon completo (CDN, CloudFail, Serverless)',
      'C2 Framework completo',
      'DDoS Testing (todos os métodos)',
      'Phishing / Human Simulation',
      'SOC Chain Validation',
      'Remediation Tracker (kanban + SLA)',
      'Relatórios PDF/DOCX/XLSX',
      'Exportação Wazuh Rules',
      'ATT&CK Matrix completa',
      'Suporte prioritário (email)',
    ],
    limits: [],
  },
  {
    name: 'Enterprise',
    price: 'Sob consulta',
    period: '',
    description: 'Para MSSPs e grandes organizações',
    Icon: Building2,
    color: 'border-purple-700',
    headerColor: 'text-purple-400',
    btn: 'Falar com vendas',
    btnClass: 'bg-purple-700 hover:bg-purple-600 text-white',
    features: [
      'Usuários ilimitados',
      'Multi-tenant isolado',
      'Microsoft Sentinel Integration',
      'Wazuh + SIEM customizados',
      'LLM Narrative nos relatórios',
      'Cloud Identity (AWS IAM + Entra ID)',
      'White-label (logo próprio)',
      'Deploy on-premise ou cloud privada',
      'SLA 99.9% uptime',
      'Treinamento e onboarding dedicado',
      'Integração Jira/ServiceNow',
      'Suporte 24/7',
    ],
    limits: [],
  },
]

export default function Pricing() {
  return (
    <div className="min-h-screen bg-dark-900 px-6 py-12">
      <div className="max-w-5xl mx-auto space-y-12">
        <div className="text-center space-y-4">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-red-900/30 border border-red-800/50 text-red-400 text-sm">
            <Zap className="w-4 h-4" /> Red Team Platform
          </div>
          <h1 className="text-4xl font-bold text-gray-100">
            Planos e Preços
          </h1>
          <p className="text-gray-400 max-w-xl mx-auto">
            Do pentest individual ao MSSP enterprise. Escolha o plano que se encaixa no seu contexto.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {PLANS.map(plan => (
            <div key={plan.name} className={`relative rounded-2xl border-2 ${plan.color} bg-dark-800 p-6 flex flex-col`}>
              {plan.badge && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                  <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full bg-red-700 text-white text-xs font-bold">
                    <Star className="w-3 h-3" /> {plan.badge}
                  </span>
                </div>
              )}

              <div className="flex items-center gap-3 mb-4">
                <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${plan.name === 'Free' ? 'bg-dark-700' : plan.name === 'Pro' ? 'bg-red-900/30' : 'bg-purple-900/30'}`}>
                  <plan.Icon className={`w-5 h-5 ${plan.headerColor}`} />
                </div>
                <div>
                  <h2 className={`font-bold text-lg ${plan.headerColor}`}>{plan.name}</h2>
                  <p className="text-xs text-gray-500">{plan.description}</p>
                </div>
              </div>

              <div className="mb-6">
                <span className="text-3xl font-bold text-gray-100">{plan.price}</span>
                {plan.period && <span className="text-gray-500 text-sm">{plan.period}</span>}
              </div>

              <button className={`w-full py-2.5 rounded-lg text-sm font-semibold transition mb-6 ${plan.btnClass}`}>
                {plan.btn}
              </button>

              <div className="flex-1 space-y-2">
                {plan.features.map(f => (
                  <div key={f} className="flex items-start gap-2 text-sm">
                    <Check className="w-4 h-4 text-green-500 shrink-0 mt-0.5" />
                    <span className="text-gray-300">{f}</span>
                  </div>
                ))}
                {plan.limits.map(f => (
                  <div key={f} className="flex items-start gap-2 text-sm opacity-40">
                    <span className="w-4 h-4 text-gray-600 shrink-0 mt-0.5 text-center leading-none">✕</span>
                    <span className="text-gray-500">{f}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="card-dark p-8 text-center space-y-3">
          <h2 className="text-xl font-bold text-gray-100">Tem dúvidas?</h2>
          <p className="text-gray-400">Fale com nossa equipe para um orçamento personalizado ou para uma demonstração.</p>
          <div className="flex flex-wrap justify-center gap-4 pt-2">
            <a href="mailto:comercial@penteia.com.br" className="px-6 py-2.5 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-semibold transition">
              comercial@penteia.com.br
            </a>
            <a href="/dashboard" className="px-6 py-2.5 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded-lg text-sm transition">
              Acessar plataforma →
            </a>
          </div>
        </div>

        <p className="text-center text-xs text-gray-600">
          Preços em BRL. Plano Pro com faturamento mensal ou anual (20% de desconto).
          Cancelamento a qualquer momento. Sem contratos de longo prazo obrigatórios.
        </p>
      </div>
    </div>
  )
}
