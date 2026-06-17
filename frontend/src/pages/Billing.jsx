import React, { useState, useEffect, useCallback } from 'react'
import { Clock, Zap, CheckCircle, XCircle, RefreshCw, Copy, AlertTriangle, Crown, Shield, Briefcase } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

const PLAN_META = {
  free:       { label: 'Free',       color: 'text-gray-400',   border: 'border-gray-700',   bg: 'bg-gray-900/30',   icon: Shield },
  researcher: { label: 'Researcher', color: 'text-blue-400',   border: 'border-blue-700',   bg: 'bg-blue-900/20',   icon: Zap },
  pro:        { label: 'Pro',        color: 'text-purple-400', border: 'border-purple-700', bg: 'bg-purple-900/20', icon: Crown },
  business:   { label: 'Business',   color: 'text-yellow-400', border: 'border-yellow-700', bg: 'bg-yellow-900/20', icon: Briefcase },
}

const PLANS_ORDER = ['researcher', 'pro', 'business']

function MinutesBar({ used, quota, unlimited }) {
  if (unlimited) return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 rounded-full bg-dark-700">
        <div className="h-2 rounded-full bg-yellow-500" style={{ width: '100%' }} />
      </div>
      <span className="text-xs text-yellow-400 font-semibold">Ilimitado</span>
    </div>
  )
  const pct = quota ? Math.min(100, (used / quota) * 100) : 100
  const color = pct > 80 ? 'bg-red-500' : pct > 50 ? 'bg-yellow-500' : 'bg-green-500'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 rounded-full bg-dark-700">
        <div className={`h-2 rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-gray-400">{Math.round((quota - used) / 60 * 10) / 10}h restantes</span>
    </div>
  )
}

function QRCodeModal({ deposit, onClose, onConfirmed }) {
  const [checking, setChecking] = useState(false)
  const [status, setStatus] = useState('pending')
  const { add: toast } = useToast()

  const copyCode = () => {
    navigator.clipboard.writeText(deposit.qr_code)
    toast({ type: 'success', message: 'Código PIX copiado!' })
  }

  const checkStatus = useCallback(async () => {
    setChecking(true)
    try {
      const res = await api.get(`/api/billing/deposit/${deposit.deposit_id}`)
      setStatus(res.data.status)
      if (res.data.status === 'confirmed') {
        toast({ type: 'success', message: 'Pagamento confirmado! Plano ativado.' })
        onConfirmed()
      } else if (res.data.status === 'expired') {
        toast({ type: 'error', message: 'PIX expirado. Gere um novo.' })
      }
    } catch {
      toast({ type: 'error', message: 'Erro ao verificar pagamento.' })
    } finally {
      setChecking(false)
    }
  }, [deposit.deposit_id])

  // Poll automático a cada 10s
  useEffect(() => {
    if (status !== 'pending') return
    const interval = setInterval(checkStatus, 10000)
    return () => clearInterval(interval)
  }, [checkStatus, status])

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="card-dark w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-bold text-gray-100">Pague via PIX</h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300">✕</button>
        </div>

        {status === 'confirmed' ? (
          <div className="text-center py-8 space-y-3">
            <CheckCircle className="w-16 h-16 text-green-400 mx-auto" />
            <p className="text-green-400 font-semibold text-lg">Pagamento confirmado!</p>
            <p className="text-gray-400 text-sm">Seu plano foi ativado com sucesso.</p>
            <button onClick={onClose} className="btn-blue mt-4">Fechar</button>
          </div>
        ) : status === 'expired' ? (
          <div className="text-center py-8 space-y-3">
            <XCircle className="w-16 h-16 text-red-400 mx-auto" />
            <p className="text-red-400 font-semibold">PIX expirado</p>
            <button onClick={onClose} className="btn-blue mt-2">Tentar novamente</button>
          </div>
        ) : (
          <>
            <div className="bg-dark-700 rounded-xl p-4 space-y-2">
              <p className="text-xs text-gray-500 uppercase tracking-wide">Valor</p>
              <p className="text-3xl font-black text-gray-100">R$ {deposit.amount_brl},00</p>
              {deposit.plan_label && (
                <p className="text-sm text-gray-400">Plano {deposit.plan_label} — 30 dias</p>
              )}
              {deposit.pack_label && (
                <p className="text-sm text-gray-400">{deposit.pack_label}</p>
              )}
            </div>

            <div className="bg-dark-700 rounded-xl p-4 space-y-3">
              <p className="text-xs text-gray-500 uppercase tracking-wide">PIX Copia e Cola</p>
              <div className="font-mono text-xs text-gray-300 break-all bg-dark-800 rounded-lg p-3 max-h-24 overflow-y-auto">
                {deposit.qr_code}
              </div>
              <button
                onClick={copyCode}
                className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-500 text-white py-2.5 rounded-lg text-sm font-semibold transition"
              >
                <Copy className="w-4 h-4" />
                Copiar código PIX
              </button>
            </div>

            <div className="flex items-center gap-3 text-sm text-gray-500">
              <div className="w-2 h-2 rounded-full bg-yellow-400 animate-pulse" />
              Aguardando confirmação...
              <button
                onClick={checkStatus}
                disabled={checking}
                className="ml-auto text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
              >
                <RefreshCw className={`w-3 h-3 ${checking ? 'animate-spin' : ''}`} />
                Verificar
              </button>
            </div>

            <p className="text-xs text-gray-600 text-center">PIX expira em 30 minutos</p>
          </>
        )}
      </div>
    </div>
  )
}

export default function Billing() {
  const [status, setStatus] = useState(null)
  const [plans, setPlans] = useState({})
  const [extras, setExtras] = useState({})
  const [deposits, setDeposits] = useState([])
  const [loading, setLoading] = useState(true)
  const [activeDeposit, setActiveDeposit] = useState(null)
  const [subscribing, setSubscribing] = useState(null)
  const { add: toast } = useToast()

  const fetchAll = useCallback(async () => {
    try {
      const [statusRes, plansRes, depositsRes] = await Promise.all([
        api.get('/api/billing/status'),
        api.get('/api/billing/plans'),
        api.get('/api/billing/deposits'),
      ])
      setStatus(statusRes.data)
      setPlans(plansRes.data.plans || {})
      setExtras(plansRes.data.extra_packs || {})
      setDeposits(depositsRes.data.deposits || [])
    } catch {
      toast({ type: 'error', message: 'Erro ao carregar dados de billing.' })
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchAll() }, [fetchAll])

  const handleSubscribe = async (plan) => {
    setSubscribing(plan)
    try {
      const res = await api.post('/api/billing/subscribe', { plan })
      setActiveDeposit({ ...res.data, plan_label: plans[plan]?.label })
    } catch (e) {
      toast({ type: 'error', message: e.response?.data?.detail || 'Erro ao gerar PIX.' })
    } finally {
      setSubscribing(null)
    }
  }

  const handleExtraHours = async (pack) => {
    setSubscribing(pack)
    try {
      const res = await api.post('/api/billing/extra-hours', { pack })
      setActiveDeposit({ ...res.data, pack_label: extras[pack]?.label })
    } catch (e) {
      toast({ type: 'error', message: e.response?.data?.detail || 'Erro ao gerar PIX.' })
    } finally {
      setSubscribing(null)
    }
  }

  const onPaymentConfirmed = () => {
    setActiveDeposit(null)
    fetchAll()
  }

  if (loading) return (
    <div className="flex items-center justify-center h-96">
      <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin" />
    </div>
  )

  const currentPlan = status?.plan || 'free'
  const meta = PLAN_META[currentPlan] || PLAN_META.free
  const PlanIcon = meta.icon

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      <div>
        <h1 className="text-3xl font-bold text-gray-100">Assinatura & Tempo</h1>
        <p className="text-gray-500 mt-1">Gerencie seu plano e compre horas de ataque via PIX</p>
      </div>

      {/* Status atual */}
      <div className={`card-dark p-6 border ${meta.border} ${meta.bg}`}>
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <PlanIcon className={`w-8 h-8 ${meta.color}`} />
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide">Plano atual</p>
              <p className={`text-2xl font-black ${meta.color}`}>{meta.label}</p>
            </div>
          </div>
          <div className="text-right">
            {status?.plan_active && status?.days_left !== null && (
              <p className="text-sm text-gray-400">{status.days_left} dias restantes</p>
            )}
            {status?.plan_expires_at && (
              <p className="text-xs text-gray-600">
                Vence: {new Date(status.plan_expires_at).toLocaleDateString('pt-BR')}
              </p>
            )}
          </div>
        </div>

        <div className="mt-5 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="bg-dark-800/60 rounded-xl p-4">
            <p className="text-xs text-gray-500 mb-1">Tempo restante</p>
            {status?.unlimited ? (
              <p className="text-xl font-bold text-yellow-400">Ilimitado</p>
            ) : (
              <p className="text-xl font-bold text-gray-100">{status?.hours_remaining ?? 0}h</p>
            )}
            <div className="mt-2">
              <MinutesBar
                used={status?.minutes_used || 0}
                quota={status?.minutes_quota}
                unlimited={status?.unlimited}
              />
            </div>
          </div>
          <div className="bg-dark-800/60 rounded-xl p-4">
            <p className="text-xs text-gray-500 mb-1">Ataques simultâneos</p>
            <p className="text-xl font-bold text-gray-100">
              {status?.active_attacks ?? 0}
              <span className="text-gray-500 text-sm font-normal"> / {status?.max_concurrent}</span>
            </p>
            <p className="text-xs text-gray-600 mt-1">ativos agora</p>
          </div>
          <div className="bg-dark-800/60 rounded-xl p-4">
            <p className="text-xs text-gray-500 mb-1">Uso total</p>
            <p className="text-xl font-bold text-gray-100">
              {Math.round((status?.minutes_used || 0) / 60 * 10) / 10}h
            </p>
            <p className="text-xs text-gray-600 mt-1">de {status?.unlimited ? '∞' : `${(status?.minutes_quota || 0) / 60}h`} do plano</p>
          </div>
        </div>

        {/* Força do ataque */}
        {status?.attack_limits && (
          <div className="mt-4 border border-dark-600 rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs text-gray-500 uppercase tracking-wide font-semibold">Força máxima de ataque</p>
              {currentPlan !== 'business' && (
                <span className="text-xs text-blue-400 cursor-pointer hover:underline" onClick={() => document.getElementById('plans-section')?.scrollIntoView({behavior:'smooth'})}>
                  Fazer upgrade ↓
                </span>
              )}
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: 'Threads', value: status.attack_limits.max_threads.toLocaleString(), why: 'Número de conexões paralelas. Mais threads = ataque mais intenso.' },
                { label: 'Pacotes/s', value: status.attack_limits.max_pps.toLocaleString(), why: 'Pacotes por segundo enviados ao alvo. Limita a saturação de banda.' },
                { label: 'Duração máx', value: `${status.attack_limits.max_duration}s`, why: 'Tempo máximo por sessão de ataque. Planos maiores = testes mais longos.' },
                { label: 'Workers recon', value: status.attack_limits.max_workers.toLocaleString(), why: 'Threads paralelas em port scan e BAS. Mais workers = scan mais rápido.' },
              ].map(item => (
                <div key={item.label} className="bg-dark-800/60 rounded-lg p-3 group relative cursor-help">
                  <p className="text-xs text-gray-500 mb-1">{item.label}</p>
                  <p className={`text-lg font-bold ${meta.color}`}>{item.value}</p>
                  <div className="absolute bottom-full left-0 mb-1 hidden group-hover:block z-10 w-52 bg-dark-700 border border-dark-500 rounded-lg p-2 text-xs text-gray-300 shadow-xl">
                    {item.why}
                    {currentPlan !== 'business' && (
                      <span className="block mt-1 text-blue-400">Faça upgrade para aumentar.</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
            {currentPlan === 'free' && (
              <p className="text-xs text-gray-600 mt-3">
                Suficiente para testar servidores simples. Para testes em infraestrutura real, faça upgrade para Researcher ou Pro.
              </p>
            )}
            {currentPlan === 'researcher' && (
              <p className="text-xs text-gray-600 mt-3">
                Ideal para labs e alvos de médio porte. O plano Pro oferece 2,5× mais threads e 5× mais PPS para engajamentos maiores.
              </p>
            )}
            {currentPlan === 'pro' && (
              <p className="text-xs text-gray-600 mt-3">
                Alto desempenho para auditorias. Business remove todos os limites com 1.000 threads e sem restrição de duração.
              </p>
            )}
          </div>
        )}

        {currentPlan === 'free' && (
          <div className="mt-4 flex items-start gap-2 bg-yellow-900/20 border border-yellow-800/40 rounded-lg p-3">
            <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-yellow-300">
              <strong>Conta Free:</strong> 10 minutos de ataque vitalícios.{' '}
              {status?.minutes_remaining === 0
                ? 'Seu tempo foi esgotado — assine um plano para continuar.'
                : `${status?.minutes_remaining} min restantes.`
              }
            </p>
          </div>
        )}
      </div>

      {/* Planos */}
      <div id="plans-section">
        <h2 className="text-lg font-bold text-gray-100 mb-4">Planos mensais — tudo incluso</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {PLANS_ORDER.map(planKey => {
            const plan = plans[planKey]
            if (!plan) return null
            const pm = PLAN_META[planKey]
            const Icon = pm.icon
            const isCurrent = currentPlan === planKey && status?.plan_active
            return (
              <div key={planKey} className={`card-dark p-5 border-2 ${isCurrent ? pm.border : 'border-dark-600'} relative`}>
                {isCurrent && (
                  <span className={`absolute top-3 right-3 text-xs px-2 py-0.5 rounded-full border ${pm.border} ${pm.color} font-semibold`}>
                    Atual
                  </span>
                )}
                <div className="flex items-center gap-2 mb-3">
                  <Icon className={`w-5 h-5 ${pm.color}`} />
                  <span className={`font-bold ${pm.color}`}>{plan.label}</span>
                </div>
                <p className="text-3xl font-black text-gray-100 mb-1">
                  R${plan.price_brl}
                  <span className="text-sm font-normal text-gray-500">/mês</span>
                </p>
                <ul className="text-sm text-gray-400 space-y-1.5 my-4">
                  <li className="flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                    {plan.minutes === null ? 'Tempo ilimitado' : `${plan.minutes / 60}h de ataque/mês`}
                  </li>
                  <li className="flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                    {plan.concurrent} ataque{plan.concurrent > 1 ? 's' : ''} simultâneo{plan.concurrent > 1 ? 's' : ''}
                  </li>
                  <li className="flex items-center gap-1.5">
                    <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                    Todas as ferramentas
                  </li>
                  <li className="flex items-center gap-1.5">
                    <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                    PIX · renova em 30 dias
                  </li>
                </ul>
                <button
                  onClick={() => handleSubscribe(planKey)}
                  disabled={!!subscribing}
                  className={`w-full py-2.5 rounded-lg text-sm font-semibold transition ${
                    isCurrent
                      ? 'bg-dark-700 text-gray-400 border border-dark-500 hover:border-dark-400'
                      : 'bg-blue-600 hover:bg-blue-500 text-white'
                  }`}
                >
                  {subscribing === planKey ? (
                    <span className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin" /> Gerando PIX...
                    </span>
                  ) : isCurrent ? 'Renovar plano' : 'Assinar via PIX'}
                </button>
              </div>
            )
          })}
        </div>
      </div>

      {/* Horas extras */}
      {currentPlan !== 'free' && (
        <div>
          <h2 className="text-lg font-bold text-gray-100 mb-4">Horas extras</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {Object.entries(extras).map(([key, pack]) => (
              <div key={key} className="card-dark p-5 border border-dark-600 flex items-center justify-between gap-4">
                <div>
                  <p className="font-bold text-gray-100">{pack.label}</p>
                  <p className="text-sm text-gray-500">{pack.minutes / 60}h adicionadas ao mês atual</p>
                </div>
                <div className="text-right flex-shrink-0">
                  <p className="text-xl font-black text-gray-100">R${pack.price_brl}</p>
                  <button
                    onClick={() => handleExtraHours(key)}
                    disabled={!!subscribing}
                    className="mt-2 text-sm px-4 py-1.5 bg-green-700 hover:bg-green-600 text-white rounded-lg font-semibold transition"
                  >
                    {subscribing === key ? <RefreshCw className="w-4 h-4 animate-spin inline" /> : 'Comprar'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Histórico */}
      {deposits.length > 0 && (
        <div>
          <h2 className="text-lg font-bold text-gray-100 mb-4">Histórico de pagamentos</h2>
          <div className="card-dark overflow-hidden">
            <table className="w-full text-sm">
              <thead className="border-b border-dark-700">
                <tr className="text-xs text-gray-500 uppercase">
                  <th className="text-left p-4">Tipo</th>
                  <th className="text-left p-4">Valor</th>
                  <th className="text-left p-4">Status</th>
                  <th className="text-left p-4">Data</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-700">
                {deposits.map(d => (
                  <tr key={d.id} className="hover:bg-dark-700/30">
                    <td className="p-4 text-gray-300">
                      {d.type === 'subscription'
                        ? `Plano ${PLAN_META[d.plan]?.label || d.plan}`
                        : `Horas extras ${d.pack}`}
                    </td>
                    <td className="p-4 font-semibold text-gray-100">R${d.amount_brl}</td>
                    <td className="p-4">
                      <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${
                        d.status === 'confirmed' ? 'bg-green-900/40 text-green-400' :
                        d.status === 'expired' ? 'bg-red-900/40 text-red-400' :
                        'bg-yellow-900/40 text-yellow-400'
                      }`}>
                        {d.status === 'confirmed' ? 'Confirmado' : d.status === 'expired' ? 'Expirado' : 'Pendente'}
                      </span>
                    </td>
                    <td className="p-4 text-gray-500 text-xs">
                      {new Date(d.created_at).toLocaleString('pt-BR')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeDeposit && (
        <QRCodeModal
          deposit={activeDeposit}
          onClose={() => setActiveDeposit(null)}
          onConfirmed={onPaymentConfirmed}
        />
      )}
    </div>
  )
}
