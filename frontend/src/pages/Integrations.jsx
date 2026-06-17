import React, { useState } from 'react'
import { Link2, Shield, ShieldCheck, Database, Download, CheckCircle, AlertTriangle, Play, X, Settings, MessageSquare, Tag, Users, Upload, Zap } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

function SentinelPanel() {
  const toast = useToast()
  const [form, setForm] = useState({ tenant_id: '', client_id: '', client_secret: '', workspace_id: '', subscription_id: '' })
  const [configured, setConfigured] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [simulations, setSimulations] = useState([])
  const [simId, setSimId] = useState('')
  const [pushing, setPushing] = useState(false)
  const [pushResult, setPushResult] = useState(null)

  const configure = async () => {
    if (!form.tenant_id || !form.client_id || !form.workspace_id) {
      toast('Preencha Tenant ID, Client ID e Workspace ID', 'warning'); return
    }
    try {
      await api.post('/api/integrations/sentinel/configure', form)
      setConfigured(true)
      toast('Sentinel configurado', 'success')
      api.get('/api/bas/simulations').then(r => setSimulations((r.data.simulations || []).filter(s => s.status === 'completed'))).catch(() => {})
    } catch (e) { toast(e.response?.data?.detail || 'Erro', 'error') }
  }

  const test = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const r = await api.post('/api/integrations/sentinel/test')
      setTestResult(r.data)
    } catch (e) { setTestResult({ status: 'error', message: e.response?.data?.detail || 'Erro de conexão' }) }
    finally { setTesting(false) }
  }

  const push = async () => {
    if (!simId) { toast('Selecione uma simulação', 'warning'); return }
    setPushing(true)
    setPushResult(null)
    try {
      const r = await api.post('/api/integrations/sentinel/push-alerts', { simulation_id: simId })
      setPushResult(r.data)
      toast(`${r.data.alerts_pushed ?? 0} alertas enviados`, 'success')
    } catch (e) { toast(e.response?.data?.detail || 'Erro', 'error') }
    finally { setPushing(false) }
  }

  return (
    <div className="card-dark p-6 space-y-6">
      <div className="flex items-center gap-3 pb-3 border-b border-dark-600">
        <div className="w-10 h-10 bg-blue-900/30 border border-blue-700/50 rounded-lg flex items-center justify-center">
          <Shield className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <h2 className="font-bold text-gray-100">Microsoft Sentinel</h2>
          <p className="text-xs text-gray-500">Push de alertas BAS para o Azure Sentinel SIEM</p>
        </div>
        {configured && <span className="ml-auto text-xs bg-green-900/40 text-green-400 border border-green-800 px-2 py-0.5 rounded">Configurado</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {[
          { key: 'tenant_id', label: 'Tenant ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
          { key: 'client_id', label: 'Client ID (App Registration)', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
          { key: 'client_secret', label: 'Client Secret', placeholder: '•••••••••••••••••••', type: 'password' },
          { key: 'workspace_id', label: 'Log Analytics Workspace ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
          { key: 'subscription_id', label: 'Subscription ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
        ].map(f => (
          <div key={f.key}>
            <label className="text-xs text-gray-400 mb-1 block">{f.label}</label>
            <input
              className="input-dark w-full font-mono text-sm"
              placeholder={f.placeholder}
              type={f.type || 'text'}
              value={form[f.key]}
              onChange={e => setForm(ff => ({ ...ff, [f.key]: e.target.value }))}
            />
          </div>
        ))}
      </div>

      <div className="flex flex-wrap gap-2">
        <button onClick={configure} className="px-4 py-2 bg-blue-700 hover:bg-blue-600 text-white rounded text-sm">
          <Settings className="w-4 h-4 inline mr-1" /> Salvar configuração
        </button>
        {configured && (
          <button onClick={test} disabled={testing} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-gray-300 rounded text-sm">
            {testing ? 'Testando...' : 'Testar conexão'}
          </button>
        )}
      </div>

      {testResult && (
        <div className={`p-3 rounded border text-sm ${testResult.status === 'connected' ? 'bg-green-900/20 border-green-800 text-green-300' : 'bg-red-900/20 border-red-800 text-red-300'}`}>
          {testResult.status === 'connected' ? <CheckCircle className="w-4 h-4 inline mr-1" /> : <AlertTriangle className="w-4 h-4 inline mr-1" />}
          {testResult.message}
        </div>
      )}

      {configured && (
        <div className="space-y-3 pt-3 border-t border-dark-600">
          <h3 className="text-sm font-bold text-gray-200">Enviar alertas BAS</h3>
          <div className="flex gap-3">
            <select className="select-dark flex-1" value={simId} onChange={e => setSimId(e.target.value)}>
              <option value="">Selecione uma simulação</option>
              {simulations.map(s => (
                <option key={s.id} value={s.id}>{s.playbook_name || s.id.slice(0, 8)} — {s.target}</option>
              ))}
            </select>
            <button onClick={push} disabled={pushing} className="flex items-center gap-2 px-4 py-2 bg-blue-700 hover:bg-blue-600 text-white rounded text-sm">
              <Play className="w-4 h-4" />
              {pushing ? 'Enviando...' : 'Enviar alertas'}
            </button>
          </div>
          {pushResult && (
            <div className="p-3 rounded bg-green-900/20 border border-green-800 text-sm text-green-300">
              <CheckCircle className="w-4 h-4 inline mr-1" /> {pushResult.message}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function WazuhPanel() {
  const toast = useToast()
  const [simulations, setSimulations] = useState([])
  const [form, setForm] = useState({ simulation_id: '', severity_filter: '' })
  const [loaded, setLoaded] = useState(false)

  const loadSims = () => {
    if (loaded) return
    api.get('/api/bas/simulations').then(r => {
      setSimulations((r.data.simulations || []).filter(s => s.status === 'completed'))
      setLoaded(true)
    }).catch(() => {})
  }

  const exportRules = async () => {
    try {
      const r = await api.post('/api/export/wazuh-rules', {
        simulation_id: form.simulation_id || null,
        severity_filter: form.severity_filter || null,
      }, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([r.data], { type: 'application/xml' }))
      const a = document.createElement('a')
      a.href = url; a.download = 'penteia_wazuh_rules.xml'; a.click()
      toast('Regras Wazuh exportadas', 'success')
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao exportar', 'error') }
  }

  return (
    <div className="card-dark p-6 space-y-6">
      <div className="flex items-center gap-3 pb-3 border-b border-dark-600">
        <div className="w-10 h-10 bg-orange-900/30 border border-orange-700/50 rounded-lg flex items-center justify-center">
          <Shield className="w-5 h-5 text-orange-400" />
        </div>
        <div>
          <h2 className="font-bold text-gray-100">Wazuh Rules Export</h2>
          <p className="text-xs text-gray-500">Gera regras XML do Wazuh baseadas nas técnicas encontradas pelo BAS</p>
        </div>
      </div>

      <div className="bg-dark-700 rounded p-4 text-xs text-gray-400 space-y-1 font-mono">
        <p className="text-green-400">&lt;!-- Exemplo de regra gerada --&gt;</p>
        <p>&lt;rule id="100500" level="14"&gt;</p>
        <p className="pl-4">&lt;field name="mitre.id"&gt;T1190&lt;/field&gt;</p>
        <p className="pl-4">&lt;description&gt;PenteIA BAS: SQLi detectado (CVSS 8.5)&lt;/description&gt;</p>
        <p className="pl-4">&lt;group&gt;mitre,attack,initial_access,&lt;/group&gt;</p>
        <p>&lt;/rule&gt;</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Simulação <span className="text-gray-600">(opcional — deixe vazio para todas)</span></label>
          <select className="select-dark w-full" value={form.simulation_id} onFocus={loadSims} onChange={e => setForm(f => ({ ...f, simulation_id: e.target.value }))}>
            <option value="">Todas as simulações</option>
            {simulations.map(s => (
              <option key={s.id} value={s.id}>{s.playbook_name || s.id.slice(0, 8)} — {s.target}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Filtrar por severidade <span className="text-gray-600">(opcional)</span></label>
          <select className="select-dark w-full" value={form.severity_filter} onChange={e => setForm(f => ({ ...f, severity_filter: e.target.value }))}>
            <option value="">Todas</option>
            <option value="Critical">Apenas Critical</option>
            <option value="High">Critical + High</option>
          </select>
        </div>
      </div>

      <button onClick={exportRules} className="flex items-center gap-2 px-4 py-2 bg-orange-700 hover:bg-orange-600 text-white rounded text-sm">
        <Download className="w-4 h-4" /> Exportar Regras XML para Wazuh
      </button>
    </div>
  )
}

function SlackPanel() {
  const toast = useToast()
  const [form, setForm] = useState({ webhook_url: '' })
  const [testResult, setTestResult] = useState(null)
  const [testing, setTesting] = useState(false)
  const [simulations, setSimulations] = useState([])
  const [simId, setSimId] = useState('')
  const [sending, setSending] = useState(false)

  const loadSims = () => {
    api.get('/api/bas/simulations').then(r => setSimulations((r.data.simulations || []).filter(s => s.status === 'completed'))).catch(() => {})
  }

  const testWebhook = async () => {
    if (!form.webhook_url) { toast('Informe o Webhook URL', 'warning'); return }
    setTesting(true)
    setTestResult(null)
    try {
      const r = await api.post('/api/integrations/slack/test', { webhook_url: form.webhook_url })
      setTestResult(r.data)
      if (r.data.status === 'ok' || r.data.status === 'success') {
        loadSims()
      }
    } catch (e) { setTestResult({ status: 'error', message: e.response?.data?.detail || 'Erro de conexão' }) }
    finally { setTesting(false) }
  }

  const sendAlert = async () => {
    if (!simId) { toast('Selecione uma simulação', 'warning'); return }
    setSending(true)
    try {
      await api.post('/api/integrations/slack/send', { webhook_url: form.webhook_url, simulation_id: simId })
      toast('Alerta enviado para o Slack', 'success')
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao enviar', 'error') }
    finally { setSending(false) }
  }

  const webhookOk = testResult && (testResult.status === 'ok' || testResult.status === 'success')

  return (
    <div className="card-dark p-6 space-y-6">
      <div className="flex items-center gap-3 pb-3 border-b border-dark-600">
        <div className="w-10 h-10 bg-green-900/30 border border-green-700/50 rounded-lg flex items-center justify-center">
          <MessageSquare className="w-5 h-5 text-green-400" />
        </div>
        <div>
          <h2 className="font-bold text-gray-100">Slack Webhooks</h2>
          <p className="text-xs text-gray-500">Envie alertas BAS diretamente para canais do Slack via Incoming Webhook</p>
        </div>
        {webhookOk && <span className="ml-auto text-xs bg-green-900/40 text-green-400 border border-green-800 px-2 py-0.5 rounded">Conectado</span>}
      </div>

      <div>
        <label className="text-xs text-gray-400 mb-1 block">Webhook URL</label>
        <input
          className="input-dark w-full font-mono text-sm"
          placeholder="https://hooks.slack.com/services/T.../B.../..."
          type="text"
          value={form.webhook_url}
          onChange={e => setForm(f => ({ ...f, webhook_url: e.target.value }))}
        />
      </div>

      <div className="flex flex-wrap gap-2">
        <button onClick={testWebhook} disabled={testing} className="px-4 py-2 bg-green-700 hover:bg-green-600 text-white rounded text-sm">
          {testing ? 'Testando...' : 'Testar'}
        </button>
      </div>

      {testResult && (
        <div className={`p-3 rounded border text-sm ${webhookOk ? 'bg-green-900/20 border-green-800 text-green-300' : 'bg-red-900/20 border-red-800 text-red-300'}`}>
          {webhookOk ? <CheckCircle className="w-4 h-4 inline mr-1" /> : <AlertTriangle className="w-4 h-4 inline mr-1" />}
          {testResult.message || (webhookOk ? 'Webhook válido' : 'Falha na conexão')}
        </div>
      )}

      {webhookOk && (
        <div className="space-y-3 pt-3 border-t border-dark-600">
          <h3 className="text-sm font-bold text-gray-200">Enviar alerta de simulação</h3>
          <div className="flex gap-3">
            <select className="select-dark flex-1" value={simId} onChange={e => setSimId(e.target.value)}>
              <option value="">Selecione uma simulação</option>
              {simulations.map(s => (
                <option key={s.id} value={s.id}>{s.playbook_name || s.id.slice(0, 8)} — {s.target}</option>
              ))}
            </select>
            <button onClick={sendAlert} disabled={sending} className="flex items-center gap-2 px-4 py-2 bg-green-700 hover:bg-green-600 text-white rounded text-sm">
              <Play className="w-4 h-4" />
              {sending ? 'Enviando...' : 'Enviar alerta'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function TeamsPanel() {
  const toast = useToast()
  const [form, setForm] = useState({ webhook_url: '' })
  const [testResult, setTestResult] = useState(null)
  const [testing, setTesting] = useState(false)
  const [simulations, setSimulations] = useState([])
  const [simId, setSimId] = useState('')
  const [sending, setSending] = useState(false)

  const loadSims = () => {
    api.get('/api/bas/simulations').then(r => setSimulations((r.data.simulations || []).filter(s => s.status === 'completed'))).catch(() => {})
  }

  const testWebhook = async () => {
    if (!form.webhook_url) { toast('Informe o Webhook URL', 'warning'); return }
    setTesting(true)
    setTestResult(null)
    try {
      const r = await api.post('/api/integrations/teams/test', { webhook_url: form.webhook_url })
      setTestResult(r.data)
      if (r.data.status === 'ok' || r.data.status === 'success') {
        loadSims()
      }
    } catch (e) { setTestResult({ status: 'error', message: e.response?.data?.detail || 'Erro de conexão' }) }
    finally { setTesting(false) }
  }

  const sendAlert = async () => {
    if (!simId) { toast('Selecione uma simulação', 'warning'); return }
    setSending(true)
    try {
      await api.post('/api/integrations/teams/send', { webhook_url: form.webhook_url, simulation_id: simId })
      toast('Alerta enviado para o Teams', 'success')
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao enviar', 'error') }
    finally { setSending(false) }
  }

  const webhookOk = testResult && (testResult.status === 'ok' || testResult.status === 'success')

  return (
    <div className="card-dark p-6 space-y-6">
      <div className="flex items-center gap-3 pb-3 border-b border-dark-600">
        <div className="w-10 h-10 bg-purple-900/30 border border-purple-700/50 rounded-lg flex items-center justify-center">
          <Users className="w-5 h-5 text-purple-400" />
        </div>
        <div>
          <h2 className="font-bold text-gray-100">Microsoft Teams</h2>
          <p className="text-xs text-gray-500">Envie alertas BAS para canais do Teams via Incoming Webhook</p>
        </div>
        {webhookOk && <span className="ml-auto text-xs bg-green-900/40 text-green-400 border border-green-800 px-2 py-0.5 rounded">Conectado</span>}
      </div>

      <div>
        <label className="text-xs text-gray-400 mb-1 block">Webhook URL</label>
        <input
          className="input-dark w-full font-mono text-sm"
          placeholder="https://outlook.office.com/webhook/..."
          type="text"
          value={form.webhook_url}
          onChange={e => setForm(f => ({ ...f, webhook_url: e.target.value }))}
        />
      </div>

      <div className="flex flex-wrap gap-2">
        <button onClick={testWebhook} disabled={testing} className="px-4 py-2 bg-purple-700 hover:bg-purple-600 text-white rounded text-sm">
          {testing ? 'Testando...' : 'Testar'}
        </button>
      </div>

      {testResult && (
        <div className={`p-3 rounded border text-sm ${webhookOk ? 'bg-green-900/20 border-green-800 text-green-300' : 'bg-red-900/20 border-red-800 text-red-300'}`}>
          {webhookOk ? <CheckCircle className="w-4 h-4 inline mr-1" /> : <AlertTriangle className="w-4 h-4 inline mr-1" />}
          {testResult.message || (webhookOk ? 'Webhook válido' : 'Falha na conexão')}
        </div>
      )}

      {webhookOk && (
        <div className="space-y-3 pt-3 border-t border-dark-600">
          <h3 className="text-sm font-bold text-gray-200">Enviar alerta de simulação</h3>
          <div className="flex gap-3">
            <select className="select-dark flex-1" value={simId} onChange={e => setSimId(e.target.value)}>
              <option value="">Selecione uma simulação</option>
              {simulations.map(s => (
                <option key={s.id} value={s.id}>{s.playbook_name || s.id.slice(0, 8)} — {s.target}</option>
              ))}
            </select>
            <button onClick={sendAlert} disabled={sending} className="flex items-center gap-2 px-4 py-2 bg-purple-700 hover:bg-purple-600 text-white rounded text-sm">
              <Play className="w-4 h-4" />
              {sending ? 'Enviando...' : 'Enviar alerta'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function JiraPanel() {
  const toast = useToast()
  const [form, setForm] = useState({ jira_url: '', email: '', api_token: '', project_key: '' })
  const [configured, setConfigured] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [simulations, setSimulations] = useState([])
  const [simId, setSimId] = useState('')
  const [techId, setTechId] = useState('')
  const [creating, setCreating] = useState(false)
  const [ticketResult, setTicketResult] = useState(null)

  const techniques = simId
    ? (simulations.find(s => s.id === simId)?.techniques || [])
    : []

  const configure = async () => {
    if (!form.jira_url || !form.email || !form.api_token || !form.project_key) {
      toast('Preencha todos os campos', 'warning'); return
    }
    try {
      const r = await api.post('/api/integrations/jira/configure', form)
      setTestResult(r.data)
      setConfigured(true)
      toast('Jira configurado com sucesso', 'success')
      api.get('/api/bas/simulations').then(res => setSimulations((res.data.simulations || []).filter(s => s.status === 'completed'))).catch(() => {})
    } catch (e) {
      setTestResult({ status: 'error', message: e.response?.data?.detail || 'Erro ao conectar' })
      toast(e.response?.data?.detail || 'Falha ao conectar ao Jira', 'error')
    }
  }

  const createTicket = async () => {
    if (!simId) { toast('Selecione uma simulação', 'warning'); return }
    if (!techId) { toast('Selecione uma técnica', 'warning'); return }
    setCreating(true)
    setTicketResult(null)
    try {
      const r = await api.post('/api/integrations/jira/create-ticket', { simulation_id: simId, technique_id: techId })
      setTicketResult(r.data)
      toast(`Ticket ${r.data.key ?? '(sem chave)'} criado no Jira`, 'success')
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao criar ticket', 'error') }
    finally { setCreating(false) }
  }

  const jiraBase = form.jira_url.replace(/\/$/, '')

  return (
    <div className="card-dark p-6 space-y-6">
      <div className="flex items-center gap-3 pb-3 border-b border-dark-600">
        <div className="w-10 h-10 bg-blue-900/30 border border-blue-700/50 rounded-lg flex items-center justify-center">
          <Tag className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <h2 className="font-bold text-gray-100">Jira</h2>
          <p className="text-xs text-gray-500">Crie tickets no Jira automaticamente a partir de técnicas detectadas pelo BAS</p>
        </div>
        {configured && <span className="ml-auto text-xs bg-green-900/40 text-green-400 border border-green-800 px-2 py-0.5 rounded">Configurado</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Jira URL</label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="https://suaempresa.atlassian.net"
            type="text"
            value={form.jira_url}
            onChange={e => setForm(f => ({ ...f, jira_url: e.target.value }))}
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">E-mail</label>
          <input
            className="input-dark w-full text-sm"
            placeholder="usuario@empresa.com"
            type="text"
            value={form.email}
            onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">API Token</label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="•••••••••••••••••••"
            type="password"
            value={form.api_token}
            onChange={e => setForm(f => ({ ...f, api_token: e.target.value }))}
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Project Key</label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="SEC"
            type="text"
            value={form.project_key}
            onChange={e => setForm(f => ({ ...f, project_key: e.target.value }))}
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <button onClick={configure} className="flex items-center gap-2 px-4 py-2 bg-blue-700 hover:bg-blue-600 text-white rounded text-sm">
          <Settings className="w-4 h-4" /> Conectar Jira
        </button>
      </div>

      {testResult && (
        <div className={`p-3 rounded border text-sm ${configured ? 'bg-green-900/20 border-green-800 text-green-300' : 'bg-red-900/20 border-red-800 text-red-300'}`}>
          {configured ? <CheckCircle className="w-4 h-4 inline mr-1" /> : <AlertTriangle className="w-4 h-4 inline mr-1" />}
          {testResult.message || (configured ? 'Conectado com sucesso' : 'Falha na conexão')}
        </div>
      )}

      {configured && (
        <div className="space-y-4 pt-3 border-t border-dark-600">
          <h3 className="text-sm font-bold text-gray-200">Criar Ticket</h3>

          <div>
            <label className="text-xs text-gray-400 mb-1 block">Simulação</label>
            <select className="select-dark w-full" value={simId} onChange={e => { setSimId(e.target.value); setTechId('') }}>
              <option value="">Selecione uma simulação</option>
              {simulations.map(s => (
                <option key={s.id} value={s.id}>{s.playbook_name || s.id.slice(0, 8)} — {s.target}</option>
              ))}
            </select>
          </div>

          {simId && (
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Técnica</label>
              <select className="select-dark w-full" value={techId} onChange={e => setTechId(e.target.value)}>
                <option value="">Selecione uma técnica</option>
                {techniques.length > 0
                  ? techniques.map(t => (
                      <option key={t.id || t.technique_id} value={t.id || t.technique_id}>
                        {t.technique_id || t.id} — {t.name || t.technique_name || 'Técnica'}
                      </option>
                    ))
                  : <option disabled>Nenhuma técnica disponível</option>
                }
              </select>
            </div>
          )}

          <button onClick={createTicket} disabled={creating} className="flex items-center gap-2 px-4 py-2 bg-blue-700 hover:bg-blue-600 text-white rounded text-sm">
            <Tag className="w-4 h-4" />
            {creating ? 'Criando...' : 'Criar Ticket no Jira'}
          </button>

          {ticketResult && (
            <div className="p-3 rounded bg-green-900/20 border border-green-800 text-sm text-green-300 flex items-center gap-2">
              <CheckCircle className="w-4 h-4 flex-shrink-0" />
              <span>
                Ticket criado:{' '}
                {ticketResult.key && (
                  <a
                    href={`${jiraBase}/browse/${ticketResult.key}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="underline font-mono font-bold hover:text-green-200"
                  >
                    {ticketResult.key}
                  </a>
                )}
                {ticketResult.message && !ticketResult.key && ticketResult.message}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function CrowdStrikePanel() {
  const toast = useToast()
  const [form, setForm] = useState({ client_id: '', client_secret: '' })
  const [configured, setConfigured] = useState(false)
  const [simId, setSimId] = useState('')
  const [hoursBack, setHoursBack] = useState(24)
  const [correlating, setCorrelating] = useState(false)
  const [result, setResult] = useState(null)
  const [simulations, setSimulations] = useState([])

  const configure = async () => {
    if (!form.client_id || !form.client_secret) {
      toast('Preencha Client ID e Client Secret', 'warning'); return
    }
    try {
      await api.post('/api/integrations/crowdstrike/configure', form)
      setConfigured(true)
      toast('CrowdStrike configurado', 'success')
      api.get('/api/bas/simulations').then(r => setSimulations((r.data.simulations || []).filter(s => s.status === 'completed'))).catch(() => {})
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao configurar', 'error') }
  }

  const correlate = async () => {
    if (!simId) { toast('Selecione uma simulação', 'warning'); return }
    setCorrelating(true)
    setResult(null)
    try {
      const r = await api.post('/api/integrations/crowdstrike/detection-rate', { simulation_id: simId, hours_back: Number(hoursBack) })
      setResult(r.data)
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao calcular', 'error') }
    finally { setCorrelating(false) }
  }

  const rateColor = result
    ? result.detection_rate_pct >= 70
      ? 'text-green-400'
      : result.detection_rate_pct >= 40
        ? 'text-yellow-400'
        : 'text-red-400'
    : ''

  return (
    <div className="card-dark p-6 space-y-6">
      <div className="flex items-center gap-3 pb-3 border-b border-dark-600">
        <div className="w-10 h-10 bg-red-900/30 border border-red-700/50 rounded-lg flex items-center justify-center">
          <ShieldCheck className="w-5 h-5 text-red-400" />
        </div>
        <div>
          <h2 className="font-bold text-gray-100">CrowdStrike Falcon</h2>
          <p className="text-xs text-gray-500">Correlação de detecção entre BAS e EDR Falcon</p>
        </div>
        {configured && <span className="ml-auto text-xs bg-green-900/40 text-green-400 border border-green-800 px-2 py-0.5 rounded">Configurado</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Client ID</label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            type="text"
            value={form.client_id}
            onChange={e => setForm(f => ({ ...f, client_id: e.target.value }))}
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Client Secret</label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="•••••••••••••••••••"
            type="password"
            value={form.client_secret}
            onChange={e => setForm(f => ({ ...f, client_secret: e.target.value }))}
          />
        </div>
      </div>

      <button onClick={configure} className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded text-sm">
        <Settings className="w-4 h-4" /> Salvar configuração
      </button>

      {configured && (
        <div className="space-y-4 pt-3 border-t border-dark-600">
          <h3 className="text-sm font-bold text-gray-200">Calcular Detection Rate</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="md:col-span-2">
              <label className="text-xs text-gray-400 mb-1 block">Simulação</label>
              <select className="select-dark w-full" value={simId} onChange={e => setSimId(e.target.value)}>
                <option value="">Selecione uma simulação</option>
                {simulations.map(s => (
                  <option key={s.id} value={s.id}>{s.playbook_name || s.id.slice(0, 8)} — {s.target}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Janela (horas)</label>
              <input
                className="input-dark w-full text-sm"
                type="number"
                min={1}
                max={720}
                value={hoursBack}
                onChange={e => setHoursBack(Number(e.target.value) || 1)}
              />
            </div>
          </div>
          <button onClick={correlate} disabled={correlating} className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded text-sm">
            <Play className="w-4 h-4" />
            {correlating ? 'Calculando...' : 'Calcular Detection Rate'}
          </button>

          {result && (
            <div className="space-y-4">
              <div className="flex items-center gap-4 p-4 bg-dark-700 rounded-lg">
                <span className={`text-5xl font-black ${rateColor}`}>
                  {result.detection_rate_pct != null ? `${result.detection_rate_pct.toFixed(1)}%` : '--'}
                </span>
                <div>
                  <p className="text-sm text-gray-300 font-semibold">Detection Rate</p>
                  <p className="text-xs text-gray-500">
                    {result.detected_count ?? 0} de {result.total_count ?? 0} técnicas detectadas pelo Falcon
                  </p>
                </div>
              </div>

              {result.detected && result.detected.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold text-green-400 uppercase tracking-wide mb-2">Detectadas pelo Falcon</h4>
                  <div className="space-y-1">
                    {result.detected.map((t, i) => (
                      <div key={i} className="flex items-center gap-2 text-sm text-gray-300 bg-green-900/10 border border-green-900/30 rounded px-3 py-1.5">
                        <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                        <span className="font-mono text-green-300 text-xs">{t.technique_id}</span>
                        <span className="text-gray-400">—</span>
                        <span>{t.technique_name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {result.not_detected && result.not_detected.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold text-red-400 uppercase tracking-wide mb-2">NAO detectadas</h4>
                  <div className="space-y-1">
                    {result.not_detected.map((t, i) => (
                      <div key={i} className="flex items-center gap-2 text-sm text-gray-300 bg-red-900/10 border border-red-900/30 rounded px-3 py-1.5">
                        <X className="w-4 h-4 text-red-400 flex-shrink-0" />
                        <span className="font-mono text-red-300 text-xs">{t.technique_id}</span>
                        <span className="text-gray-400">—</span>
                        <span>{t.technique_name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function TenablePanel() {
  const toast = useToast()
  const [form, setForm] = useState({ access_key: '', secret_key: '' })
  const [configured, setConfigured] = useState(false)
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState('')
  const [importing, setImporting] = useState(false)
  const [results, setResults] = useState(null)
  const [activeSubTab, setActiveSubTab] = useState('cloud')
  const [nessusFile, setNessusFile] = useState(null)
  const [sortBy, setSortBy] = useState('cvss')

  const configure = async () => {
    if (!form.access_key || !form.secret_key) {
      toast('Preencha Access Key e Secret Key', 'warning'); return
    }
    try {
      await api.post('/api/integrations/tenable/configure', form)
      setConfigured(true)
      toast('Tenable configurado', 'success')
      fetchScans()
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao configurar', 'error') }
  }

  const fetchScans = async () => {
    try {
      const r = await api.get('/api/integrations/tenable/scans')
      setScans(r.data.scans || [])
    } catch (e) { toast('Erro ao buscar scans', 'error') }
  }

  const importScan = async () => {
    if (!selectedScan) { toast('Selecione um scan', 'warning'); return }
    setImporting(true)
    setResults(null)
    try {
      const r = await api.post('/api/integrations/tenable/import', { scan_id: selectedScan })
      setResults(r.data)
      toast(`${r.data.vulnerabilities?.length || 0} vulnerabilidades importadas`, 'success')
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao importar', 'error') }
    finally { setImporting(false) }
  }

  const uploadNessus = async () => {
    if (!nessusFile) { toast('Selecione um arquivo .nessus', 'warning'); return }
    setImporting(true)
    setResults(null)
    try {
      const fd = new FormData()
      fd.append('file', nessusFile)
      const r = await api.post('/api/integrations/tenable/parse-nessus', fd)
      setResults(r.data)
      toast(`${r.data.vulnerabilities?.length || 0} vulnerabilidades parseadas`, 'success')
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao processar arquivo', 'error') }
    finally { setImporting(false) }
  }

  const severityColor = sev => {
    const s = (sev || '').toLowerCase()
    if (s === 'critical') return 'text-red-400'
    if (s === 'high') return 'text-orange-400'
    if (s === 'medium') return 'text-yellow-400'
    return 'text-gray-400'
  }

  const sortedVulns = results?.vulnerabilities
    ? [...results.vulnerabilities].sort((a, b) => {
        if (sortBy === 'cvss') return (b.cvss || 0) - (a.cvss || 0)
        if (sortBy === 'severity') { const ord = { critical: 4, high: 3, medium: 2, low: 1 }; return (ord[(b.severity || '').toLowerCase()] || 0) - (ord[(a.severity || '').toLowerCase()] || 0) }
        return 0
      })
    : []

  return (
    <div className="card-dark p-6 space-y-6">
      <div className="flex items-center gap-3 pb-3 border-b border-dark-600">
        <div className="w-10 h-10 bg-cyan-900/30 border border-cyan-700/50 rounded-lg flex items-center justify-center">
          <Database className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <h2 className="font-bold text-gray-100">Tenable.io / Nessus</h2>
          <p className="text-xs text-gray-500">Importar resultado de scan e priorizar com EPSS</p>
        </div>
        {configured && <span className="ml-auto text-xs bg-green-900/40 text-green-400 border border-green-800 px-2 py-0.5 rounded">Configurado</span>}
      </div>

      <div className="flex gap-1 border-b border-dark-600">
        {[{ id: 'cloud', label: 'Tenable Cloud' }, { id: 'nessus', label: 'Upload Nessus XML' }].map(t => (
          <button
            key={t.id}
            onClick={() => { setActiveSubTab(t.id); setResults(null) }}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeSubTab === t.id ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-gray-400 hover:text-gray-200'}`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {activeSubTab === 'cloud' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Access Key</label>
              <input
                className="input-dark w-full font-mono text-sm"
                placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                type="text"
                value={form.access_key}
                onChange={e => setForm(f => ({ ...f, access_key: e.target.value }))}
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Secret Key</label>
              <input
                className="input-dark w-full font-mono text-sm"
                placeholder="•••••••••••••••••••"
                type="password"
                value={form.secret_key}
                onChange={e => setForm(f => ({ ...f, secret_key: e.target.value }))}
              />
            </div>
          </div>
          <button onClick={configure} className="flex items-center gap-2 px-4 py-2 bg-cyan-700 hover:bg-cyan-600 text-white rounded text-sm">
            <Settings className="w-4 h-4" /> Configurar e buscar scans
          </button>

          {configured && (
            <div className="space-y-3 pt-3 border-t border-dark-600">
              <div className="flex gap-3">
                <select className="select-dark flex-1" value={selectedScan} onChange={e => setSelectedScan(e.target.value)}>
                  <option value="">Selecione um scan</option>
                  {scans.map(s => (
                    <option key={s.id} value={s.id}>{s.name || s.id}</option>
                  ))}
                </select>
                <button onClick={importScan} disabled={importing} className="flex items-center gap-2 px-4 py-2 bg-cyan-700 hover:bg-cyan-600 text-white rounded text-sm">
                  <Download className="w-4 h-4" />
                  {importing ? 'Importando...' : 'Importar'}
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {activeSubTab === 'nessus' && (
        <div className="space-y-4">
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Arquivo Nessus (.nessus / .xml)</label>
            <input
              type="file"
              accept=".nessus,.xml"
              className="block w-full text-sm text-gray-400 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:bg-dark-700 file:text-gray-300 hover:file:bg-dark-600"
              onChange={e => setNessusFile(e.target.files?.[0] || null)}
            />
          </div>
          <button onClick={uploadNessus} disabled={importing} className="flex items-center gap-2 px-4 py-2 bg-cyan-700 hover:bg-cyan-600 text-white rounded text-sm">
            <Upload className="w-4 h-4" />
            {importing ? 'Processando...' : 'Fazer Upload e Parsear'}
          </button>
        </div>
      )}

      {sortedVulns.length > 0 && (
        <div className="space-y-3 pt-3 border-t border-dark-600">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-gray-200">{sortedVulns.length} Vulnerabilidades</h3>
            <select className="select-dark text-xs py-1" value={sortBy} onChange={e => setSortBy(e.target.value)}>
              <option value="cvss">Ordenar por CVSS</option>
              <option value="severity">Ordenar por Severidade</option>
            </select>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-gray-500 border-b border-dark-600">
                  <th className="pb-2 pr-3">CVE</th>
                  <th className="pb-2 pr-3">Nome</th>
                  <th className="pb-2 pr-3">CVSS</th>
                  <th className="pb-2 pr-3">Severidade</th>
                  <th className="pb-2">Host</th>
                </tr>
              </thead>
              <tbody>
                {sortedVulns.map((v, i) => (
                  <tr key={i} className="border-b border-dark-700 hover:bg-dark-700/40">
                    <td className="py-1.5 pr-3 font-mono text-cyan-400">{v.cve_id || '—'}</td>
                    <td className="py-1.5 pr-3 text-gray-300 max-w-xs truncate">{v.name}</td>
                    <td className="py-1.5 pr-3 font-mono font-bold text-gray-200">{v.cvss ?? '—'}</td>
                    <td className={`py-1.5 pr-3 font-semibold ${severityColor(v.severity)}`}>{v.severity || '—'}</td>
                    <td className="py-1.5 font-mono text-gray-400">{v.host || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

function QualysPanel() {
  const toast = useToast()
  const [form, setForm] = useState({ username: '', password: '', platform_url: '' })
  const [configured, setConfigured] = useState(false)
  const [importing, setImporting] = useState(false)
  const [results, setResults] = useState(null)

  const configure = async () => {
    if (!form.username || !form.password || !form.platform_url) {
      toast('Preencha todos os campos', 'warning'); return
    }
    try {
      await api.post('/api/integrations/qualys/configure', form)
      setConfigured(true)
      toast('Qualys configurado', 'success')
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao configurar', 'error') }
  }

  const importVulns = async () => {
    setImporting(true)
    setResults(null)
    try {
      const r = await api.post('/api/integrations/qualys/import', { days_back: 30 })
      setResults(r.data)
      toast(`${r.data.vulnerabilities?.length || 0} vulnerabilidades importadas`, 'success')
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao importar', 'error') }
    finally { setImporting(false) }
  }

  const severityColor = sev => {
    const s = (sev || '').toLowerCase()
    if (s === 'critical') return 'text-red-400'
    if (s === 'high') return 'text-orange-400'
    if (s === 'medium') return 'text-yellow-400'
    return 'text-gray-400'
  }

  const vulns = results?.vulnerabilities || []

  return (
    <div className="card-dark p-6 space-y-6">
      <div className="flex items-center gap-3 pb-3 border-b border-dark-600">
        <div className="w-10 h-10 bg-indigo-900/30 border border-indigo-700/50 rounded-lg flex items-center justify-center">
          <Shield className="w-5 h-5 text-indigo-400" />
        </div>
        <div>
          <h2 className="font-bold text-gray-100">Qualys VMDR</h2>
          <p className="text-xs text-gray-500">Importar vulnerabilidades do Qualys para correlação com BAS</p>
        </div>
        {configured && <span className="ml-auto text-xs bg-green-900/40 text-green-400 border border-green-800 px-2 py-0.5 rounded">Configurado</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Username</label>
          <input
            className="input-dark w-full text-sm"
            placeholder="usuario@empresa.com"
            type="text"
            value={form.username}
            onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Password</label>
          <input
            className="input-dark w-full text-sm"
            placeholder="•••••••••••••••••••"
            type="password"
            value={form.password}
            onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
          />
        </div>
        <div className="md:col-span-2">
          <label className="text-xs text-gray-400 mb-1 block">Platform URL</label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="https://qualysapi.qg2.apps.qualys.com"
            type="text"
            value={form.platform_url}
            onChange={e => setForm(f => ({ ...f, platform_url: e.target.value }))}
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <button onClick={configure} className="flex items-center gap-2 px-4 py-2 bg-indigo-700 hover:bg-indigo-600 text-white rounded text-sm">
          <Settings className="w-4 h-4" /> Salvar configuração
        </button>
        {configured && (
          <button onClick={importVulns} disabled={importing} className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-sm">
            <Download className="w-4 h-4" />
            {importing ? 'Importando...' : 'Importar Vulnerabilidades'}
          </button>
        )}
      </div>

      {vulns.length > 0 && (
        <div className="space-y-3 pt-3 border-t border-dark-600">
          <h3 className="text-sm font-bold text-gray-200">{vulns.length} Vulnerabilidades importadas (últimos 30 dias)</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-gray-500 border-b border-dark-600">
                  <th className="pb-2 pr-3">QID / CVE</th>
                  <th className="pb-2 pr-3">Nome</th>
                  <th className="pb-2 pr-3">CVSS</th>
                  <th className="pb-2 pr-3">Severidade</th>
                  <th className="pb-2">Host</th>
                </tr>
              </thead>
              <tbody>
                {vulns.map((v, i) => (
                  <tr key={i} className="border-b border-dark-700 hover:bg-dark-700/40">
                    <td className="py-1.5 pr-3 font-mono text-indigo-400">{v.cve_id || v.qid || '—'}</td>
                    <td className="py-1.5 pr-3 text-gray-300 max-w-xs truncate">{v.name}</td>
                    <td className="py-1.5 pr-3 font-mono font-bold text-gray-200">{v.cvss ?? '—'}</td>
                    <td className={`py-1.5 pr-3 font-semibold ${severityColor(v.severity)}`}>{v.severity || '—'}</td>
                    <td className="py-1.5 font-mono text-gray-400">{v.host || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

function SentinelOnePanel() {
  const toast = useToast()
  const [form, setForm] = useState({ base_url: '', api_token: '', site_id: '' })
  const [configured, setConfigured] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [threats, setThreats] = useState([])
  const [loadingThreats, setLoadingThreats] = useState(false)
  const [simulations, setSimulations] = useState([])
  const [simId, setSimId] = useState('')
  const [correlating, setCorrelating] = useState(false)
  const [correlationResult, setCorrelationResult] = useState(null)

  const configure = async () => {
    if (!form.base_url || !form.api_token) {
      toast('Preencha Base URL e API Token', 'warning'); return
    }
    try {
      await api.post('/api/integrations/sentinelone/configure', form)
      setConfigured(true)
      toast('SentinelOne configurado', 'success')
      api.get('/api/bas/simulations').then(r => setSimulations((r.data.simulations || []).filter(s => s.status === 'completed'))).catch(() => {})
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao configurar', 'error') }
  }

  const test = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const r = await api.post('/api/integrations/sentinelone/test')
      setTestResult(r.data)
    } catch (e) { setTestResult({ status: 'error', message: e.response?.data?.detail || 'Erro de conexão' }) }
    finally { setTesting(false) }
  }

  const fetchThreats = async () => {
    setLoadingThreats(true)
    setThreats([])
    try {
      const r = await api.get('/api/integrations/sentinelone/threats', { params: { hours_back: 24 } })
      setThreats(r.data.threats || [])
      toast(`${r.data.threats?.length || 0} ameaças nas últimas 24h`, 'success')
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao buscar ameaças', 'error') }
    finally { setLoadingThreats(false) }
  }

  const correlate = async () => {
    if (!simId) { toast('Selecione uma simulação', 'warning'); return }
    setCorrelating(true)
    setCorrelationResult(null)
    try {
      const r = await api.post('/api/integrations/sentinelone/detection-rate', { simulation_id: simId, hours_back: 24 })
      setCorrelationResult(r.data)
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao calcular', 'error') }
    finally { setCorrelating(false) }
  }

  const rateColor = result =>
    result?.detection_rate_pct >= 70 ? 'text-green-400'
    : result?.detection_rate_pct >= 40 ? 'text-yellow-400'
    : 'text-red-400'

  const threatSeverityColor = sev => {
    const s = (sev || '').toLowerCase()
    if (s === 'critical') return 'text-red-400'
    if (s === 'high') return 'text-orange-400'
    if (s === 'medium') return 'text-yellow-400'
    return 'text-gray-400'
  }

  return (
    <div className="card-dark p-6 space-y-6">
      <div className="flex items-center gap-3 pb-3 border-b border-dark-600">
        <div className="w-10 h-10 bg-violet-900/30 border border-violet-700/50 rounded-lg flex items-center justify-center">
          <Shield className="w-5 h-5 text-violet-400" />
        </div>
        <div>
          <h2 className="font-bold text-gray-100">SentinelOne</h2>
          <p className="text-xs text-gray-500">Correlação de ameaças e detection rate com o EDR SentinelOne</p>
        </div>
        {configured && <span className="ml-auto text-xs bg-green-900/40 text-green-400 border border-green-800 px-2 py-0.5 rounded">Configurado</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="md:col-span-2">
          <label className="text-xs text-gray-400 mb-1 block">Base URL</label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="https://usea1.sentinelone.net"
            type="text"
            value={form.base_url}
            onChange={e => setForm(f => ({ ...f, base_url: e.target.value }))}
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">API Token</label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="•••••••••••••••••••"
            type="password"
            value={form.api_token}
            onChange={e => setForm(f => ({ ...f, api_token: e.target.value }))}
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Site ID <span className="text-gray-600">(opcional)</span></label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="123456789012345678"
            type="text"
            value={form.site_id}
            onChange={e => setForm(f => ({ ...f, site_id: e.target.value }))}
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <button onClick={configure} className="flex items-center gap-2 px-4 py-2 bg-violet-700 hover:bg-violet-600 text-white rounded text-sm">
          <Settings className="w-4 h-4" /> Salvar configuração
        </button>
        {configured && (
          <button onClick={test} disabled={testing} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-gray-300 rounded text-sm">
            {testing ? 'Testando...' : 'Testar conexão'}
          </button>
        )}
        {configured && (
          <button onClick={fetchThreats} disabled={loadingThreats} className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-gray-300 rounded text-sm">
            <Download className="w-4 h-4" />
            {loadingThreats ? 'Buscando...' : 'Ameaças últimas 24h'}
          </button>
        )}
      </div>

      {testResult && (
        <div className={`p-3 rounded border text-sm ${testResult.status === 'connected' ? 'bg-green-900/20 border-green-800 text-green-300' : 'bg-red-900/20 border-red-800 text-red-300'}`}>
          {testResult.status === 'connected' ? <CheckCircle className="w-4 h-4 inline mr-1" /> : <AlertTriangle className="w-4 h-4 inline mr-1" />}
          {testResult.message}
        </div>
      )}

      {threats.length > 0 && (
        <div className="space-y-2 pt-3 border-t border-dark-600">
          <h3 className="text-sm font-bold text-gray-200">Ameaças detectadas nas últimas 24h ({threats.length})</h3>
          <div className="overflow-x-auto max-h-64 overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-dark-800">
                <tr className="text-left text-gray-500 border-b border-dark-600">
                  <th className="pb-2 pr-3">Nome</th>
                  <th className="pb-2 pr-3">Severidade</th>
                  <th className="pb-2 pr-3">Classificação</th>
                  <th className="pb-2">Host</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((t, i) => (
                  <tr key={i} className="border-b border-dark-700 hover:bg-dark-700/40">
                    <td className="py-1.5 pr-3 text-gray-300 max-w-xs truncate">{t.threat_name || t.name || '—'}</td>
                    <td className={`py-1.5 pr-3 font-semibold ${threatSeverityColor(t.confidence_level || t.severity)}`}>{t.confidence_level || t.severity || '—'}</td>
                    <td className="py-1.5 pr-3 text-gray-400">{t.classification || '—'}</td>
                    <td className="py-1.5 font-mono text-gray-400">{t.agent_computer_name || t.host || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {configured && (
        <div className="space-y-4 pt-3 border-t border-dark-600">
          <h3 className="text-sm font-bold text-gray-200">Correlacionar com Simulação</h3>
          <div className="flex gap-3">
            <select className="select-dark flex-1" value={simId} onChange={e => setSimId(e.target.value)}>
              <option value="">Selecione uma simulação</option>
              {simulations.map(s => (
                <option key={s.id} value={s.id}>{s.playbook_name || s.id.slice(0, 8)} — {s.target}</option>
              ))}
            </select>
            <button onClick={correlate} disabled={correlating} className="flex items-center gap-2 px-4 py-2 bg-violet-700 hover:bg-violet-600 text-white rounded text-sm">
              <Play className="w-4 h-4" />
              {correlating ? 'Calculando...' : 'Detection Rate'}
            </button>
          </div>

          {correlationResult && (
            <div className="flex items-center gap-4 p-4 bg-dark-700 rounded-lg">
              <span className={`text-5xl font-black ${rateColor(correlationResult)}`}>
                {correlationResult.detection_rate_pct != null ? `${correlationResult.detection_rate_pct.toFixed(1)}%` : '--'}
              </span>
              <div>
                <p className="text-sm text-gray-300 font-semibold">SentinelOne Detection Rate</p>
                <p className="text-xs text-gray-500">
                  {correlationResult.detected_count ?? 0} de {correlationResult.total_count ?? 0} técnicas detectadas
                </p>
                {correlationResult.not_detected && correlationResult.not_detected.length > 0 && (
                  <p className="text-xs text-red-400 mt-1">{correlationResult.not_detected.length} técnicas sem detecção</p>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function DefenderPanel() {
  const toast = useToast()
  const [form, setForm] = useState({ tenant_id: '', client_id: '', client_secret: '' })
  const [configured, setConfigured] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [loadingAlerts, setLoadingAlerts] = useState(false)
  const [simulations, setSimulations] = useState([])
  const [simId, setSimId] = useState('')
  const [correlating, setCorrelating] = useState(false)
  const [correlationResult, setCorrelationResult] = useState(null)
  const [s1Rate, setS1Rate] = useState(null)

  const configure = async () => {
    if (!form.tenant_id || !form.client_id || !form.client_secret) {
      toast('Preencha Tenant ID, Client ID e Client Secret', 'warning'); return
    }
    try {
      await api.post('/api/integrations/defender/configure', form)
      setConfigured(true)
      toast('Defender XDR configurado', 'success')
      api.get('/api/bas/simulations').then(r => setSimulations((r.data.simulations || []).filter(s => s.status === 'completed'))).catch(() => {})
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao configurar', 'error') }
  }

  const test = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const r = await api.post('/api/integrations/defender/test')
      setTestResult(r.data)
    } catch (e) { setTestResult({ status: 'error', message: e.response?.data?.detail || 'Erro de conexão' }) }
    finally { setTesting(false) }
  }

  const fetchAlerts = async () => {
    setLoadingAlerts(true)
    setAlerts([])
    try {
      const r = await api.get('/api/integrations/defender/alerts', { params: { hours_back: 24 } })
      setAlerts(r.data.alerts || [])
      toast(`${r.data.alerts?.length || 0} alertas nas últimas 24h`, 'success')
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao buscar alertas', 'error') }
    finally { setLoadingAlerts(false) }
  }

  const correlate = async () => {
    if (!simId) { toast('Selecione uma simulação', 'warning'); return }
    setCorrelating(true)
    setCorrelationResult(null)
    try {
      const [defRes, s1Res] = await Promise.allSettled([
        api.post('/api/integrations/defender/detection-rate', { simulation_id: simId, hours_back: 24 }),
        api.post('/api/integrations/sentinelone/detection-rate', { simulation_id: simId, hours_back: 24 }),
      ])
      if (defRes.status === 'fulfilled') setCorrelationResult(defRes.value.data)
      else toast(defRes.reason?.response?.data?.detail || 'Erro ao calcular Defender', 'error')
      if (s1Res.status === 'fulfilled') setS1Rate(s1Res.value.data)
      else setS1Rate(null)
    } finally { setCorrelating(false) }
  }

  const rateColor = pct =>
    pct >= 70 ? 'text-green-400' : pct >= 40 ? 'text-yellow-400' : 'text-red-400'

  const severityColor = sev => {
    const s = (sev || '').toLowerCase()
    if (s === 'high') return 'text-red-400'
    if (s === 'medium') return 'text-orange-400'
    if (s === 'low') return 'text-yellow-400'
    return 'text-gray-400'
  }

  return (
    <div className="card-dark p-6 space-y-6">
      <div className="flex items-center gap-3 pb-3 border-b border-dark-600">
        <div className="w-10 h-10 bg-blue-900/30 border border-blue-700/50 rounded-lg flex items-center justify-center">
          <ShieldCheck className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <h2 className="font-bold text-gray-100">Microsoft Defender XDR</h2>
          <p className="text-xs text-gray-500">Alertas e detection rate do Defender vs SentinelOne</p>
        </div>
        {configured && <span className="ml-auto text-xs bg-green-900/40 text-green-400 border border-green-800 px-2 py-0.5 rounded">Configurado</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Tenant ID</label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            type="text"
            value={form.tenant_id}
            onChange={e => setForm(f => ({ ...f, tenant_id: e.target.value }))}
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Client ID</label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            type="text"
            value={form.client_id}
            onChange={e => setForm(f => ({ ...f, client_id: e.target.value }))}
          />
        </div>
        <div className="md:col-span-2">
          <label className="text-xs text-gray-400 mb-1 block">Client Secret</label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="•••••••••••••••••••"
            type="password"
            value={form.client_secret}
            onChange={e => setForm(f => ({ ...f, client_secret: e.target.value }))}
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <button onClick={configure} className="flex items-center gap-2 px-4 py-2 bg-blue-700 hover:bg-blue-600 text-white rounded text-sm">
          <Settings className="w-4 h-4" /> Salvar configuração
        </button>
        {configured && (
          <button onClick={test} disabled={testing} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-gray-300 rounded text-sm">
            {testing ? 'Testando...' : 'Testar conexão'}
          </button>
        )}
        {configured && (
          <button onClick={fetchAlerts} disabled={loadingAlerts} className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-gray-300 rounded text-sm">
            <Download className="w-4 h-4" />
            {loadingAlerts ? 'Buscando...' : 'Alertas últimas 24h'}
          </button>
        )}
      </div>

      {testResult && (
        <div className={`p-3 rounded border text-sm ${testResult.status === 'connected' ? 'bg-green-900/20 border-green-800 text-green-300' : 'bg-red-900/20 border-red-800 text-red-300'}`}>
          {testResult.status === 'connected' ? <CheckCircle className="w-4 h-4 inline mr-1" /> : <AlertTriangle className="w-4 h-4 inline mr-1" />}
          {testResult.message}
        </div>
      )}

      {alerts.length > 0 && (
        <div className="space-y-2 pt-3 border-t border-dark-600">
          <h3 className="text-sm font-bold text-gray-200">Alertas Defender XDR nas últimas 24h ({alerts.length})</h3>
          <div className="overflow-x-auto max-h-64 overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-dark-800">
                <tr className="text-left text-gray-500 border-b border-dark-600">
                  <th className="pb-2 pr-3">Título</th>
                  <th className="pb-2 pr-3">Severidade</th>
                  <th className="pb-2 pr-3">Categoria</th>
                  <th className="pb-2">Entidade</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a, i) => (
                  <tr key={i} className="border-b border-dark-700 hover:bg-dark-700/40">
                    <td className="py-1.5 pr-3 text-gray-300 max-w-xs truncate">{a.title || a.alert_display_name || '—'}</td>
                    <td className={`py-1.5 pr-3 font-semibold ${severityColor(a.severity)}`}>{a.severity || '—'}</td>
                    <td className="py-1.5 pr-3 text-gray-400">{a.category || '—'}</td>
                    <td className="py-1.5 font-mono text-gray-400">{a.entity || a.device_name || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {configured && (
        <div className="space-y-4 pt-3 border-t border-dark-600">
          <h3 className="text-sm font-bold text-gray-200">Correlacionar com Simulação</h3>
          <div className="flex gap-3">
            <select className="select-dark flex-1" value={simId} onChange={e => setSimId(e.target.value)}>
              <option value="">Selecione uma simulação</option>
              {simulations.map(s => (
                <option key={s.id} value={s.id}>{s.playbook_name || s.id.slice(0, 8)} — {s.target}</option>
              ))}
            </select>
            <button onClick={correlate} disabled={correlating} className="flex items-center gap-2 px-4 py-2 bg-blue-700 hover:bg-blue-600 text-white rounded text-sm">
              <Play className="w-4 h-4" />
              {correlating ? 'Calculando...' : 'Comparar Detection Rate'}
            </button>
          </div>

          {(correlationResult || s1Rate) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {correlationResult && (
                <div className="flex items-center gap-4 p-4 bg-dark-700 rounded-lg border border-blue-900/40">
                  <span className={`text-4xl font-black ${rateColor(correlationResult.detection_rate_pct)}`}>
                    {correlationResult.detection_rate_pct != null ? `${correlationResult.detection_rate_pct.toFixed(1)}%` : '--'}
                  </span>
                  <div>
                    <p className="text-sm text-blue-300 font-semibold">Defender XDR</p>
                    <p className="text-xs text-gray-500">{correlationResult.detected_count ?? 0} / {correlationResult.total_count ?? 0} técnicas</p>
                  </div>
                </div>
              )}
              {s1Rate && (
                <div className="flex items-center gap-4 p-4 bg-dark-700 rounded-lg border border-violet-900/40">
                  <span className={`text-4xl font-black ${rateColor(s1Rate.detection_rate_pct)}`}>
                    {s1Rate.detection_rate_pct != null ? `${s1Rate.detection_rate_pct.toFixed(1)}%` : '--'}
                  </span>
                  <div>
                    <p className="text-sm text-violet-300 font-semibold">SentinelOne</p>
                    <p className="text-xs text-gray-500">{s1Rate.detected_count ?? 0} / {s1Rate.total_count ?? 0} técnicas</p>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function SOARPanel() {
  const toast = useToast()
  const [soarType, setSoarType] = useState('splunk_soar')
  const [form, setForm] = useState({ base_url: '', api_token: '', verify_ssl: true })
  const [configured, setConfigured] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [simulations, setSimulations] = useState([])
  const [simId, setSimId] = useState('')
  const [pushing, setPushing] = useState(false)
  const [pushResult, setPushResult] = useState(null)

  const configure = async () => {
    if (!form.base_url || !form.api_token) {
      toast('Preencha Base URL e API Token', 'warning'); return
    }
    try {
      await api.post('/api/integrations/soar/configure', { soar_type: soarType, ...form })
      setConfigured(true)
      toast(`${soarType === 'splunk_soar' ? 'Splunk SOAR' : 'XSOAR'} configurado`, 'success')
      api.get('/api/bas/simulations').then(r => setSimulations((r.data.simulations || []).filter(s => s.status === 'completed'))).catch(() => {})
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao configurar', 'error') }
  }

  const test = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const r = await api.post('/api/integrations/soar/test', { soar_type: soarType })
      setTestResult(r.data)
    } catch (e) { setTestResult({ status: 'error', message: e.response?.data?.detail || 'Erro de conexão' }) }
    finally { setTesting(false) }
  }

  const pushFindings = async () => {
    if (!simId) { toast('Selecione uma simulação', 'warning'); return }
    setPushing(true)
    setPushResult(null)
    try {
      const r = await api.post('/api/integrations/soar/push-findings', { simulation_id: simId, soar_type: soarType })
      setPushResult(r.data)
      toast(`${r.data.pushed_count ?? 0} eventos enviados ao SOAR`, 'success')
    } catch (e) { toast(e.response?.data?.detail || 'Erro ao enviar findings', 'error') }
    finally { setPushing(false) }
  }

  const soarColor = soarType === 'splunk_soar' ? 'green' : 'orange'
  const colorMap = {
    green: { bg: 'bg-green-900/30', border: 'border-green-700/50', icon: 'text-green-400', btn: 'bg-green-700 hover:bg-green-600', badge: 'bg-green-900/40 text-green-400 border-green-800', tabActive: 'border-green-500 text-green-400' },
    orange: { bg: 'bg-orange-900/30', border: 'border-orange-700/50', icon: 'text-orange-400', btn: 'bg-orange-700 hover:bg-orange-600', badge: 'bg-orange-900/40 text-orange-400 border-orange-800', tabActive: 'border-orange-500 text-orange-400' },
  }
  const c = colorMap[soarColor]

  return (
    <div className="card-dark p-6 space-y-6">
      <div className="flex items-center gap-3 pb-3 border-b border-dark-600">
        <div className={`w-10 h-10 ${c.bg} border ${c.border} rounded-lg flex items-center justify-center`}>
          <Zap className={`w-5 h-5 ${c.icon}`} />
        </div>
        <div>
          <h2 className="font-bold text-gray-100">SOAR Integration</h2>
          <p className="text-xs text-gray-500">Envie findings do BAS como eventos/incidentes para o SOAR</p>
        </div>
        {configured && <span className={`ml-auto text-xs ${c.badge} border px-2 py-0.5 rounded`}>Configurado</span>}
      </div>

      <div className="flex gap-1 border-b border-dark-600">
        {[
          { id: 'splunk_soar', label: 'Splunk SOAR' },
          { id: 'xsoar', label: 'Cortex XSOAR' },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => { setSoarType(t.id); setConfigured(false); setTestResult(null); setPushResult(null) }}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${soarType === t.id ? (t.id === 'splunk_soar' ? 'border-green-500 text-green-400' : 'border-orange-500 text-orange-400') : 'border-transparent text-gray-400 hover:text-gray-200'}`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="md:col-span-2">
          <label className="text-xs text-gray-400 mb-1 block">
            {soarType === 'splunk_soar' ? 'Splunk SOAR Base URL' : 'XSOAR Base URL'}
          </label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder={soarType === 'splunk_soar' ? 'https://soar.empresa.com' : 'https://xsoar.empresa.com'}
            type="text"
            value={form.base_url}
            onChange={e => setForm(f => ({ ...f, base_url: e.target.value }))}
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">
            {soarType === 'splunk_soar' ? 'Automation User Token' : 'API Key'}
          </label>
          <input
            className="input-dark w-full font-mono text-sm"
            placeholder="•••••••••••••••••••"
            type="password"
            value={form.api_token}
            onChange={e => setForm(f => ({ ...f, api_token: e.target.value }))}
          />
        </div>
        <div className="flex items-end gap-3">
          <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer pb-2">
            <input
              type="checkbox"
              className="w-4 h-4 rounded border-dark-600 bg-dark-700 text-green-500"
              checked={form.verify_ssl}
              onChange={e => setForm(f => ({ ...f, verify_ssl: e.target.checked }))}
            />
            Verificar SSL
          </label>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <button onClick={configure} className={`flex items-center gap-2 px-4 py-2 ${c.btn} text-white rounded text-sm`}>
          <Settings className="w-4 h-4" /> Salvar configuração
        </button>
        {configured && (
          <button onClick={test} disabled={testing} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 border border-dark-600 text-gray-300 rounded text-sm">
            {testing ? 'Testando...' : 'Testar conexão'}
          </button>
        )}
      </div>

      {testResult && (
        <div className={`p-3 rounded border text-sm ${testResult.status === 'connected' ? 'bg-green-900/20 border-green-800 text-green-300' : 'bg-red-900/20 border-red-800 text-red-300'}`}>
          {testResult.status === 'connected' ? <CheckCircle className="w-4 h-4 inline mr-1" /> : <AlertTriangle className="w-4 h-4 inline mr-1" />}
          {testResult.message}
        </div>
      )}

      {configured && (
        <div className="space-y-4 pt-3 border-t border-dark-600">
          <h3 className="text-sm font-bold text-gray-200">
            Enviar Findings como {soarType === 'splunk_soar' ? 'Eventos' : 'Incidentes'}
          </h3>
          <div className="flex gap-3">
            <select className="select-dark flex-1" value={simId} onChange={e => setSimId(e.target.value)}>
              <option value="">Selecione uma simulação</option>
              {simulations.map(s => (
                <option key={s.id} value={s.id}>{s.playbook_name || s.id.slice(0, 8)} — {s.target}</option>
              ))}
            </select>
            <button onClick={pushFindings} disabled={pushing} className={`flex items-center gap-2 px-4 py-2 ${c.btn} text-white rounded text-sm`}>
              <Zap className="w-4 h-4" />
              {pushing ? 'Enviando...' : 'Push para SOAR'}
            </button>
          </div>

          {pushResult && (
            <div className="space-y-3">
              <div className="flex items-center gap-4 p-4 bg-dark-700 rounded-lg">
                <span className="text-4xl font-black text-green-400">{pushResult.pushed_count ?? 0}</span>
                <div>
                  <p className="text-sm text-gray-300 font-semibold">
                    {soarType === 'splunk_soar' ? 'Eventos criados no Splunk SOAR' : 'Incidentes criados no XSOAR'}
                  </p>
                  {pushResult.container_id && (
                    <p className="text-xs text-gray-500 mt-0.5">Container ID: <span className="font-mono text-gray-300">{pushResult.container_id}</span></p>
                  )}
                </div>
              </div>

              {pushResult.links && pushResult.links.length > 0 && (
                <div className="space-y-1">
                  <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wide">Links</h4>
                  {pushResult.links.map((link, i) => (
                    <a
                      key={i}
                      href={link.url || link}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 text-xs text-blue-400 hover:text-blue-300 underline"
                    >
                      <CheckCircle className="w-3 h-3 flex-shrink-0" />
                      {link.label || link.url || link}
                    </a>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function Integrations() {
  const [activeTab, setActiveTab] = useState('sentinel')

  const tabs = [
    { id: 'sentinel', label: 'Sentinel' },
    { id: 'wazuh', label: 'Wazuh' },
    { id: 'slack', label: 'Slack' },
    { id: 'teams', label: 'Teams' },
    { id: 'jira', label: 'Jira' },
    { id: 'crowdstrike', label: 'CrowdStrike' },
    { id: 'tenable', label: 'Tenable' },
    { id: 'qualys', label: 'Qualys' },
    { id: 'sentinelone', label: 'SentinelOne', icon: Shield },
    { id: 'defender', label: 'Defender XDR', icon: ShieldCheck },
    { id: 'soar', label: 'SOAR', icon: Zap },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
          <Link2 className="w-6 h-6 text-red-500" />
          Integrações
        </h1>
        <p className="text-sm text-gray-400 mt-1">Conecte o PenteIA com seu stack de segurança</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: 'Microsoft Sentinel', status: 'Disponível', color: 'text-blue-400' },
          { label: 'Wazuh', status: 'Disponível', color: 'text-orange-400' },
          { label: 'Slack', status: 'Disponível', color: 'text-green-400' },
          { label: 'Microsoft Teams', status: 'Disponível', color: 'text-purple-400' },
          { label: 'Jira', status: 'Disponível', color: 'text-blue-400' },
          { label: 'CrowdStrike Falcon', status: 'Disponível', color: 'text-red-400' },
          { label: 'Tenable.io / Nessus', status: 'Disponível', color: 'text-cyan-400' },
          { label: 'Qualys VMDR', status: 'Disponível', color: 'text-indigo-400' },
          { label: 'SentinelOne', status: 'Disponível', color: 'text-violet-400' },
          { label: 'Microsoft Defender XDR', status: 'Disponível', color: 'text-blue-400' },
          { label: 'SOAR (Splunk / XSOAR)', status: 'Disponível', color: 'text-green-400' },
        ].map(i => (
          <div key={i.label} className="card-dark p-3 flex items-center gap-3">
            <Link2 className="w-4 h-4 text-gray-500" />
            <span className="text-sm text-gray-300 flex-1">{i.label}</span>
            <span className={`text-xs ${i.color}`}>{i.status}</span>
          </div>
        ))}
      </div>

      <div className="flex gap-1 border-b border-dark-600">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-red-500 text-red-400'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'sentinel' && <SentinelPanel />}
      {activeTab === 'wazuh' && <WazuhPanel />}
      {activeTab === 'slack' && <SlackPanel />}
      {activeTab === 'teams' && <TeamsPanel />}
      {activeTab === 'jira' && <JiraPanel />}
      {activeTab === 'crowdstrike' && <CrowdStrikePanel />}
      {activeTab === 'tenable' && <TenablePanel />}
      {activeTab === 'qualys' && <QualysPanel />}
      {activeTab === 'sentinelone' && <SentinelOnePanel />}
      {activeTab === 'defender' && <DefenderPanel />}
      {activeTab === 'soar' && <SOARPanel />}
    </div>
  )
}
