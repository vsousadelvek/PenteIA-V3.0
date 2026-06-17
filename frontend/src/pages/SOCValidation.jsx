import React, { useState, useEffect, useCallback } from 'react'
import { ShieldCheck, AlertTriangle, CheckCircle, XCircle, RefreshCw, Play, ChevronDown, ChevronRight, X } from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

const DET_COLOR = (v) => v === true ? 'text-green-400' : v === false ? 'text-red-400' : 'text-gray-500'
const DET_LABEL = (v) => v === true ? 'Detectado' : v === false ? 'NÃO detectado' : 'Desconhecido'

function ValidateModal({ onClose, onSaved }) {
  const toast = useToast()
  const [simulations, setSimulations] = useState([])
  const [form, setForm] = useState({ simulation_id: '', siem_type: 'wazuh', siem_url: '', siem_token: '' })
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    api.get('/api/bas/simulations').then(r => setSimulations((r.data.simulations || []).filter(s => s.status === 'completed'))).catch(() => {})
  }, [])

  const submit = async () => {
    if (!form.simulation_id) { toast('Selecione uma simulação', 'warning'); return }
    setLoading(true)
    try {
      await api.post('/api/soc/validate', {
        simulation_id: form.simulation_id,
        siem_type: form.siem_type,
        siem_url: form.siem_url || null,
        siem_token: form.siem_token || null,
      })
      toast('Validação SOC concluída', 'success')
      onSaved()
      onClose()
    } catch (e) { toast(e.response?.data?.detail || 'Erro', 'error') }
    finally { setLoading(false) }
  }

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-dark-800 border border-dark-600 rounded-xl shadow-2xl w-full max-w-lg" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-5 border-b border-dark-600">
          <h2 className="text-lg font-bold text-gray-100">Nova Validação SOC</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-100"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Simulação BAS</label>
            <select className="select-dark w-full" value={form.simulation_id} onChange={e => setForm(f => ({ ...f, simulation_id: e.target.value }))}>
              <option value="">Selecione uma simulação</option>
              {simulations.map(s => (
                <option key={s.id} value={s.id}>{s.playbook_name || s.id.slice(0, 8)} — {s.target}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">SIEM / EDR</label>
            <select className="select-dark w-full" value={form.siem_type} onChange={e => setForm(f => ({ ...f, siem_type: e.target.value }))}>
              <option value="wazuh">Wazuh</option>
              <option value="elastic">Elastic SIEM</option>
              <option value="splunk">Splunk</option>
              <option value="sentinel">Microsoft Sentinel</option>
              <option value="manual">Verificação Manual (simulado)</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">URL do SIEM <span className="text-gray-600">(opcional — deixe vazio para simulação)</span></label>
            <input className="input-dark w-full font-mono text-sm" placeholder="https://wazuh.empresa.com" value={form.siem_url} onChange={e => setForm(f => ({ ...f, siem_url: e.target.value }))} />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Token / API Key <span className="text-gray-600">(opcional)</span></label>
            <input className="input-dark w-full font-mono text-sm" type="password" placeholder="Bearer token..." value={form.siem_token} onChange={e => setForm(f => ({ ...f, siem_token: e.target.value }))} />
          </div>
          {!form.siem_url && (
            <div className="bg-blue-900/20 border border-blue-800/40 rounded p-3 text-xs text-blue-300">
              Sem URL configurada, o sistema usará dados simulados para demonstração do gap de detecção.
            </div>
          )}
        </div>
        <div className="flex justify-end gap-2 p-5 border-t border-dark-600">
          <button onClick={onClose} className="px-4 py-2 bg-dark-700 text-gray-300 rounded text-sm">Cancelar</button>
          <button onClick={submit} disabled={loading} className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded text-sm">
            <Play className="w-4 h-4" />
            {loading ? 'Validando...' : 'Iniciar Validação'}
          </button>
        </div>
      </div>
    </div>
  )
}

function ValidationDetail({ validation, onClose }) {
  const results = validation.results || []
  const detected = results.filter(r => r.siem_detected === true)
  const notDetected = results.filter(r => r.siem_detected === false)
  const unknown = results.filter(r => r.siem_detected === null)

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-dark-800 border border-dark-600 rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-5 border-b border-dark-600">
          <div>
            <h2 className="text-lg font-bold text-gray-100">Validação SOC</h2>
            <p className="text-xs text-gray-500">{validation.siem_type?.toUpperCase()} · {validation.created_at?.slice(0, 16).replace('T', ' ')}</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-100"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-5">
          <div className="grid grid-cols-3 gap-3">
            <div className="card-dark p-3 text-center">
              <p className="text-2xl font-bold text-gray-100">{results.length}</p>
              <p className="text-xs text-gray-500">Técnicas analisadas</p>
            </div>
            <div className="card-dark p-3 text-center">
              <p className="text-2xl font-bold text-green-400">{detected.length}</p>
              <p className="text-xs text-gray-500">Detectadas pelo SIEM</p>
            </div>
            <div className="card-dark p-3 text-center">
              <p className="text-2xl font-bold text-red-400">{notDetected.length}</p>
              <p className="text-xs text-gray-500">NÃO detectadas</p>
            </div>
          </div>

          <div className="card-dark p-4">
            <div className="flex justify-between text-xs text-gray-400 mb-2">
              <span>Taxa de detecção</span>
              <span className={`font-bold ${validation.detection_rate_pct >= 70 ? 'text-green-400' : validation.detection_rate_pct >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>
                {validation.detection_rate_pct}%
              </span>
            </div>
            <div className="w-full bg-dark-700 rounded-full h-3">
              <div
                className={`h-3 rounded-full ${validation.detection_rate_pct >= 70 ? 'bg-green-500' : validation.detection_rate_pct >= 40 ? 'bg-yellow-500' : 'bg-red-500'}`}
                style={{ width: `${validation.detection_rate_pct}%` }}
              />
            </div>
            <p className="text-xs text-gray-500 mt-2">
              {validation.detection_rate_pct >= 70 ? 'Boa cobertura de detecção' :
               validation.detection_rate_pct >= 40 ? 'Cobertura moderada — revise as regras do SIEM' :
               'Cobertura baixa — o SOC não está detectando a maioria dos ataques simulados'}
            </p>
          </div>

          {notDetected.length > 0 && (
            <div>
              <h3 className="text-sm font-bold text-red-400 mb-2 flex items-center gap-1">
                <XCircle className="w-4 h-4" /> Técnicas NÃO detectadas ({notDetected.length})
              </h3>
              <div className="space-y-2">
                {notDetected.map((r, i) => (
                  <div key={i} className="flex items-center gap-3 p-3 rounded bg-red-950/20 border border-red-800/30">
                    <span className="text-xs font-mono text-gray-500 w-20 shrink-0">{r.technique_id}</span>
                    <span className="text-sm text-gray-300 flex-1">{r.name}</span>
                    <span className={`text-xs px-2 py-0.5 rounded border ${r.severity === 'Critical' ? 'bg-red-900/40 text-red-400 border-red-700' : r.severity === 'High' ? 'bg-orange-900/40 text-orange-400 border-orange-700' : 'bg-yellow-900/40 text-yellow-400 border-yellow-700'}`}>
                      {r.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {detected.length > 0 && (
            <div>
              <h3 className="text-sm font-bold text-green-400 mb-2 flex items-center gap-1">
                <CheckCircle className="w-4 h-4" /> Técnicas detectadas ({detected.length})
              </h3>
              <div className="space-y-1">
                {detected.map((r, i) => (
                  <div key={i} className="flex items-center gap-3 p-2 rounded bg-dark-700/50">
                    <span className="text-xs font-mono text-gray-500 w-20 shrink-0">{r.technique_id}</span>
                    <span className="text-sm text-gray-400 flex-1">{r.name}</span>
                    <CheckCircle className="w-4 h-4 text-green-400" />
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function SOCValidation() {
  const toast = useToast()
  const [validations, setValidations] = useState([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [selected, setSelected] = useState(null)

  const load = useCallback(() => {
    setLoading(true)
    api.get('/api/soc/validations').then(r => setValidations(r.data.validations || [])).catch(() => {}).finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const getDetail = async (v) => {
    try {
      const r = await api.get(`/api/soc/validations/${v.id}`)
      setSelected(r.data)
    } catch { toast('Erro ao carregar detalhes', 'error') }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-red-500" />
            SOC Chain Validation
          </h1>
          <p className="text-sm text-gray-400 mt-1">Verifique se os ataques simulados foram detectados pelo SIEM/EDR</p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="p-2 text-gray-400 hover:text-gray-200 hover:bg-dark-700 rounded transition">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button onClick={() => setShowModal(true)} className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm transition">
            <Play className="w-4 h-4" /> Nova Validação
          </button>
        </div>
      </div>

      <div className="card-dark p-4 border-l-4 border-blue-600 bg-blue-900/10">
        <p className="text-sm text-blue-300">
          <strong>Como funciona:</strong> Execute uma simulação BAS, depois valide se o SIEM detectou as técnicas.
          O gap entre "atacou" e "foi detectado" é o risco real da sua organização.
        </p>
      </div>

      {loading ? (
        <div className="flex justify-center py-16">
          <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : validations.length === 0 ? (
        <div className="card-dark p-12 text-center">
          <ShieldCheck className="w-10 h-10 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">Nenhuma validação ainda</p>
          <p className="text-gray-600 text-sm mt-1">Execute uma simulação BAS primeiro, depois valide a detecção do SIEM</p>
          <button onClick={() => setShowModal(true)} className="mt-4 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded text-sm">
            Nova Validação
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {validations.map(v => (
            <div key={v.id} className="card-dark p-4 cursor-pointer hover:border-dark-500 transition" onClick={() => getDetail(v)}>
              <div className="flex items-center justify-between gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="text-xs bg-dark-700 text-gray-400 px-2 py-0.5 rounded font-mono">{v.siem_type?.toUpperCase()}</span>
                    <span className="text-sm text-gray-300">{v.total_techniques} técnicas analisadas</span>
                    <span className="text-xs text-gray-600">{v.created_at?.slice(0, 10)}</span>
                  </div>
                  <div className="flex items-center gap-4 mt-2">
                    <span className="text-xs text-green-400 flex items-center gap-1">
                      <CheckCircle className="w-3 h-3" /> {v.detected} detectadas
                    </span>
                    <span className="text-xs text-red-400 flex items-center gap-1">
                      <XCircle className="w-3 h-3" /> {v.not_detected} NÃO detectadas
                    </span>
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <p className={`text-2xl font-bold ${v.detection_rate_pct >= 70 ? 'text-green-400' : v.detection_rate_pct >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>
                    {v.detection_rate_pct}%
                  </p>
                  <p className="text-xs text-gray-500">detecção</p>
                </div>
              </div>
              <div className="w-full bg-dark-700 rounded-full h-1.5 mt-3">
                <div
                  className={`h-1.5 rounded-full ${v.detection_rate_pct >= 70 ? 'bg-green-500' : v.detection_rate_pct >= 40 ? 'bg-yellow-500' : 'bg-red-500'}`}
                  style={{ width: `${v.detection_rate_pct}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}

      {showModal && <ValidateModal onClose={() => setShowModal(false)} onSaved={load} />}
      {selected && <ValidationDetail validation={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
