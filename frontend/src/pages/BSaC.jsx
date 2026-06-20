import { useState, useEffect } from 'react'
import { GitBranch, Play, CheckCircle, XCircle, Download, Code2, Loader, Copy, Terminal } from 'lucide-react'
import api from '../api'
import { useToast } from '../components/Toast'

export default function BSaC() {
  const [yaml, setYaml] = useState('')
  const [target, setTarget] = useState('')
  const [validating, setValidating] = useState(false)
  const [running, setRunning] = useState(false)
  const [validateResult, setValidateResult] = useState(null)
  const [runResult, setRunResult] = useState(null)
  const [githubTemplate, setGithubTemplate] = useState('')
  const [activeTab, setActiveTab] = useState('editor')
  const toast = useToast()

  useEffect(() => {
    api.get('/api/bsac/example')
      .then(r => {
        setYaml(r.data.playbook_yaml || '')
        setGithubTemplate(r.data.github_actions || '')
      })
      .catch(() => {})
  }, [])

  const handleValidate = async () => {
    setValidating(true)
    setValidateResult(null)
    try {
      const { data } = await api.post('/api/bsac/validate', { playbook_yaml: yaml, target: target || 'validate-only' })
      setValidateResult(data)
      toast(data.valid ? 'Playbook válido!' : 'Erros encontrados no playbook', data.valid ? 'success' : 'error')
    } catch (e) {
      toast('Erro na validação', 'error')
    } finally {
      setValidating(false)
    }
  }

  const handleRun = async () => {
    if (!target.trim()) { toast('Informe o alvo', 'error'); return }
    setRunning(true)
    setRunResult(null)
    try {
      const { data } = await api.post('/api/bsac/run', { playbook_yaml: yaml, target })
      setRunResult(data)
      toast(data.passed ? 'Playbook PASSOU nos critérios' : 'Playbook FALHOU — vulnerabilidades detectadas', data.passed ? 'success' : 'error')
    } catch (e) {
      toast(e.response?.data?.detail?.errors?.join(', ') || 'Erro na execução', 'error')
    } finally {
      setRunning(false)
    }
  }

  const handleJunit = async () => {
    if (!target.trim()) { toast('Informe o alvo', 'error'); return }
    try {
      const { data } = await api.post('/api/bsac/run/junit', { playbook_yaml: yaml, target }, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([data]))
      const a = document.createElement('a')
      a.href = url; a.download = 'penteia-results.xml'; a.click()
    } catch {
      toast('Erro ao gerar JUnit XML', 'error')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <GitBranch size={24} className="text-red-500" />
          Breach Simulation as Code
          <span className="text-xs bg-blue-900/40 border border-blue-700 text-blue-300 px-2 py-0.5 rounded">CI/CD</span>
        </h1>
        <p className="text-gray-400 mt-1">Defina playbooks de BAS em YAML e integre com pipelines de CI/CD</p>
      </div>

      <div className="flex gap-2">
        {[
          { id: 'editor', label: 'Editor YAML', icon: <Code2 size={14} /> },
          { id: 'github', label: 'GitHub Actions', icon: <GitBranch size={14} /> },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium ${
              activeTab === t.id ? 'bg-red-700 text-white' : 'bg-dark-800 text-gray-400 hover:text-white'
            }`}
          >
            {t.icon}{t.label}
          </button>
        ))}
      </div>

      {activeTab === 'editor' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-3">
            <div className="bg-dark-800 border border-dark-600 rounded-lg overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2 border-b border-dark-600">
                <span className="text-sm font-medium text-gray-300 flex items-center gap-1.5"><Code2 size={14} />playbook.yaml</span>
                <button
                  onClick={() => { navigator.clipboard.writeText(yaml); toast('Copiado!', 'success') }}
                  className="text-xs text-gray-500 hover:text-gray-300 flex items-center gap-1"
                >
                  <Copy size={12} />Copiar
                </button>
              </div>
              <textarea
                value={yaml}
                onChange={e => setYaml(e.target.value)}
                className="w-full h-80 bg-dark-900 text-green-300 font-mono text-xs p-4 resize-none border-none outline-none"
                spellCheck={false}
              />
            </div>
            <div className="flex gap-2">
              <input
                value={target}
                onChange={e => setTarget(e.target.value)}
                placeholder="Alvo (ex: 10.0.0.1)"
                className="flex-1 bg-dark-800 border border-dark-600 rounded px-3 py-2 text-sm text-white"
              />
              <button
                onClick={handleValidate}
                disabled={validating}
                className="flex items-center gap-1.5 bg-dark-700 hover:bg-dark-600 border border-dark-500 text-white text-sm px-3 py-2 rounded"
              >
                {validating ? <Loader size={14} className="animate-spin" /> : <CheckCircle size={14} />}
                Validar
              </button>
              <button
                onClick={handleRun}
                disabled={running}
                className="flex items-center gap-1.5 bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white text-sm px-3 py-2 rounded"
              >
                {running ? <Loader size={14} className="animate-spin" /> : <Play size={14} />}
                Executar
              </button>
              <button
                onClick={handleJunit}
                className="flex items-center gap-1.5 bg-dark-700 hover:bg-dark-600 border border-dark-500 text-white text-sm px-3 py-2 rounded"
              >
                <Download size={14} />JUnit
              </button>
            </div>
          </div>

          <div className="space-y-4">
            {validateResult && (
              <div className={`border rounded-lg p-4 ${validateResult.valid ? 'border-green-700 bg-green-900/20' : 'border-red-700 bg-red-900/20'}`}>
                <div className="flex items-center gap-2 mb-2">
                  {validateResult.valid ? <CheckCircle size={16} className="text-green-400" /> : <XCircle size={16} className="text-red-400" />}
                  <span className={`font-medium text-sm ${validateResult.valid ? 'text-green-300' : 'text-red-300'}`}>
                    {validateResult.valid ? 'Playbook Válido' : 'Erros Encontrados'}
                  </span>
                </div>
                {(validateResult.errors || []).map((e, i) => (
                  <div key={i} className="text-xs text-red-300 mt-1">{e}</div>
                ))}
                {validateResult.valid && validateResult.playbook && (
                  <div className="text-xs text-gray-400 mt-1">{validateResult.playbook.techniques?.length} técnicas configuradas</div>
                )}
              </div>
            )}

            {runResult && (
              <div className={`border rounded-lg p-4 ${runResult.passed ? 'border-green-700 bg-green-900/20' : 'border-red-700 bg-red-900/20'}`}>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    {runResult.passed ? <CheckCircle size={16} className="text-green-400" /> : <XCircle size={16} className="text-red-400" />}
                    <span className={`font-semibold text-sm ${runResult.passed ? 'text-green-300' : 'text-red-300'}`}>
                      {runResult.passed ? 'PASSOU' : 'FALHOU'}
                    </span>
                  </div>
                  <span className={`text-xs font-mono px-2 py-0.5 rounded ${runResult.ci_exit_code === 0 ? 'bg-green-800 text-green-200' : 'bg-red-800 text-red-200'}`}>
                    exit {runResult.ci_exit_code}
                  </span>
                </div>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between"><span className="text-gray-400">Score</span><span className="text-white font-bold">{runResult.score}</span></div>
                  <div className="flex justify-between"><span className="text-gray-400">Técnicas</span><span className="text-white">{runResult.techniques_tested}</span></div>
                  {runResult.fail_reason && <div className="text-red-300 mt-1">{runResult.fail_reason}</div>}
                </div>
                <div className="mt-3 space-y-1">
                  {(runResult.results || []).map(r => (
                    <div key={r.technique_id} className="flex items-center gap-2 text-xs">
                      {r.status === 'found' ? <XCircle size={12} className="text-red-400" /> : <CheckCircle size={12} className="text-green-400" />}
                      <span className="text-gray-300">{r.name}</span>
                      <span className="text-gray-500 ml-auto">{r.severity}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="bg-dark-800 border border-dark-600 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-1.5">
                <Terminal size={14} />CLI Integration
              </h3>
              <div className="space-y-2 text-xs font-mono text-gray-300">
                <div className="bg-dark-900 rounded p-2">curl -X POST $PENTEIA_URL/api/bsac/run \</div>
                <div className="bg-dark-900 rounded p-2">-H "Authorization: Bearer $TOKEN" \</div>
                <div className="bg-dark-900 rounded p-2">-d @playbook.yaml</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'github' && (
        <div className="bg-dark-800 border border-dark-600 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-dark-600">
            <span className="text-sm font-medium text-gray-300">.github/workflows/penteia.yml</span>
            <button
              onClick={() => { navigator.clipboard.writeText(githubTemplate); toast('Copiado!', 'success') }}
              className="text-xs text-gray-500 hover:text-gray-300 flex items-center gap-1"
            >
              <Copy size={12} />Copiar
            </button>
          </div>
          <pre className="text-xs text-green-300 font-mono p-4 overflow-x-auto whitespace-pre-wrap">{githubTemplate}</pre>
        </div>
      )}
    </div>
  )
}
