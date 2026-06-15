import React, { useEffect, useState, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ReactFlow,
  Background, Controls, MiniMap,
  useNodesState, useEdgesState, ReactFlowProvider,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { ArrowLeft, AlertTriangle, Shield, Target, Activity } from 'lucide-react'
import api from '../api'

const SEV_COLOR = { Critical: '#e74c3c', High: '#e67e22', Medium: '#f39c12', Low: '#2980b9', '': '#95a5a6' }

function TechniqueNode({ data }) {
  const isFound = data.status === 'found'
  const borderColor = isFound ? '#e74c3c' : data.status === 'blocked' ? '#27ae60' : '#64748b'
  const bgColor = isFound ? 'rgba(231,76,60,0.12)' : data.status === 'blocked' ? 'rgba(39,174,96,0.12)' : 'rgba(100,116,139,0.12)'
  return (
    <div style={{ border: `2px solid ${borderColor}`, background: bgColor, borderRadius: 8, padding: '8px 12px', minWidth: 140, maxWidth: 180, fontSize: 11 }}>
      <div style={{ color: borderColor, fontWeight: 700, marginBottom: 2 }}>{data.label?.split('\n')[0]}</div>
      <div style={{ color: '#94a3b8', fontSize: 10, marginBottom: 4 }}>{data.label?.split('\n')[1] || ''}</div>
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
        {data.severity && <span style={{ background: SEV_COLOR[data.severity] || '#64748b', color: '#fff', fontSize: 9, padding: '1px 5px', borderRadius: 4 }}>{data.severity}</span>}
        {data.cvss > 0 && <span style={{ background: '#1e293b', color: '#94a3b8', fontSize: 9, padding: '1px 5px', borderRadius: 4 }}>CVSS {data.cvss}</span>}
      </div>
    </div>
  )
}

function AttackerNode({ data }) {
  return (
    <div style={{ border: '2px solid #e74c3c', background: 'rgba(231,76,60,0.15)', borderRadius: 8, padding: '10px 14px', textAlign: 'center', minWidth: 120 }}>
      <div style={{ fontSize: 20, marginBottom: 4 }}>🌐</div>
      <div style={{ color: '#e74c3c', fontWeight: 700, fontSize: 12 }}>{data.label}</div>
    </div>
  )
}

function TargetNode({ data }) {
  return (
    <div style={{ border: '2px solid #3b82f6', background: 'rgba(59,130,246,0.15)', borderRadius: 8, padding: '10px 14px', textAlign: 'center', minWidth: 120 }}>
      <div style={{ fontSize: 20, marginBottom: 4 }}>🖥️</div>
      <div style={{ color: '#3b82f6', fontWeight: 700, fontSize: 12 }}>{data.label}</div>
    </div>
  )
}

const nodeTypes = { attacker: AttackerNode, target: TargetNode, technique: TechniqueNode }

function AttackPathInner() {
  const { simId } = useParams()
  const navigate = useNavigate()
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [summary, setSummary] = useState(null)
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!simId) return
    api.get(`/api/bas/simulations/${simId}/graph`)
      .then(res => {
        const { nodes: n, edges: e, summary: s } = res.data
        // Map node types for ReactFlow
        const mapped = n.map(node => ({
          ...node,
          type: node.data?.type === 'attacker' ? 'attacker' : node.data?.type === 'server' ? 'target' : 'technique',
        }))
        setNodes(mapped)
        setEdges(e)
        setSummary(s)
      })
      .catch(err => setError(err.response?.data?.detail || 'Erro ao carregar grafo'))
      .finally(() => setLoading(false))
  }, [simId])

  const onNodeClick = useCallback((_, node) => {
    if (node.type === 'technique') setSelected(node.data)
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-96">
      <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
    </div>
  )

  if (error) return (
    <div className="card-dark p-8 text-center">
      <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
      <p className="text-red-400">{error}</p>
      <button onClick={() => navigate(-1)} className="mt-4 text-sm text-gray-400 hover:text-gray-200">← Voltar</button>
    </div>
  )

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button onClick={() => navigate(-1)} className="text-gray-400 hover:text-gray-200 transition">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-100">Attack Path — Grafo de Ataque</h1>
            <p className="text-gray-400 text-sm">Visualização de vetores testados nesta simulação</p>
          </div>
        </div>
      </div>

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="card-dark p-4">
            <p className="text-gray-400 text-xs mb-1">Total Técnicas</p>
            <p className="text-2xl font-bold text-gray-100">{summary.total}</p>
          </div>
          <div className="card-dark p-4">
            <p className="text-gray-400 text-xs mb-1">Vulneráveis</p>
            <p className="text-2xl font-bold text-red-400">{summary.found}</p>
          </div>
          <div className="card-dark p-4">
            <p className="text-gray-400 text-xs mb-1">Bloqueados</p>
            <p className="text-2xl font-bold text-green-400">{summary.blocked}</p>
          </div>
          <div className="card-dark p-4">
            <p className="text-gray-400 text-xs mb-1">Cobertura Detecção</p>
            <p className={`text-2xl font-bold ${summary.detection_coverage_pct >= 70 ? 'text-green-400' : summary.detection_coverage_pct >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>
              {summary.detection_coverage_pct?.toFixed(1)}%
            </p>
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="flex gap-4 text-xs text-gray-400">
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-500/50 border border-red-500 inline-block" /> Vulnerável (borda animada)</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-green-500/50 border border-green-500 inline-block" /> Bloqueado (tracejado)</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-gray-500/30 border border-gray-500 inline-block" /> Desconhecido</span>
      </div>

      {/* Main layout: graph + detail panel */}
      <div className="flex gap-4" style={{ height: 520 }}>
        <div className="flex-1 rounded-xl overflow-hidden border border-dark-600" style={{ background: '#0d1117' }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.2 }}
          >
            <Background color="#1e293b" gap={20} />
            <Controls style={{ background: '#1e293b', border: '1px solid #334155' }} />
            <MiniMap style={{ background: '#1e293b' }} nodeColor={n => n.data?.status === 'found' ? '#e74c3c' : n.data?.status === 'blocked' ? '#27ae60' : '#64748b'} />
          </ReactFlow>
        </div>

        {/* Detail panel */}
        <div className="w-72 card-dark p-4 overflow-y-auto flex-shrink-0">
          {selected ? (
            <div className="space-y-3 text-sm">
              <div>
                <p className="text-xs text-gray-500 mb-1">Técnica</p>
                <p className="text-gray-100 font-bold">{selected.label?.split('\n')[0]}</p>
                <p className="text-gray-400">{selected.label?.split('\n')[1]}</p>
              </div>
              <div className="flex gap-2">
                {selected.severity && (
                  <span className="text-xs px-2 py-0.5 rounded font-bold" style={{ background: SEV_COLOR[selected.severity] + '33', color: SEV_COLOR[selected.severity], border: `1px solid ${SEV_COLOR[selected.severity]}` }}>
                    {selected.severity}
                  </span>
                )}
                {selected.status === 'found'
                  ? <span className="text-xs px-2 py-0.5 rounded bg-red-900/30 text-red-400 border border-red-700">Vulnerável</span>
                  : <span className="text-xs px-2 py-0.5 rounded bg-green-900/30 text-green-400 border border-green-700">Bloqueado</span>
                }
              </div>
              {selected.cvss > 0 && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">CVSS Score</p>
                  <p className="text-gray-100 font-mono text-lg font-bold">{selected.cvss}</p>
                </div>
              )}
              {selected.detail && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Evidência</p>
                  <p className="text-gray-300 text-xs leading-relaxed">{selected.detail}</p>
                </div>
              )}
              {selected.compliance?.length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Compliance</p>
                  <div className="flex flex-wrap gap-1">
                    {selected.compliance.map(c => (
                      <span key={c} className="text-xs px-1.5 py-0.5 rounded bg-dark-700 text-cyan-400 border border-dark-500">{c}</span>
                    ))}
                  </div>
                </div>
              )}
              {selected.remediation && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Remediação</p>
                  <p className="text-gray-300 text-xs leading-relaxed">{selected.remediation}</p>
                </div>
              )}
              <button onClick={() => setSelected(null)} className="text-xs text-gray-500 hover:text-gray-300 mt-2">← Fechar detalhe</button>
            </div>
          ) : (
            <div className="text-center py-12">
              <Target className="w-8 h-8 text-gray-600 mx-auto mb-3" />
              <p className="text-gray-500 text-sm">Clique em uma técnica no grafo para ver os detalhes</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function AttackPath() {
  return (
    <ReactFlowProvider>
      <AttackPathInner />
    </ReactFlowProvider>
  )
}
