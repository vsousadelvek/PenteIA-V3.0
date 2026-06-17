import React, { useState, useEffect, lazy, Suspense } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import ErrorBoundary from './components/ErrorBoundary'
import { ToastProvider } from './components/Toast'
import api from './api'

const Login = lazy(() => import('./pages/Login'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Recon = lazy(() => import('./pages/Recon'))
const DDoS = lazy(() => import('./pages/DDoS'))
const Modules = lazy(() => import('./pages/Modules'))
const C2 = lazy(() => import('./pages/C2'))
const BAS = lazy(() => import('./pages/BAS'))
const Evasion = lazy(() => import('./pages/Evasion'))
const Operations = lazy(() => import('./pages/Operations'))
const Reporting = lazy(() => import('./pages/Reporting'))
const Admin = lazy(() => import('./pages/Admin'))
const Campaign = lazy(() => import('./pages/Campaign'))
const Agents = lazy(() => import('./pages/Agents'))
const AttackPath = lazy(() => import('./pages/AttackPath'))
const ATTCKMatrix = lazy(() => import('./pages/ATTCKMatrix'))
const VulnDB = lazy(() => import('./pages/VulnDB'))
const Cloud = lazy(() => import('./pages/Cloud'))
const Phishing = lazy(() => import('./pages/Phishing'))
const SOCValidation = lazy(() => import('./pages/SOCValidation'))
const Remediation = lazy(() => import('./pages/Remediation'))
const Integrations = lazy(() => import('./pages/Integrations'))
const Pricing = lazy(() => import('./pages/Pricing'))
const CloudIdentity = lazy(() => import('./pages/CloudIdentity'))
const AI = lazy(() => import('./pages/AI'))
const APT = lazy(() => import('./pages/APT'))
const Compliance = lazy(() => import('./pages/Compliance'))
const ApiKeys = lazy(() => import('./pages/ApiKeys'))
const Tenants = lazy(() => import('./pages/Tenants'))
const ScheduledBAS = lazy(() => import('./pages/ScheduledBAS'))
const PurpleTeam = lazy(() => import('./pages/PurpleTeam'))
const PlaybookBuilder = lazy(() => import('./pages/PlaybookBuilder'))
const BRFiscal = lazy(() => import('./pages/BRFiscal'))
const AIScenarios = lazy(() => import('./pages/AIScenarios'))
const RealExecution = lazy(() => import('./pages/RealExecution'))
const MSSP = lazy(() => import('./pages/MSSP'))
const ADAttacks = lazy(() => import('./pages/ADAttacks'))
const Billing = lazy(() => import('./pages/Billing'))
const Landing = lazy(() => import('./pages/Landing'))

const SSOCallback = ({ onLoginSuccess }) => {
  const [status, setStatus] = React.useState('processing')
  React.useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code'); const state = params.get('state')
    if (!code) { setStatus('error'); return }
    api.post('/api/auth/sso/callback', { code, state, redirect_uri: window.location.origin + '/sso-callback' })
      .then(r => {
        localStorage.setItem('token', r.data.access_token)
        localStorage.setItem('username', r.data.username)
        localStorage.setItem('is_admin', r.data.is_admin)
        localStorage.setItem('user_role', r.data.role || 'user')
        onLoginSuccess()
        window.location.href = '/'
      })
      .catch(() => setStatus('error'))
  }, [])
  if (status === 'error') return <div className="flex items-center justify-center h-screen text-red-400">Erro no login SSO. Tente novamente.</div>
  return <div className="flex items-center justify-center h-screen text-gray-400">Autenticando via SSO...</div>
}

const ProtectedRoute = ({ element }) => {
  const token = localStorage.getItem('token')
  return token ? element : <Navigate to="/login" replace />
}

const AdminRoute = ({ element, isAdmin }) => {
  const token = localStorage.getItem('token')
  if (!token) return <Navigate to="/login" replace />
  if (!isAdmin) return <Navigate to="/" replace />
  return element
}

const PageLoader = () => (
  <div className="flex items-center justify-center py-24">
    <div className="w-8 h-8 border-2 border-red-600 border-t-transparent rounded-full animate-spin" />
  </div>
)

export default function App() {
  const [systemStatus, setSystemStatus] = useState('online')
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'))
  const [isAdmin, setIsAdmin] = useState(localStorage.getItem('is_admin') === 'true')
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => localStorage.getItem('sidebar_collapsed') === 'true')

  useEffect(() => {
    const checkHealth = async () => {
      try {
        await api.get('/api/health')
        setSystemStatus('online')
      } catch {
        setSystemStatus('offline')
      }
    }
    checkHealth()
    const interval = setInterval(checkHealth, 30000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    if (isAuthenticated) {
      api.get('/api/auth/me')
        .then(res => {
          setIsAdmin(res.data.is_admin || false)
          localStorage.setItem('user_role', res.data.role || 'user')
        })
        .catch(() => setIsAdmin(false))
    } else {
      setIsAdmin(false)
    }
  }, [isAuthenticated])

  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('username')
    localStorage.removeItem('is_admin')
    localStorage.removeItem('user_role')
    setIsAuthenticated(false)
    window.location.href = '/login'
  }

  const handleLoginSuccess = () => setIsAuthenticated(true)

  return (
    <ToastProvider>
      <Router>
        <ErrorBoundary>
          <div className="flex min-h-screen bg-dark-900">
            {isAuthenticated && (
              <Sidebar systemStatus={systemStatus} onLogout={handleLogout} isAdmin={isAdmin} onCollapse={setSidebarCollapsed} />
            )}
            <div
              className="flex-1 flex flex-col min-w-0 transition-all duration-200"
              style={{ paddingLeft: isAuthenticated ? (sidebarCollapsed ? 56 : 220) : 0 }}
            >
              <main className="flex-1 px-6 py-6">
                <Suspense fallback={<PageLoader />}>
                  <Routes>
                    <Route path="/login" element={<Login onLoginSuccess={handleLoginSuccess} />} />
                    <Route path="/" element={isAuthenticated ? <Navigate to="/dashboard" replace /> : <Landing />} />
                    <Route path="/dashboard" element={<ProtectedRoute element={<Dashboard />} />} />
                    <Route path="/recon" element={<ProtectedRoute element={<Recon />} />} />
                    <Route path="/ddos" element={<ProtectedRoute element={<DDoS />} />} />
                    <Route path="/modules" element={<ProtectedRoute element={<Modules />} />} />
                    <Route path="/c2" element={<ProtectedRoute element={<C2 />} />} />
                    <Route path="/bas" element={<ProtectedRoute element={<BAS />} />} />
                    <Route path="/playbook-builder" element={<ProtectedRoute element={<PlaybookBuilder />} />} />
                    <Route path="/evasion" element={<ProtectedRoute element={<Evasion />} />} />
                    <Route path="/operations" element={<ProtectedRoute element={<Operations />} />} />
                    <Route path="/reporting" element={<ProtectedRoute element={<Reporting />} />} />
                    <Route path="/campaign" element={<ProtectedRoute element={<Campaign />} />} />
                    <Route path="/agents" element={<ProtectedRoute element={<Agents />} />} />
                    <Route path="/admin" element={<AdminRoute element={<Admin />} isAdmin={isAdmin} />} />
                    <Route path="/attack-path/:simId" element={<ProtectedRoute element={<AttackPath />} />} />
                    <Route path="/attck-matrix" element={<ProtectedRoute element={<ATTCKMatrix />} />} />
                    <Route path="/vulndb" element={<ProtectedRoute element={<VulnDB />} />} />
                    <Route path="/cloud" element={<ProtectedRoute element={<Cloud />} />} />
                    <Route path="/phishing" element={<ProtectedRoute element={<Phishing />} />} />
                    <Route path="/soc-validation" element={<ProtectedRoute element={<SOCValidation />} />} />
                    <Route path="/remediation" element={<ProtectedRoute element={<Remediation />} />} />
                    <Route path="/integrations" element={<ProtectedRoute element={<Integrations />} />} />
                    <Route path="/pricing" element={<Navigate to="/" replace />} />
                    <Route path="/cloud-identity" element={<ProtectedRoute element={<CloudIdentity />} />} />
                    <Route path="/ai" element={<ProtectedRoute element={<AI />} />} />
                    <Route path="/apt" element={<ProtectedRoute element={<APT />} />} />
                    <Route path="/compliance" element={<ProtectedRoute element={<Compliance />} />} />
                    <Route path="/api-keys" element={<ProtectedRoute element={<ApiKeys />} />} />
                    <Route path="/tenants" element={<ProtectedRoute element={<Tenants />} />} />
                    <Route path="/scheduled-bas" element={<ProtectedRoute element={<ScheduledBAS />} />} />
                    <Route path="/purple-team" element={<ProtectedRoute element={<PurpleTeam />} />} />
                    <Route path="/br-fiscal" element={<ProtectedRoute element={<BRFiscal />} />} />
                    <Route path="/ai-scenarios" element={<ProtectedRoute element={<AIScenarios />} />} />
                    <Route path="/real-execution" element={<ProtectedRoute element={<RealExecution />} />} />
                    <Route path="/mssp" element={<ProtectedRoute element={<MSSP />} />} />
                    <Route path="/ad-attacks" element={<ProtectedRoute element={<ADAttacks />} />} />
                    <Route path="/billing" element={<ProtectedRoute element={<Billing />} />} />
                    <Route path="/sso-callback" element={<SSOCallback onLoginSuccess={handleLoginSuccess} />} />
                  </Routes>
                </Suspense>
              </main>
            </div>
          </div>
        </ErrorBoundary>
      </Router>
    </ToastProvider>
  )
}
