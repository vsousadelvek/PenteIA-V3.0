import React, { useState, useEffect, lazy, Suspense } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import Navbar from './components/Navbar'
import Footer from './components/Footer'
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
        .then(res => setIsAdmin(res.data.is_admin || false))
        .catch(() => setIsAdmin(false))
    } else {
      setIsAdmin(false)
    }
  }, [isAuthenticated])

  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('username')
    localStorage.removeItem('is_admin')
    setIsAuthenticated(false)
    window.location.href = '/login'
  }

  const handleLoginSuccess = () => setIsAuthenticated(true)

  return (
    <ToastProvider>
      <Router>
        <ErrorBoundary>
          <div className="flex flex-col min-h-screen bg-dark-900">
            {isAuthenticated && <Navbar systemStatus={systemStatus} onLogout={handleLogout} isAdmin={isAdmin} />}
            <main className="flex-1 container mx-auto px-4 py-8">
              <Suspense fallback={<PageLoader />}>
                <Routes>
                  <Route path="/login" element={<Login onLoginSuccess={handleLoginSuccess} />} />
                  <Route path="/" element={<ProtectedRoute element={<Dashboard />} />} />
                  <Route path="/dashboard" element={<ProtectedRoute element={<Dashboard />} />} />
                  <Route path="/recon" element={<ProtectedRoute element={<Recon />} />} />
                  <Route path="/ddos" element={<ProtectedRoute element={<DDoS />} />} />
                  <Route path="/modules" element={<ProtectedRoute element={<Modules />} />} />
                  <Route path="/c2" element={<ProtectedRoute element={<C2 />} />} />
                  <Route path="/bas" element={<ProtectedRoute element={<BAS />} />} />
                  <Route path="/evasion" element={<ProtectedRoute element={<Evasion />} />} />
                  <Route path="/operations" element={<ProtectedRoute element={<Operations />} />} />
                  <Route path="/reporting" element={<ProtectedRoute element={<Reporting />} />} />
                  <Route path="/campaign" element={<ProtectedRoute element={<Campaign />} />} />
                  <Route path="/admin" element={<AdminRoute element={<Admin />} isAdmin={isAdmin} />} />
                </Routes>
              </Suspense>
            </main>
            {isAuthenticated && <Footer />}
          </div>
        </ErrorBoundary>
      </Router>
    </ToastProvider>
  )
}
