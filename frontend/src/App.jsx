import React, { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import Dashboard from './pages/Dashboard'
import Recon from './pages/Recon'
import DDoS from './pages/DDoS'
import Modules from './pages/Modules'
import C2 from './pages/C2'
import BAS from './pages/BAS'
import Evasion from './pages/Evasion'
import Operations from './pages/Operations'
import Reporting from './pages/Reporting'

export default function App() {
  const [systemStatus, setSystemStatus] = useState('online')

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch('/api/health')
        if (res.ok) setSystemStatus('online')
      } catch {
        setSystemStatus('offline')
      }
    }
    checkHealth()
    const interval = setInterval(checkHealth, 30000)
    return () => clearInterval(interval)
  }, [])

  return (
    <Router>
      <div className="flex flex-col min-h-screen bg-dark-900">
        <Navbar systemStatus={systemStatus} />
        <main className="flex-1 container mx-auto px-4 py-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/recon" element={<Recon />} />
            <Route path="/ddos" element={<DDoS />} />
            <Route path="/modules" element={<Modules />} />
            <Route path="/c2" element={<C2 />} />
            <Route path="/bas" element={<BAS />} />
            <Route path="/evasion" element={<Evasion />} />
            <Route path="/operations" element={<Operations />} />
            <Route path="/reporting" element={<Reporting />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </Router>
  )
}
