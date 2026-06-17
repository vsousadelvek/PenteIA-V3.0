import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Shield, Lock, Eye, EyeOff } from 'lucide-react'
import api from '../api'
import { useToast } from '../components/Toast'

const ERROR_MESSAGES = {
  'Invalid credentials': 'Usuário ou senha incorretos. Verifique e tente novamente.',
  'User not found': 'Usuário não encontrado. Verifique o nome de usuário.',
  'Username already exists': 'Este nome de usuário já está em uso. Escolha outro.',
  'Too many login attempts': 'Muitas tentativas de login. Aguarde alguns minutos e tente novamente.',
}

function translateError(msg) {
  if (!msg) return 'Erro na autenticação. Tente novamente.'
  for (const [key, val] of Object.entries(ERROR_MESSAGES)) {
    if (msg.includes(key)) return val
  }
  return msg
}

export default function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isLogin, setIsLogin] = useState(true)
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const navigate = useNavigate()
  const toast = useToast()

  const handleSSOLogin = async (provider) => {
    try {
      const r = await api.get('/api/auth/sso/authorize', { params: { provider, redirect_uri: window.location.origin + '/sso-callback' } })
      const redirectUrl = r.data.authorization_url || r.data.url
      if (redirectUrl) window.location.href = redirectUrl
      else throw new Error('URL de autorização não retornada')
    } catch (e) { toast('SSO não configurado ou indisponível', 'warning') }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register'
      const data = isLogin ? { username, password } : { username, email, password }

      const res = await api.post(endpoint, data)

      if (res.data.access_token) {
        localStorage.setItem('token', res.data.access_token)
        localStorage.setItem('username', res.data.username)
        localStorage.setItem('is_admin', res.data.is_admin ? 'true' : 'false')
        onLoginSuccess?.()
        navigate('/dashboard')
      }
    } catch (err) {
      setError(translateError(err.response?.data?.detail || ''))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-dark-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-6">

        {/* Logo e Descrição */}
        <div className="text-center">
          <div className="flex justify-center mb-4">
            <div className="w-16 h-16 rounded-2xl bg-red-600/20 border border-red-600/40 flex items-center justify-center">
              <Shield className="w-8 h-8 text-red-500" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-gray-100 mb-1">PenteIA v4.0</h1>
          <p className="text-gray-400 text-sm">Plataforma de Testes de Segurança Autorizada</p>
          <p className="text-gray-600 text-xs mt-1">Simulação de Ataques · Red Team · BAS</p>
        </div>

        {/* Aviso de Uso Autorizado */}
        <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-3 text-center">
          <p className="text-red-400 text-xs">
            <Lock className="w-3 h-3 inline mr-1" />
            Acesso restrito. Use apenas em ambientes autorizados.
          </p>
        </div>

        {/* Card de Login */}
        <div className="card-dark p-8">
          <h2 className="text-xl font-bold text-gray-100 mb-1">
            {isLogin ? 'Entrar na Plataforma' : 'Criar Nova Conta'}
          </h2>
          <p className="text-gray-500 text-sm mb-6">
            {isLogin
              ? 'Digite suas credenciais para acessar.'
              : 'Preencha os dados para criar uma conta de acesso.'}
          </p>

          {error && (
            <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-3 mb-5 text-red-400 text-sm flex gap-2">
              <span className="flex-shrink-0">⚠</span>
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Nome de Usuário
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="input-dark w-full"
                placeholder="seu_usuario"
                required
                autoFocus
                autoComplete="username"
              />
            </div>

            {!isLogin && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  E-mail <span className="text-gray-500 font-normal">(para recuperação de conta)</span>
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input-dark w-full"
                  placeholder="seu@email.com"
                  required
                  autoComplete="email"
                />
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Senha</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-dark w-full pr-10"
                  placeholder="••••••••"
                  required
                  autoComplete={isLogin ? 'current-password' : 'new-password'}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {!isLogin && password.length > 0 && password.length < 8 && (
                <p className="text-yellow-500 text-xs mt-1">Use pelo menos 8 caracteres para maior segurança.</p>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-blue w-full py-3 disabled:opacity-50 text-base font-semibold"
            >
              {loading
                ? 'Aguarde...'
                : isLogin ? 'Entrar' : 'Criar Conta e Entrar'}
            </button>
          </form>

          <div className="mt-6 pt-6 border-t border-dark-600 text-center">
            <p className="text-gray-400 text-sm mb-2">
              {isLogin ? 'Ainda não tem acesso?' : 'Já tem uma conta?'}
            </p>
            <button
              onClick={() => { setIsLogin(!isLogin); setError('') }}
              className="text-blue-400 hover:text-blue-300 transition text-sm font-medium"
            >
              {isLogin ? 'Solicitar criação de conta' : 'Fazer login'}
            </button>
          </div>

          {/* SSO Login */}
          <div className="mt-4 pt-4 border-t border-dark-600">
            <p className="text-center text-xs text-gray-500 mb-3">ou acesse via SSO</p>
            <div className="space-y-2">
              <button onClick={() => handleSSOLogin('azure')} className="w-full flex items-center gap-3 px-4 py-2.5 bg-dark-700 hover:bg-dark-600 border border-dark-600 rounded-lg text-sm text-gray-300">
                <span className="text-blue-400 font-bold text-xs">MS</span>
                <span>Continuar com Microsoft Azure AD</span>
              </button>
              <button onClick={() => handleSSOLogin('google')} className="w-full flex items-center gap-3 px-4 py-2.5 bg-dark-700 hover:bg-dark-600 border border-dark-600 rounded-lg text-sm text-gray-300">
                <span className="text-red-400 font-bold text-xs">G</span>
                <span>Continuar com Google Workspace</span>
              </button>
              <button onClick={() => handleSSOLogin('okta')} className="w-full flex items-center gap-3 px-4 py-2.5 bg-dark-700 hover:bg-dark-600 border border-dark-600 rounded-lg text-sm text-gray-300">
                <span className="text-blue-400 font-bold text-xs">OK</span>
                <span>Continuar com Okta</span>
              </button>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-center gap-4 text-xs text-gray-600">
          <span>Problemas de acesso? Contate o administrador.</span>
          <span>·</span>
          <Link to="/pricing" className="text-gray-500 hover:text-gray-300 transition underline underline-offset-2">
            Ver planos
          </Link>
        </div>
      </div>
    </div>
  )
}
