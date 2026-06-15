import { useState, useEffect } from 'react'

const KEY = 'penteia_env'
const EV  = 'penteia-env-changed'

export function getEnv() {
  try { return JSON.parse(localStorage.getItem(KEY) || '{}') } catch { return {} }
}

export function saveEnv(env) {
  localStorage.setItem(KEY, JSON.stringify(env))
  window.dispatchEvent(new Event(EV))
}

export function useEnv() {
  const [env, set] = useState(getEnv)
  useEffect(() => {
    const h = () => set(getEnv())
    window.addEventListener(EV, h)
    return () => window.removeEventListener(EV, h)
  }, [])
  return env
}
