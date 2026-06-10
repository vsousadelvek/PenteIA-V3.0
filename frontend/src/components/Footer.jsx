import React from 'react'

export default function Footer() {
  return (
    <footer className="bg-dark-800 border-t border-dark-700 mt-16">
      <div className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div>
            <h3 className="font-bold text-red-600 mb-2">PenteIA v4.0</h3>
            <p className="text-gray-400 text-sm">Plataforma Red Team para testes autorizados</p>
          </div>
          <div>
            <h4 className="font-semibold text-gray-100 mb-2">Aviso Legal</h4>
            <p className="text-gray-400 text-xs">
              Use apenas em ambientes autorizados. Teste sem permissão é ilegal.
            </p>
          </div>
          <div className="text-right">
            <p className="text-gray-400 text-sm">
              <span id="current-time"></span>
            </p>
          </div>
        </div>
        <div className="border-t border-dark-700 mt-8 pt-8 text-center text-gray-500 text-xs">
          <p>© 2026 PenteIA v4.0 | Desenvolvido para testes autorizados</p>
        </div>
      </div>
    </footer>
  )
}
