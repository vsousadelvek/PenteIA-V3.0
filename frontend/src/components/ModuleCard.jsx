import React, { memo } from 'react'

const ModuleCard = memo(function ModuleCard({ name, icon: Icon, color, description }) {
  const colors = {
    red: 'text-red-600 border-red-600/30 hover:border-red-600',
    blue: 'text-blue-600 border-blue-600/30 hover:border-blue-600',
    green: 'text-green-600 border-green-600/30 hover:border-green-600',
    yellow: 'text-yellow-600 border-yellow-600/30 hover:border-yellow-600',
    purple: 'text-purple-600 border-purple-600/30 hover:border-purple-600',
    orange: 'text-orange-600 border-orange-600/30 hover:border-orange-600',
    cyan: 'text-cyan-600 border-cyan-600/30 hover:border-cyan-600',
  }

  return (
    <div className={`card-dark p-4 ${colors[color]} transition-all hover:shadow-lg cursor-pointer`}>
      <div className="mb-3">
        {Icon ? <Icon className="w-8 h-8" /> : <div className="text-2xl">📦</div>}
      </div>
      <h3 className="font-semibold text-gray-100 text-sm">{name}</h3>
      <p className="text-xs text-gray-400 mt-1">{description}</p>
      <div className="mt-3 pt-3 border-t border-dark-600">
        <span className="inline-block text-xs bg-dark-700 text-gray-300 px-2 py-1 rounded">Pronto</span>
      </div>
    </div>
  )
})

export default ModuleCard
