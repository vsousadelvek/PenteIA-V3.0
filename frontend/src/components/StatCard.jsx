import React, { memo } from 'react'

const StatCard = memo(function StatCard({ title, value, icon: Icon, color = 'red' }) {
  const colors = {
    red: 'border-red-600 text-red-600',
    blue: 'border-blue-600 text-blue-600',
    green: 'border-green-600 text-green-600',
    yellow: 'border-yellow-600 text-yellow-600',
  }

  return (
    <div className={`card-dark p-6 border-l-4 ${colors[color]} slide-in`}>
      <div className="flex justify-between items-start">
        <div>
          <p className="text-gray-400 text-sm font-medium">{title}</p>
          <p className="text-3xl font-bold text-gray-100 mt-2">{value}</p>
        </div>
        {Icon && <Icon className={`w-8 h-8 ${colors[color]}`} strokeWidth={1.5} />}
      </div>
    </div>
  )
})

export default StatCard
