import { useQuery } from '@tanstack/react-query'
import { apiService } from '@/services/api'
import { BarChart, Bar, PieChart, Pie, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from 'recharts'
import { AlertTriangle, Shield, TrendingUp, Activity } from 'lucide-react'
import { format } from 'date-fns'

const COLORS = {
  Critical: '#dc2626',
  High: '#ea580c',
  Medium: '#eab308',
  Low: '#22c55e',
}

const ATTACK_TYPE_COLORS = [
  '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981',
  '#06b6d4', '#6366f1', '#f97316', '#84cc16', '#a855f7'
]

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['stats'],
    queryFn: () => apiService.getStats(),
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const { data: timeline, isLoading: timelineLoading } = useQuery({
    queryKey: ['timeline'],
    queryFn: () => apiService.getTimeline(24),
    refetchInterval: 60000, // Refresh every minute
  })

  if (statsLoading || timelineLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  // Prepare data for charts
  const severityData = stats?.severities.map(s => ({
    name: s.severity,
    value: s.count,
  })) || []

  const attackTypeData = stats?.attack_types.map(at => ({
    name: at.type,
    count: at.count,
  })).slice(0, 10) || []

  const timelineData = timeline?.timeline.map(t => ({
    time: format(new Date(t.timestamp), 'HH:mm'),
    count: t.count,
  })) || []

  const topIPsData = stats?.top_attacking_ips.slice(0, 8) || []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold text-gray-900">Security Dashboard</h2>
        <p className="text-gray-600 mt-1">Real-time URL attack monitoring and analysis</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card bg-gradient-to-br from-blue-500 to-blue-600 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm font-medium">Total Attacks</p>
              <p className="text-3xl font-bold mt-2">{stats?.total_attacks.toLocaleString() || 0}</p>
            </div>
            <Shield className="h-12 w-12 text-blue-200" />
          </div>
        </div>

        <div className="card bg-gradient-to-br from-orange-500 to-orange-600 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-orange-100 text-sm font-medium">Last 24 Hours</p>
              <p className="text-3xl font-bold mt-2">{stats?.recent_24h.toLocaleString() || 0}</p>
            </div>
            <Activity className="h-12 w-12 text-orange-200" />
          </div>
        </div>

        <div className="card bg-gradient-to-br from-red-500 to-red-600 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-red-100 text-sm font-medium">Attack Types</p>
              <p className="text-3xl font-bold mt-2">{stats?.attack_types.length || 0}</p>
            </div>
            <AlertTriangle className="h-12 w-12 text-red-200" />
          </div>
        </div>

        <div className="card bg-gradient-to-br from-green-500 to-green-600 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-green-100 text-sm font-medium">Detection Rate</p>
              <p className="text-3xl font-bold mt-2">98.5%</p>
            </div>
            <TrendingUp className="h-12 w-12 text-green-200" />
          </div>
        </div>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Attack Timeline */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Attack Timeline (24h)</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} name="Attacks" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={(entry) => `${entry.name}: ${entry.value}`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {severityData.map((entry) => (
                  <Cell key={`cell-${entry.name}`} fill={COLORS[entry.name as keyof typeof COLORS]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Attack Types */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Attack Types</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={attackTypeData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
              <YAxis />
              <Tooltip />
              <Bar dataKey="count" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top Attacking IPs */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Attacking IPs</h3>
          <div className="space-y-3">
            {topIPsData.map((ip, index) => (
              <div key={ip.ip} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <span className="flex items-center justify-center w-8 h-8 rounded-full bg-gray-100 text-sm font-semibold text-gray-700">
                    {index + 1}
                  </span>
                  <span className="font-mono text-sm font-medium text-gray-900">{ip.ip}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-32 bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-red-600 h-2 rounded-full"
                      style={{ width: `${(ip.count / topIPsData[0].count) * 100}%` }}
                    ></div>
                  </div>
                  <span className="text-sm font-semibold text-gray-700 w-12 text-right">
                    {ip.count}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Attacks Table */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Recent Attacks</h3>
          <a href="/attacks" className="text-blue-600 hover:text-blue-700 text-sm font-medium">
            View All →
          </a>
        </div>
        <RecentAttacksTable />
      </div>
    </div>
  )
}

function RecentAttacksTable() {
  const { data, isLoading } = useQuery({
    queryKey: ['recent-attacks'],
    queryFn: () => apiService.getAttacks({ limit: 10 }),
    refetchInterval: 30000,
  })

  if (isLoading) {
    return <div className="text-center py-8 text-gray-500">Loading...</div>
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200">
        <thead>
          <tr>
            <th className="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Timestamp
            </th>
            <th className="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Source IP
            </th>
            <th className="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Attack Type
            </th>
            <th className="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Severity
            </th>
            <th className="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Confidence
            </th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {data?.attacks.map((attack) => (
            <tr key={attack.id} className="hover:bg-gray-50">
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                {format(new Date(attack.timestamp), 'MMM dd, HH:mm:ss')}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                {attack.source_ip}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                {attack.attack_type}
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <span className={`badge badge-${attack.severity.toLowerCase()}`}>
                  {attack.severity}
                </span>
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                {attack.confidence_score.toFixed(1)}%
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
