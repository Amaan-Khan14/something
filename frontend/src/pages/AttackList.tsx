import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { apiService } from '@/services/api'
import { Filter, Download, ExternalLink } from 'lucide-react'
import { format } from 'date-fns'

export default function AttackList() {
  const [filters, setFilters] = useState({
    attack_type: '',
    severity: '',
    source_ip: '',
    skip: 0,
    limit: 50,
  })

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['attacks', filters],
    queryFn: () => apiService.getAttacks(filters),
  })

  const handleExport = async (format: 'csv' | 'json') => {
    try {
      if (format === 'csv') {
        const blob = await apiService.exportCSV({
          attack_type: filters.attack_type || undefined,
          severity: filters.severity || undefined,
        })
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `attacks_${Date.now()}.csv`
        a.click()
      } else {
        const data = await apiService.exportJSON({
          attack_type: filters.attack_type || undefined,
          severity: filters.severity || undefined,
        })
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `attacks_${Date.now()}.json`
        a.click()
      }
    } catch (error) {
      console.error('Export failed:', error)
      alert('Export failed. Please try again.')
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-gray-900">Attack List</h2>
          <p className="text-gray-600 mt-1">Browse and filter detected attacks</p>
        </div>
        <div className="flex space-x-2">
          <button
            onClick={() => handleExport('csv')}
            className="btn-secondary flex items-center space-x-2"
          >
            <Download className="h-4 w-4" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={() => handleExport('json')}
            className="btn-secondary flex items-center space-x-2"
          >
            <Download className="h-4 w-4" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex items-center space-x-2 mb-4">
          <Filter className="h-5 w-5 text-gray-500" />
          <h3 className="text-lg font-semibold text-gray-900">Filters</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Attack Type
            </label>
            <select
              className="input"
              value={filters.attack_type}
              onChange={(e) => setFilters({ ...filters, attack_type: e.target.value, skip: 0 })}
            >
              <option value="">All Types</option>
              <option value="SQL Injection">SQL Injection</option>
              <option value="Cross-Site Scripting">XSS</option>
              <option value="Directory Traversal">Directory Traversal</option>
              <option value="Command Injection">Command Injection</option>
              <option value="Server-Side Request Forgery">SSRF</option>
              <option value="Local/Remote File Inclusion">LFI/RFI</option>
              <option value="XML External Entity Injection">XXE</option>
              <option value="Web Shell Upload">Web Shell</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Severity
            </label>
            <select
              className="input"
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value, skip: 0 })}
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Source IP
            </label>
            <input
              type="text"
              className="input"
              placeholder="192.168.1.1"
              value={filters.source_ip}
              onChange={(e) => setFilters({ ...filters, source_ip: e.target.value, skip: 0 })}
            />
          </div>
        </div>
      </div>

      {/* Results */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              {data?.total || 0} Attacks Found
            </h3>
            <p className="text-sm text-gray-600">
              Showing {filters.skip + 1} - {Math.min(filters.skip + filters.limit, data?.total || 0)}
            </p>
          </div>
        </div>

        {isLoading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead>
                  <tr>
                    <th className="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      ID
                    </th>
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
                    <th className="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Method
                    </th>
                    <th className="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {data?.attacks.map((attack) => (
                    <tr key={attack.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                        {attack.id}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {format(new Date(attack.timestamp), 'MMM dd, yyyy HH:mm:ss')}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                        {attack.source_ip}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-900">
                        <div>{attack.attack_type}</div>
                        {attack.attack_subtype && (
                          <div className="text-xs text-gray-500">{attack.attack_subtype}</div>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`badge badge-${attack.severity.toLowerCase()}`}>
                          {attack.severity}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {attack.confidence_score.toFixed(1)}%
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        <span className="px-2 py-1 bg-gray-100 rounded text-xs font-mono">
                          {attack.method}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        <Link
                          to={`/attacks/${attack.id}`}
                          className="text-blue-600 hover:text-blue-700 flex items-center space-x-1"
                        >
                          <span>View</span>
                          <ExternalLink className="h-3 w-3" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-between mt-6">
              <button
                onClick={() => setFilters({ ...filters, skip: Math.max(0, filters.skip - filters.limit) })}
                disabled={filters.skip === 0}
                className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <span className="text-sm text-gray-600">
                Page {Math.floor(filters.skip / filters.limit) + 1} of{' '}
                {Math.ceil((data?.total || 0) / filters.limit)}
              </span>
              <button
                onClick={() => setFilters({ ...filters, skip: filters.skip + filters.limit })}
                disabled={filters.skip + filters.limit >= (data?.total || 0)}
                className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
