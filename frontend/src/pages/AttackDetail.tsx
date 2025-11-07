import { useQuery } from '@tanstack/react-query'
import { useParams, Link } from 'react-router-dom'
import { apiService } from '@/services/api'
import { ArrowLeft, Clock, Globe, Shield, AlertTriangle } from 'lucide-react'
import { format } from 'date-fns'

export default function AttackDetail() {
  const { id } = useParams<{ id: string }>()

  const { data: attack, isLoading } = useQuery({
    queryKey: ['attack', id],
    queryFn: () => apiService.getAttackDetail(Number(id)),
    enabled: !!id,
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!attack) {
    return (
      <div className="card text-center py-12">
        <AlertTriangle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-gray-900">Attack Not Found</h3>
        <p className="text-gray-600 mt-2">The requested attack could not be found.</p>
        <Link to="/attacks" className="btn-primary mt-4 inline-block">
          Back to Attack List
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Link to="/attacks" className="flex items-center space-x-2 text-blue-600 hover:text-blue-700 mb-4">
          <ArrowLeft className="h-4 w-4" />
          <span>Back to Attack List</span>
        </Link>
        <h2 className="text-3xl font-bold text-gray-900">Attack Details</h2>
        <p className="text-gray-600 mt-1">Attack ID: {attack.id}</p>
      </div>

      {/* Overview Card */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Overview</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div>
            <div className="flex items-center space-x-2 text-gray-500 mb-1">
              <Clock className="h-4 w-4" />
              <span className="text-sm font-medium">Timestamp</span>
            </div>
            <p className="text-gray-900 font-medium">
              {format(new Date(attack.timestamp), 'MMM dd, yyyy HH:mm:ss')}
            </p>
          </div>

          <div>
            <div className="flex items-center space-x-2 text-gray-500 mb-1">
              <Shield className="h-4 w-4" />
              <span className="text-sm font-medium">Attack Type</span>
            </div>
            <p className="text-gray-900 font-medium">{attack.attack_type}</p>
            {attack.attack_subtype && (
              <p className="text-sm text-gray-600">{attack.attack_subtype}</p>
            )}
          </div>

          <div>
            <div className="flex items-center space-x-2 text-gray-500 mb-1">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-sm font-medium">Severity</span>
            </div>
            <span className={`badge badge-${attack.severity.toLowerCase()} text-base`}>
              {attack.severity}
            </span>
          </div>

          <div>
            <div className="flex items-center space-x-2 text-gray-500 mb-1">
              <Globe className="h-4 w-4" />
              <span className="text-sm font-medium">Detection Method</span>
            </div>
            <p className="text-gray-900 font-medium capitalize">{attack.detection_method}</p>
          </div>
        </div>
      </div>

      {/* Network Information */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Network Information</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-500 mb-1">Source IP</label>
            <p className="text-gray-900 font-mono font-medium">{attack.source_ip}</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-500 mb-1">Destination IP</label>
            <p className="text-gray-900 font-mono font-medium">{attack.dest_ip}</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-500 mb-1">Destination Port</label>
            <p className="text-gray-900 font-mono font-medium">{attack.dest_port || 'N/A'}</p>
          </div>
        </div>
      </div>

      {/* HTTP Request Details */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">HTTP Request Details</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-500 mb-1">Method</label>
            <span className="px-3 py-1 bg-blue-100 text-blue-800 rounded font-mono text-sm font-medium">
              {attack.method}
            </span>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-500 mb-1">URL</label>
            <div className="bg-gray-50 p-3 rounded border border-gray-200 font-mono text-sm break-all">
              {attack.url}
            </div>
          </div>

          {attack.user_agent && (
            <div>
              <label className="block text-sm font-medium text-gray-500 mb-1">User Agent</label>
              <div className="bg-gray-50 p-3 rounded border border-gray-200 font-mono text-sm">
                {attack.user_agent}
              </div>
            </div>
          )}

          {attack.referer && (
            <div>
              <label className="block text-sm font-medium text-gray-500 mb-1">Referer</label>
              <div className="bg-gray-50 p-3 rounded border border-gray-200 font-mono text-sm">
                {attack.referer}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Detection Analysis */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Detection Analysis</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-500 mb-1">Confidence Score</label>
            <div className="flex items-center space-x-3">
              <div className="flex-1 bg-gray-200 rounded-full h-3">
                <div
                  className={`h-3 rounded-full ${
                    attack.confidence_score >= 90
                      ? 'bg-green-500'
                      : attack.confidence_score >= 70
                      ? 'bg-yellow-500'
                      : 'bg-red-500'
                  }`}
                  style={{ width: `${attack.confidence_score}%` }}
                ></div>
              </div>
              <span className="text-gray-900 font-semibold">{attack.confidence_score.toFixed(1)}%</span>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-500 mb-1">Success Status</label>
            <span className={`px-3 py-1 rounded font-medium ${
              attack.success_status
                ? 'bg-red-100 text-red-800'
                : 'bg-gray-100 text-gray-800'
            }`}>
              {attack.success_status ? 'Successful Attack' : 'Attack Attempt'}
            </span>
          </div>
        </div>
      </div>

      {/* Raw Request */}
      {attack.raw_request && (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Raw HTTP Request</h3>
          <div className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto">
            <pre className="text-sm font-mono whitespace-pre-wrap">{attack.raw_request}</pre>
          </div>
        </div>
      )}
    </div>
  )
}
