import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { apiService, DetectionResult } from '@/services/api'
import { Search, AlertCircle, CheckCircle, Shield } from 'lucide-react'

export default function AnalyzeURL() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState<DetectionResult | null>(null)

  const analyzeMutation = useMutation({
    mutationFn: (url: string) => apiService.analyzeURL(url),
    onSuccess: (data) => {
      setResult(data)
    },
  })

  const handleAnalyze = (e: React.FormEvent) => {
    e.preventDefault()
    if (url.trim()) {
      setResult(null)
      analyzeMutation.mutate(url.trim())
    }
  }

  const handleReset = () => {
    setUrl('')
    setResult(null)
    analyzeMutation.reset()
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="text-center">
        <h2 className="text-3xl font-bold text-gray-900">URL Analysis</h2>
        <p className="text-gray-600 mt-2">
          Analyze URLs in real-time using our hybrid detection engine
        </p>
      </div>

      {/* Input Form */}
      <div className="card">
        <form onSubmit={handleAnalyze} className="space-y-4">
          <div>
            <label htmlFor="url" className="block text-sm font-medium text-gray-700 mb-2">
              Enter URL to Analyze
            </label>
            <div className="flex space-x-2">
              <input
                id="url"
                type="text"
                className="input flex-1"
                placeholder="https://example.com/page?param=value"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={analyzeMutation.isPending}
              />
              <button
                type="submit"
                className="btn-primary flex items-center space-x-2 whitespace-nowrap"
                disabled={analyzeMutation.isPending || !url.trim()}
              >
                {analyzeMutation.isPending ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4" />
                    <span>Analyze</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Examples */}
          <div className="bg-gray-50 p-4 rounded-lg">
            <p className="text-sm font-medium text-gray-700 mb-2">Try these examples:</p>
            <div className="space-y-1">
              <button
                type="button"
                onClick={() => setUrl("http://example.com/login?user=admin' OR '1'='1")}
                className="block text-sm text-blue-600 hover:text-blue-700"
              >
                SQL Injection: http://example.com/login?user=admin' OR '1'='1
              </button>
              <button
                type="button"
                onClick={() => setUrl('http://example.com/search?q=<script>alert(1)</script>')}
                className="block text-sm text-blue-600 hover:text-blue-700"
              >
                XSS: http://example.com/search?q=&lt;script&gt;alert(1)&lt;/script&gt;
              </button>
              <button
                type="button"
                onClick={() => setUrl('http://example.com/file?path=../../../etc/passwd')}
                className="block text-sm text-blue-600 hover:text-blue-700"
              >
                Path Traversal: http://example.com/file?path=../../../etc/passwd
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Results */}
      {result && (
        <div className="card">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-semibold text-gray-900">Analysis Results</h3>
            <button onClick={handleReset} className="btn-secondary text-sm">
              Analyze Another URL
            </button>
          </div>

          {/* Detection Status */}
          <div className={`p-6 rounded-lg mb-6 ${
            result.is_attack
              ? 'bg-red-50 border-2 border-red-200'
              : 'bg-green-50 border-2 border-green-200'
          }`}>
            <div className="flex items-center space-x-3">
              {result.is_attack ? (
                <AlertCircle className="h-8 w-8 text-red-600" />
              ) : (
                <CheckCircle className="h-8 w-8 text-green-600" />
              )}
              <div>
                <h4 className={`text-xl font-bold ${
                  result.is_attack ? 'text-red-900' : 'text-green-900'
                }`}>
                  {result.is_attack ? 'Attack Detected!' : 'URL is Safe'}
                </h4>
                <p className={`text-sm ${
                  result.is_attack ? 'text-red-700' : 'text-green-700'
                }`}>
                  {result.is_attack
                    ? 'This URL contains malicious patterns'
                    : 'No threats detected in this URL'}
                </p>
              </div>
            </div>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            {result.is_attack && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-500 mb-1">
                    Attack Type
                  </label>
                  <div className="flex items-center space-x-2">
                    <Shield className="h-5 w-5 text-red-600" />
                    <p className="text-gray-900 font-semibold text-lg">
                      {result.attack_type}
                    </p>
                  </div>
                  {result.attack_subtype && (
                    <p className="text-sm text-gray-600 ml-7 mt-1">
                      Subtype: {result.attack_subtype}
                    </p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-500 mb-1">
                    Severity Level
                  </label>
                  <span className={`badge badge-${result.severity.toLowerCase()} text-lg px-4 py-2`}>
                    {result.severity}
                  </span>
                </div>
              </>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-500 mb-1">
                Confidence Score
              </label>
              <div className="flex items-center space-x-3">
                <div className="flex-1 bg-gray-200 rounded-full h-3">
                  <div
                    className={`h-3 rounded-full ${
                      result.confidence_score >= 90
                        ? result.is_attack ? 'bg-red-500' : 'bg-green-500'
                        : result.confidence_score >= 70
                        ? 'bg-yellow-500'
                        : 'bg-orange-500'
                    }`}
                    style={{ width: `${result.confidence_score}%` }}
                  ></div>
                </div>
                <span className="text-gray-900 font-bold text-lg">
                  {result.confidence_score.toFixed(1)}%
                </span>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-500 mb-1">
                Detection Method
              </label>
              <p className="text-gray-900 font-medium text-lg capitalize">
                {result.detection_method}
              </p>
            </div>
          </div>

          {/* Matched Patterns */}
          {result.matched_patterns && result.matched_patterns.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-gray-500 mb-2">
                Matched Attack Patterns
              </label>
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                <ul className="space-y-2">
                  {result.matched_patterns.map((pattern, index) => (
                    <li key={index} className="flex items-start space-x-2">
                      <span className="text-red-600 font-bold">•</span>
                      <code className="text-sm font-mono text-gray-800 break-all">
                        {pattern}
                      </code>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {/* Analyzed URL */}
          <div className="mt-6">
            <label className="block text-sm font-medium text-gray-500 mb-2">
              Analyzed URL
            </label>
            <div className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto">
              <code className="text-sm font-mono break-all">{url}</code>
            </div>
          </div>

          {/* Recommendations */}
          {result.is_attack && (
            <div className="mt-6 p-4 bg-yellow-50 border-l-4 border-yellow-400 rounded">
              <h4 className="text-sm font-semibold text-yellow-800 mb-2">
                Security Recommendations
              </h4>
              <ul className="text-sm text-yellow-700 space-y-1">
                <li>• Block requests from the source IP address</li>
                <li>• Review and strengthen input validation</li>
                <li>• Check application logs for similar patterns</li>
                <li>• Consider implementing a Web Application Firewall (WAF)</li>
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Error State */}
      {analyzeMutation.isError && (
        <div className="card bg-red-50 border-2 border-red-200">
          <div className="flex items-center space-x-3">
            <AlertCircle className="h-6 w-6 text-red-600" />
            <div>
              <h4 className="text-red-900 font-semibold">Analysis Failed</h4>
              <p className="text-red-700 text-sm">
                {analyzeMutation.error instanceof Error
                  ? analyzeMutation.error.message
                  : 'An error occurred during analysis. Please try again.'}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
