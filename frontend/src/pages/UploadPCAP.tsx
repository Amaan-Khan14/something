import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { useDropzone } from 'react-dropzone'
import { apiService } from '@/services/api'
import { Upload, FileText, CheckCircle, AlertCircle, XCircle } from 'lucide-react'

interface UploadResult {
  status: string
  total_requests: number
  attacks_detected: number
  message: string
}

export default function UploadPCAP() {
  const [result, setResult] = useState<UploadResult | null>(null)

  const uploadMutation = useMutation({
    mutationFn: (file: File) => apiService.uploadPCAP(file),
    onSuccess: (data) => {
      setResult(data)
    },
  })

  const { getRootProps, getInputProps, isDragActive, acceptedFiles } = useDropzone({
    accept: {
      'application/vnd.tcpdump.pcap': ['.pcap', '.pcapng', '.cap'],
    },
    maxFiles: 1,
    onDrop: (acceptedFiles) => {
      if (acceptedFiles.length > 0) {
        setResult(null)
        uploadMutation.mutate(acceptedFiles[0])
      }
    },
  })

  const handleReset = () => {
    setResult(null)
    uploadMutation.reset()
    acceptedFiles.splice(0, acceptedFiles.length)
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="text-center">
        <h2 className="text-3xl font-bold text-gray-900">Upload PCAP File</h2>
        <p className="text-gray-600 mt-2">
          Upload network traffic capture files for automated attack detection
        </p>
      </div>

      {/* Upload Zone */}
      {!uploadMutation.isPending && !result && (
        <div className="card">
          <div
            {...getRootProps()}
            className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors ${
              isDragActive
                ? 'border-blue-500 bg-blue-50'
                : 'border-gray-300 hover:border-gray-400'
            }`}
          >
            <input {...getInputProps()} />
            <Upload className="h-16 w-16 text-gray-400 mx-auto mb-4" />

            {isDragActive ? (
              <p className="text-lg text-blue-600 font-medium">Drop the PCAP file here...</p>
            ) : (
              <>
                <p className="text-lg text-gray-900 font-medium mb-2">
                  Drag & drop a PCAP file here, or click to select
                </p>
                <p className="text-sm text-gray-600">
                  Supports .pcap, .pcapng, and .cap files
                </p>
              </>
            )}
          </div>

          {acceptedFiles.length > 0 && !uploadMutation.isPending && (
            <div className="mt-4 p-4 bg-blue-50 rounded-lg flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <FileText className="h-5 w-5 text-blue-600" />
                <div>
                  <p className="text-sm font-medium text-gray-900">
                    {acceptedFiles[0].name}
                  </p>
                  <p className="text-xs text-gray-600">
                    {(acceptedFiles[0].size / 1024 / 1024).toFixed(2)} MB
                  </p>
                </div>
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  acceptedFiles.splice(0, acceptedFiles.length)
                }}
                className="text-red-600 hover:text-red-700"
              >
                <XCircle className="h-5 w-5" />
              </button>
            </div>
          )}

          {/* Info Box */}
          <div className="mt-6 p-4 bg-gray-50 rounded-lg">
            <h4 className="text-sm font-semibold text-gray-900 mb-2">
              About PCAP Analysis
            </h4>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• Extracts HTTP requests from network traffic</li>
              <li>• Analyzes URLs for 11+ attack types</li>
              <li>• Detects SQL Injection, XSS, Directory Traversal, and more</li>
              <li>• Stores detected attacks in the database for analysis</li>
              <li>• Supports large files with streaming processing</li>
            </ul>
          </div>
        </div>
      )}

      {/* Processing State */}
      {uploadMutation.isPending && (
        <div className="card">
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-16 w-16 border-b-4 border-blue-600 mx-auto mb-6"></div>
            <h3 className="text-xl font-semibold text-gray-900 mb-2">
              Processing PCAP File...
            </h3>
            <p className="text-gray-600">
              Parsing network traffic and detecting attacks
            </p>
            {acceptedFiles.length > 0 && (
              <p className="text-sm text-gray-500 mt-2">
                File: {acceptedFiles[0].name}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="card">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-semibold text-gray-900">Analysis Complete</h3>
            <button onClick={handleReset} className="btn-secondary text-sm">
              Upload Another File
            </button>
          </div>

          {/* Success Status */}
          <div className="bg-green-50 border-2 border-green-200 rounded-lg p-6 mb-6">
            <div className="flex items-center space-x-3">
              <CheckCircle className="h-8 w-8 text-green-600" />
              <div>
                <h4 className="text-xl font-bold text-green-900">
                  Processing Successful
                </h4>
                <p className="text-sm text-green-700">{result.message}</p>
              </div>
            </div>
          </div>

          {/* Statistics */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div className="bg-blue-50 rounded-lg p-6">
              <p className="text-sm font-medium text-blue-600 mb-2">Total Requests</p>
              <p className="text-3xl font-bold text-blue-900">
                {result.total_requests.toLocaleString()}
              </p>
            </div>

            <div className="bg-red-50 rounded-lg p-6">
              <p className="text-sm font-medium text-red-600 mb-2">Attacks Detected</p>
              <p className="text-3xl font-bold text-red-900">
                {result.attacks_detected.toLocaleString()}
              </p>
            </div>

            <div className="bg-green-50 rounded-lg p-6">
              <p className="text-sm font-medium text-green-600 mb-2">Detection Rate</p>
              <p className="text-3xl font-bold text-green-900">
                {result.total_requests > 0
                  ? ((result.attacks_detected / result.total_requests) * 100).toFixed(1)
                  : 0}
                %
              </p>
            </div>
          </div>

          {/* File Info */}
          {acceptedFiles.length > 0 && (
            <div className="bg-gray-50 rounded-lg p-4">
              <div className="flex items-center space-x-3">
                <FileText className="h-5 w-5 text-gray-600" />
                <div>
                  <p className="text-sm font-medium text-gray-900">
                    Processed File: {acceptedFiles[0].name}
                  </p>
                  <p className="text-xs text-gray-600">
                    Size: {(acceptedFiles[0].size / 1024 / 1024).toFixed(2)} MB
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Next Steps */}
          <div className="mt-6 p-4 bg-blue-50 border-l-4 border-blue-400 rounded">
            <h4 className="text-sm font-semibold text-blue-800 mb-2">Next Steps</h4>
            <ul className="text-sm text-blue-700 space-y-1">
              <li>
                • View detected attacks in the{' '}
                <a href="/attacks" className="underline font-medium">
                  Attack List
                </a>
              </li>
              <li>
                • Analyze attack patterns in the{' '}
                <a href="/" className="underline font-medium">
                  Dashboard
                </a>
              </li>
              <li>• Export results to CSV or JSON for further analysis</li>
              <li>• Review detailed attack information for each detection</li>
            </ul>
          </div>
        </div>
      )}

      {/* Error State */}
      {uploadMutation.isError && (
        <div className="card bg-red-50 border-2 border-red-200">
          <div className="flex items-start space-x-3">
            <AlertCircle className="h-6 w-6 text-red-600 mt-1" />
            <div>
              <h4 className="text-red-900 font-semibold mb-2">Upload Failed</h4>
              <p className="text-red-700 text-sm mb-4">
                {uploadMutation.error instanceof Error
                  ? uploadMutation.error.message
                  : 'An error occurred during file processing. Please try again.'}
              </p>
              <button onClick={handleReset} className="btn-secondary text-sm">
                Try Again
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
