import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ScanSearch, Loader2, AlertTriangle, ShieldCheck } from 'lucide-react'
import { useApp } from '../context/AppContext'
import './Detection.css'

type ModelKey = 'rf' | 'svm' | 'ann' | 'cnn'

const MODEL_OPTIONS: { key: ModelKey; label: string; desc: string }[] = [
  { key: 'rf', label: 'Random Forest', desc: 'ML — ensemble tree classifier' },
  { key: 'svm', label: 'SVM', desc: 'ML — support vector machine' },
  { key: 'ann', label: 'ANN / MLP', desc: 'ML — artificial neural network' },
  { key: 'cnn', label: 'CNN (Deep)', desc: 'TL — convolutional neural network' },
]

export default function Detection() {
  const { addDetection } = useApp()
  const navigate = useNavigate()
  const [packetData, setPacketData] = useState('')
  const [modelType, setModelType] = useState<ModelKey>('rf')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<{
    prediction: 'malicious' | 'safe'
    confidence: number
    attackType?: string
  } | null>(null)
  const [error, setError] = useState<string | null>(null)

  const runDetection = async () => {
    if (!packetData.trim()) return

    setLoading(true)
    setResult(null)
    setError(null)

    try {
      const res = await fetch('http://localhost:5000/api/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packetData: packetData.trim(), modelType }),
      })

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }))
        throw new Error(err.error || `Server error: ${res.status}`)
      }

      const data = await res.json()
      const detectionResult = {
        prediction: data.prediction as 'malicious' | 'safe',
        confidence: data.confidence,
        attackType: data.attackType ?? undefined,
      }

      setResult(detectionResult)
      addDetection({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        input: {
          packetData: packetData.trim().slice(0, 200),
          modelUsed: modelType === 'cnn' ? 'tl' : 'ml',
        },
        output: {
          ...detectionResult,
          modelType: modelType === 'cnn' ? 'TL' : 'ML',
        },
      })
    } catch (err: any) {
      setError(err.message || 'Detection failed. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  const resetForm = () => {
    setPacketData('')
    setResult(null)
    setError(null)
    setModelType('rf')
  }


  return (
    <div className="detection-page">
      <header className="page-header">
        <h1>
          <ScanSearch className="page-icon" />
          Threat Detection
        </h1>
        <p>Analyze network traffic using ML or Transfer Learning models</p>
      </header>

      <div className="detection-layout">
        <div className="detection-card input-card">
          <h2>Input</h2>
          <div className="form-group">
            <label>Model Type</label>
            <div className="model-selector">
              {MODEL_OPTIONS.map((opt) => (
                <button
                  key={opt.key}
                  className={`model-btn ${modelType === opt.key ? 'active' : ''}`}
                  onClick={() => setModelType(opt.key)}
                  title={opt.desc}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
          <div className="form-group">
            <label>Packet / Traffic Data</label>
            <textarea
              value={packetData}
              onChange={(e) => setPacketData(e.target.value)}
              placeholder="Paste packet data, features (CSV), or network flow attributes..."
              rows={8}
              disabled={loading}
            />
          </div>
          {error && (
            <div className="error-banner">
              ⚠ {error}
            </div>
          )}
          <div className="form-actions">
            <button
              className="btn btn-primary"
              onClick={runDetection}
              disabled={loading || !packetData.trim()}
            >
              {loading ? (
                <>
                  <Loader2 className="spin" size={20} />
                  Analyzing...
                </>
              ) : (
                <>
                  <ScanSearch size={20} />
                  Run Detection
                </>
              )}
            </button>
            <button
              className="btn btn-ghost"
              onClick={resetForm}
              disabled={loading}
            >
              Reset
            </button>
          </div>
        </div>

        <div className="detection-card output-card">
          <h2>Result</h2>
          {result ? (
            <div
              className={`result-display ${result.prediction === 'malicious' ? 'malicious' : 'safe'
                }`}
            >
              <div className="result-icon">
                {result.prediction === 'malicious' ? (
                  <AlertTriangle size={48} />
                ) : (
                  <ShieldCheck size={48} />
                )}
              </div>
              <span className="result-label">
                {result.prediction === 'malicious' ? 'Malicious' : 'Safe'}
              </span>
              <div className="result-confidence">
                Confidence: {(result.confidence * 100).toFixed(1)}%
              </div>
              {result.attackType && result.attackType !== 'Unknown' && (
                <div className="result-attack-type">
                  Attack Type: <strong>{result.attackType}</strong>
                </div>
              )}
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => navigate('/dashboard')}
              >
                View Dashboard
              </button>
            </div>
          ) : (
            <div className="result-placeholder">
              {loading ? (
                <div className="loading-state">
                  <Loader2 className="spin" size={40} />
                  <p>Running {MODEL_OPTIONS.find(m => m.key === modelType)?.label} model...</p>
                  <span className="hint">Detecting known &amp; zero-day attacks</span>
                </div>
              ) : (
                <div className="empty-state">
                  <ScanSearch size={48} />
                  <p>Enter packet data and run detection</p>
                  <span className="hint">Results will appear here</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

