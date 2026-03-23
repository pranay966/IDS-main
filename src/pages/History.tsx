import { useState } from 'react'
import {
  History as HistoryIcon,
  Trash2,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
  AlertTriangle,
  Search,
} from 'lucide-react'
import { useApp } from '../context/AppContext'
import './History.css'

export default function History() {
  const { state, clearHistory } = useApp()
  const { history } = state
  const [searchFilter, setSearchFilter] = useState('')
  const [filterType, setFilterType] = useState<'all' | 'malicious' | 'safe'>('all')
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const filteredHistory = history.filter((item) => {
    const matchesSearch =
      item.input.packetData.toLowerCase().includes(searchFilter.toLowerCase()) ||
      item.output.attackType?.toLowerCase().includes(searchFilter.toLowerCase())
    const matchesFilter =
      filterType === 'all' ||
      (filterType === 'malicious' && item.output.prediction === 'malicious') ||
      (filterType === 'safe' && item.output.prediction === 'safe')
    return matchesSearch && matchesFilter
  })

  const formatDate = (iso: string) => {
    const d = new Date(iso)
    return d.toLocaleString()
  }

  return (
    <div className="history-page">
      <header className="page-header history-header">
        <div>
          <h1>
            <HistoryIcon className="page-icon" />
            Detection History
          </h1>
          <p>Input and output details for all past detections</p>
        </div>
        {history.length > 0 && (
          <button className="btn btn-ghost btn-danger" onClick={clearHistory}>
            <Trash2 size={18} />
            Clear History
          </button>
        )}
      </header>

      {history.length > 0 ? (
        <>
          <div className="history-filters">
            <div className="search-box">
              <Search size={18} />
              <input
                type="text"
                placeholder="Search by packet data or attack type..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
              />
            </div>
            <div className="filter-buttons">
              <button
                className={`filter-btn ${filterType === 'all' ? 'active' : ''}`}
                onClick={() => setFilterType('all')}
              >
                All
              </button>
              <button
                className={`filter-btn ${filterType === 'malicious' ? 'active' : ''}`}
                onClick={() => setFilterType('malicious')}
              >
                Malicious
              </button>
              <button
                className={`filter-btn ${filterType === 'safe' ? 'active' : ''}`}
                onClick={() => setFilterType('safe')}
              >
                Safe
              </button>
            </div>
          </div>

          <div className="history-list">
            {filteredHistory.length > 0 ? (
              filteredHistory.map((item) => (
                <div
                  key={item.id}
                  className={`history-item ${item.output.prediction} ${
                    expandedId === item.id ? 'expanded' : ''
                  }`}
                >
                  <div
                    className="history-item-header"
                    onClick={() =>
                      setExpandedId(expandedId === item.id ? null : item.id)
                    }
                  >
                    <div className="history-item-main">
                      <span
                        className={`prediction-badge ${
                          item.output.prediction
                        }`}
                      >
                        {item.output.prediction === 'malicious' ? (
                          <AlertTriangle size={14} />
                        ) : (
                          <ShieldCheck size={14} />
                        )}
                        {item.output.prediction}
                      </span>
                      <span className="model-tag">{item.output.modelType}</span>
                      <span className="confidence">
                        {(item.output.confidence * 100).toFixed(1)}% conf
                      </span>
                      {item.output.attackType &&
                        item.output.attackType !== 'Unknown' && (
                          <span className="attack-type">
                            {item.output.attackType}
                          </span>
                        )}
                    </div>
                    <div className="history-item-meta">
                      <span className="timestamp">
                        {formatDate(item.timestamp)}
                      </span>
                      {expandedId === item.id ? (
                        <ChevronUp size={18} />
                      ) : (
                        <ChevronDown size={18} />
                      )}
                    </div>
                  </div>

                  {expandedId === item.id && (
                    <div className="history-item-details">
                      <div className="detail-section">
                        <h4>Input</h4>
                        <pre className="packet-data">
                          {item.input.packetData ||
                            'No packet data (features only)'}
                        </pre>
                        <span className="model-used">
                          Model: {item.output.modelType}
                        </span>
                      </div>
                      <div className="detail-section">
                        <h4>Output</h4>
                        <div className="output-details">
                          <span>Prediction: {item.output.prediction}</span>
                          <span>
                            Confidence:{(item.output.confidence * 100).toFixed(1)}
                            %
                          </span>
                          {item.output.attackType && (
                            <span>
                              Attack Type: {item.output.attackType}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div className="history-empty-filter">
                <p>No results match your search</p>
              </div>
            )}
          </div>
        </>
      ) : (
        <div className="history-empty">
          <HistoryIcon size={64} />
          <h2>No History Yet</h2>
          <p>Run detections from the Detection page to see history here.</p>
        </div>
      )}
    </div>
  )
}
