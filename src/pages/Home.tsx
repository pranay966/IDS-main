import { Link } from 'react-router-dom'
import { Shield, ScanSearch, BarChart3, History, ArrowRight } from 'lucide-react'
import './Home.css'

export default function Home() {
  return (
    <div className="home-page">
      <section className="hero">
        <div className="hero-badge">ML & Transfer Learning Powered</div>
        <h1 className="hero-title">
          Intelligent Intrusion
          <br />
          <span className="gradient-text">Detection System</span>
        </h1>
        <p className="hero-description">
          Detect both known and zero-day cyber attacks in real-time using
          advanced Machine Learning and Transfer Learning approaches. Classify
          network traffic as malicious or safe with high accuracy.
        </p>
        <div className="hero-actions">
          <Link to="/detection" className="btn btn-primary">
            <ScanSearch size={20} />
            Start Detection
          </Link>
          <Link to="/dashboard" className="btn btn-secondary">
            <BarChart3 size={20} />
            View Dashboard
          </Link>
        </div>
      </section>

      <section className="features">
        <h2 className="section-title">Key Capabilities</h2>
        <div className="feature-grid">
          <div className="feature-card">
            <Shield className="feature-icon" />
            <h3>Known Attack Detection</h3>
            <p>Identify signatures of known attack patterns using trained ML models.</p>
          </div>
          <div className="feature-card">
            <ScanSearch className="feature-icon" />
            <h3>Zero-Day Detection</h3>
            <p>Detect novel attacks through Transfer Learning on unseen attack variants.</p>
          </div>
          <div className="feature-card">
            <BarChart3 className="feature-icon" />
            <h3>Real-time Analysis</h3>
            <p>Get instant malicious vs safe classification with confidence scores.</p>
          </div>
          <div className="feature-card">
            <History className="feature-icon" />
            <h3>Detection History</h3>
            <p>Track all scans with full input/output details for forensic analysis.</p>
          </div>
        </div>
      </section>

      <section className="cta-section">
        <div className="cta-card">
          <p>Ready to analyze your network traffic?</p>
          <Link to="/detection" className="btn btn-cta">
            Run Detection <ArrowRight size={18} />
          </Link>
        </div>
      </section>
    </div>
  )
}
