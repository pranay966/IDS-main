import {
  BarChart3,
  PieChart as PieChartIcon,
  Activity,
  ShieldCheck,
  AlertTriangle,
  TrendingUp,
} from 'lucide-react'
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import { useApp } from '../context/AppContext'
import './Dashboard.css'

export default function Dashboard() {
  const { state } = useApp()
  const { dashboardStats, history } = state

  const pieData = [
    { name: 'Safe', value: dashboardStats.safeCount, color: '#10b981' },
    { name: 'Malicious', value: dashboardStats.maliciousCount, color: '#ef4444' },
  ].filter((d) => d.value > 0)

  const barData = (() => {
    const last7 = history.slice(0, 7).reverse()
    return last7.map((h, i) => ({
      name: `Scan ${i + 1}`,
      Malicious: h.output.prediction === 'malicious' ? 1 : 0,
      Safe: h.output.prediction === 'safe' ? 1 : 0,
    }))
  })()

  const mlCount = history.filter((h) => h.output.modelType === 'ML').length
  const tlCount = history.filter((h) => h.output.modelType === 'TL').length
  const modelData = [
    { name: 'ML', value: mlCount, color: '#ffffff' },
    { name: 'TL', value: tlCount, color: '#a3a3a3' },
  ].filter((d) => d.value > 0)

  const maliciousRate =
    dashboardStats.totalScans > 0
      ? ((dashboardStats.maliciousCount / dashboardStats.totalScans) * 100).toFixed(1)
      : '0'

  return (
    <div className="dashboard-page">
      <header className="page-header">
        <h1>
          <BarChart3 className="page-icon" />
          Analysis Dashboard
        </h1>
        <p>Malicious vs safe analysis based on detection outputs</p>
      </header>

      {dashboardStats.totalScans === 0 ? (
        <div className="dashboard-empty">
          <Activity size={64} />
          <h2>No Data Yet</h2>
          <p>
            Run some detections from the Detection page to see analysis here.
          </p>
        </div>
      ) : (
        <>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-icon total">
                <Activity size={24} />
              </div>
              <div className="stat-content">
                <span className="stat-value">{dashboardStats.totalScans}</span>
                <span className="stat-label">Total Scans</span>
              </div>
            </div>
            <div className="stat-card safe">
              <div className="stat-icon">
                <ShieldCheck size={24} />
              </div>
              <div className="stat-content">
                <span className="stat-value">{dashboardStats.safeCount}</span>
                <span className="stat-label">Safe</span>
              </div>
            </div>
            <div className="stat-card malicious">
              <div className="stat-icon">
                <AlertTriangle size={24} />
              </div>
              <div className="stat-content">
                <span className="stat-value">{dashboardStats.maliciousCount}</span>
                <span className="stat-label">Malicious</span>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon rate">
                <TrendingUp size={24} />
              </div>
              <div className="stat-content">
                <span className="stat-value">{maliciousRate}%</span>
                <span className="stat-label">Malicious Rate</span>
              </div>
            </div>
          </div>

          <div className="charts-grid">
            <div className="chart-card">
              <h3>
                <PieChartIcon size={20} />
                Malicious vs Safe
              </h3>
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      formatter={(value: number) => [`${value} scans`, 'Count']}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="chart-empty">No data</div>
              )}
            </div>

            <div className="chart-card">
              <h3>
                <BarChart3 size={20} />
                Recent Scans
              </h3>
              {barData.length > 0 ? (
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={barData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="name" stroke="#94a3b8" />
                    <YAxis stroke="#94a3b8" />
                    <Tooltip
                      contentStyle={{
                        background: '#1a2234',
                        border: '1px solid #334155',
                      }}
                    />
                    <Legend />
                    <Bar dataKey="Safe" fill="#10b981" radius={[4, 4, 0, 0]} />
                    <Bar
                      dataKey="Malicious"
                      fill="#ef4444"
                      radius={[4, 4, 0, 0]}
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="chart-empty">No data</div>
              )}
            </div>

            <div className="chart-card model-chart">
              <h3>Model Usage (ML vs TL)</h3>
              {modelData.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={modelData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {modelData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      formatter={(value: number) => [`${value} scans`, 'Count']}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="chart-empty">No data</div>
              )}
            </div>
          </div>

          <div className="dashboard-footer">
            <span className="last-updated">
              Last updated:{' '}
              {new Date(dashboardStats.lastUpdated).toLocaleString()}
            </span>
          </div>
        </>
      )}
    </div>
  )
}
