import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Detection from './pages/Detection'
import Dashboard from './pages/Dashboard'
import History from './pages/History'
import Home from './pages/Home'
import LiveMonitor from './pages/LiveMonitor'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/detection" element={<Detection />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/history" element={<History />} />
        <Route path="/live" element={<LiveMonitor />} />
      </Routes>
    </Layout>
  )
}

export default App
