import { NavLink } from 'react-router-dom'
import {
  Shield,
  ScanSearch,
  BarChart3,
  History,
  Home,
  Cpu,
  Radio,
} from 'lucide-react'
import './Layout.css'

interface LayoutProps {
  children: React.ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const navItems = [
    { to: '/', icon: Home, label: 'Home' },
    { to: '/detection', icon: ScanSearch, label: 'Detection' },
    { to: '/live', icon: Radio, label: 'Live Monitor' },
    { to: '/dashboard', icon: BarChart3, label: 'Dashboard' },
    { to: '/history', icon: History, label: 'History' },
  ]

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="logo">
            <Shield className="logo-icon" />
            <div>
              <span className="logo-text">IDS</span>
              <span className="logo-sub">Intrusion Detection</span>
            </div>
          </div>
          <div className="model-badge">
            <Cpu size={14} />
            ML & TL
          </div>
        </div>

        <nav className="sidebar-nav">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `nav-item ${isActive ? 'nav-item-active' : ''}`
              }
            >
              <Icon className="nav-icon" size={20} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="status-indicator">
            <span className="status-dot"></span>
            <span>System Online</span>
          </div>
        </div>
      </aside>

      <main className="main-content">{children}</main>
    </div>
  )
}
