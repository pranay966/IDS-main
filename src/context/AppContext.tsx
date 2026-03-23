import React, { createContext, useContext, useReducer, ReactNode } from 'react'

export interface DetectionResult {
  id: string
  timestamp: string
  input: {
    packetData: string
    features?: Record<string, number>
    modelUsed: 'ml' | 'tl'
  }
  output: {
    prediction: 'malicious' | 'safe'
    confidence: number
    attackType?: string
    modelType: 'ML' | 'TL'
    perModel?: Record<string, { prediction: 'malicious' | 'safe'; confidence: number; attackType?: string }>
    threatTargets?: {
      topDstIps?: Array<{ value: string; count: number }>
      topSrcIps?: Array<{ value: string; count: number }>
      topDstPorts?: Array<{ value: number; count: number }>
      topDstIpPorts?: Array<{ value: string; count: number }>
      topDomains?: Array<{ value: string; count: number }>
    }
    decisionRule?: string
  }
}

interface AppState {
  history: DetectionResult[]
  dashboardStats: {
    totalScans: number
    maliciousCount: number
    safeCount: number
    lastUpdated: string
  }
}

type AppAction =
  | { type: 'ADD_DETECTION'; payload: DetectionResult }
  | { type: 'CLEAR_HISTORY' }

const STORAGE_KEY = 'ids-history'

function loadInitialState(): AppState {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) {
      const parsed = JSON.parse(stored) as DetectionResult[]
      const history = parsed.slice(0, 100)
      const maliciousCount = history.filter((h) => h.output.prediction === 'malicious').length
      const safeCount = history.filter((h) => h.output.prediction === 'safe').length
      return {
        history,
        dashboardStats: {
          totalScans: history.length,
          maliciousCount,
          safeCount,
          lastUpdated: new Date().toISOString(),
        },
      }
    }
  } catch (_) {}
  return {
    history: [],
    dashboardStats: {
      totalScans: 0,
      maliciousCount: 0,
      safeCount: 0,
      lastUpdated: new Date().toISOString(),
    },
  }
}

const initialState = loadInitialState()

function appReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case 'ADD_DETECTION': {
      const newHistory = [action.payload, ...state.history].slice(0, 100)
      const maliciousCount = newHistory.filter(
        (h) => h.output.prediction === 'malicious'
      ).length
      const safeCount = newHistory.filter(
        (h) => h.output.prediction === 'safe'
      ).length
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(newHistory))
      } catch (_) {}
      return {
        ...state,
        history: newHistory,
        dashboardStats: {
          totalScans: newHistory.length,
          maliciousCount,
          safeCount,
          lastUpdated: new Date().toISOString(),
        },
      }
    }
    case 'CLEAR_HISTORY': {
      try {
        localStorage.removeItem(STORAGE_KEY)
      } catch (_) {}
      return {
        history: [],
        dashboardStats: {
          totalScans: 0,
          maliciousCount: 0,
          safeCount: 0,
          lastUpdated: new Date().toISOString(),
        },
      }
    }
    default:
      return state
  }
}

interface AppContextType {
  state: AppState
  addDetection: (result: DetectionResult) => void
  clearHistory: () => void
}

const AppContext = createContext<AppContextType | null>(null)

export function AppProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(appReducer, initialState)

  const addDetection = (result: DetectionResult) => {
    dispatch({ type: 'ADD_DETECTION', payload: result })
  }

  const clearHistory = () => {
    dispatch({ type: 'CLEAR_HISTORY' })
  }

  return (
    <AppContext.Provider value={{ state, addDetection, clearHistory }}>
      {children}
    </AppContext.Provider>
  )
}

export function useApp() {
  const context = useContext(AppContext)
  if (!context) {
    throw new Error('useApp must be used within AppProvider')
  }
  return context
}
