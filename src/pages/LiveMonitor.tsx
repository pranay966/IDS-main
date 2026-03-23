import { useState, useEffect, useRef, useCallback } from 'react'
import {
    Radio,
    Square,
    Play,
    Activity,
    AlertTriangle,
    ShieldCheck,
    Wifi,
    Server,
    Layers,
    Loader2,
} from 'lucide-react'
import { useApp } from '../context/AppContext'
import './LiveMonitor.css'

type ModelKey = 'rf' | 'svm' | 'ann' | 'cnn'
type SimAttackKind = 'port_scan' | 'syn_flood'

interface PacketRow {
    id: number
    timestamp: number
    src_ip: string | null
    dst_ip: string | null
    protocol: string
    length: number
    flags: string
    src_port: number
    dst_port: number
}

interface Stats {
    total: number
    tcp: number
    udp: number
    icmp: number
    other: number
    pps: number // packets per second
}

interface DetectionResult {
    prediction: 'malicious' | 'safe'
    confidence: number
    attackType?: string
    packetCount?: number
    normalCount?: number
    suspiciousCount?: number
    maliciousCount?: number
    protocolCounts?: Record<string, number>
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

const MODEL_OPTIONS: { key: ModelKey; label: string }[] = [
    { key: 'rf', label: 'Random Forest' },
    { key: 'svm', label: 'SVM' },
    { key: 'ann', label: 'ANN / MLP' },
    { key: 'cnn', label: 'CNN (Deep)' },
]

const API = 'http://localhost:5000'
const MAX_ROWS = 80

export default function LiveMonitor() {
    const { addDetection } = useApp()
    const [interfaces, setInterfaces] = useState<{ id: string, label: string, guid?: string }[]>([])
    const [selectedIface, setSelectedIface] = useState<string>('')
    const [modelType, setModelType] = useState<ModelKey>('rf')
    const [capturing, setCapturing] = useState(false)
    const [packets, setPackets] = useState<PacketRow[]>([])
    const [stats, setStats] = useState<Stats>({ total: 0, tcp: 0, udp: 0, icmp: 0, other: 0, pps: 0 })
    const [result, setResult] = useState<DetectionResult | null>(null)
    const [analyzing, setAnalyzing] = useState(false)
    const [simulating, setSimulating] = useState(false)
    const [simAttackKind, setSimAttackKind] = useState<SimAttackKind>('port_scan')
    const [error, setError] = useState<string | null>(null)
    const [scapyAvailable, setScapyAvailable] = useState<boolean | null>(null)

    const eventSourceRef = useRef<EventSource | null>(null)
    const tableRef = useRef<HTMLDivElement>(null)
    const packetIdRef = useRef(0)
    const ppsTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)
    const ppsCountRef = useRef(0)
    const lastAutoAnalyzePacketsRef = useRef(0)

    // ------------------------------------------------------------------
    // Load interfaces on mount
    // ------------------------------------------------------------------
    useEffect(() => {
        fetch(`${API}/api/capture/interfaces`)
            .then(r => r.json())
            .then(data => {
                setInterfaces(data.interfaces || [])
                setScapyAvailable(data.scapy_available)
                if (data.interfaces?.length > 0) setSelectedIface(data.interfaces[0].id)
            })
            .catch(() => setScapyAvailable(false))
    }, [])

    // ------------------------------------------------------------------
    // SSE stream
    // ------------------------------------------------------------------
    const connectSSE = useCallback(() => {
        if (eventSourceRef.current) eventSourceRef.current.close()

        const es = new EventSource(`${API}/api/capture/stream`)
        eventSourceRef.current = es

        es.onmessage = (ev) => {
            try {
                const msg = JSON.parse(ev.data)
                if (msg.type === 'packet' && msg.data) {
                    const d = msg.data
                    const row: PacketRow = {
                        id: ++packetIdRef.current,
                        timestamp: d.timestamp,
                        src_ip: d.src_ip,
                        dst_ip: d.dst_ip,
                        protocol: d.protocol || 'OTHER',
                        length: d.length || 0,
                        flags: d.flags || '',
                        src_port: d.src_port || 0,
                        dst_port: d.dst_port || 0,
                    }

                    ppsCountRef.current++

                    setPackets(prev => {
                        const next = [...prev, row]
                        return next.length > MAX_ROWS ? next.slice(-MAX_ROWS) : next
                    })

                    setStats(prev => ({
                        ...prev,
                        total: prev.total + 1,
                        tcp: prev.tcp + (d.protocol === 'TCP' ? 1 : 0),
                        udp: prev.udp + (d.protocol === 'UDP' ? 1 : 0),
                        icmp: prev.icmp + (d.protocol === 'ICMP' ? 1 : 0),
                        other: prev.other + (d.protocol === 'OTHER' ? 1 : 0),
                    }))
                }
                if (msg.type === 'stopped') {
                    setCapturing(false)
                    es.close()
                }
            } catch { /* ignore parse errors */ }
        }

        es.onerror = () => {
            // SSE auto-reconnects; we silence the error unless capture was stopped
        }
    }, [])

    // PPS counter
    useEffect(() => {
        ppsTimerRef.current = setInterval(() => {
            setStats(prev => ({ ...prev, pps: ppsCountRef.current }))
            ppsCountRef.current = 0
        }, 1000)
        return () => {
            if (ppsTimerRef.current) clearInterval(ppsTimerRef.current)
        }
    }, [])

    // Auto-scroll table
    useEffect(() => {
        if (tableRef.current) {
            tableRef.current.scrollTop = tableRef.current.scrollHeight
        }
    }, [packets])

    // Cleanup SSE on unmount
    useEffect(() => {
        return () => {
            eventSourceRef.current?.close()
        }
    }, [])

    // ------------------------------------------------------------------
    // Start capture
    // ------------------------------------------------------------------
    const startCapture = async () => {
        setError(null)
        setResult(null)
        setPackets([])
        setStats({ total: 0, tcp: 0, udp: 0, icmp: 0, other: 0, pps: 0 })
        packetIdRef.current = 0

        try {
            const res = await fetch(`${API}/api/capture/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: selectedIface || null }),
            })
            const data = await res.json()
            if (!res.ok || data.error) {
                setError(data.error || 'Failed to start capture')
                return
            }
            setCapturing(true)
            connectSSE()
        } catch (e: any) {
            setError(e.message || 'Cannot connect to backend')
        }
    }

    // ------------------------------------------------------------------
    // Stop capture
    // ------------------------------------------------------------------
    const stopCapture = async () => {
        try {
            await fetch(`${API}/api/capture/stop`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: '{}',
            })
        } catch { /* ignore */ }
        eventSourceRef.current?.close()
        setCapturing(false)
    }

    // ------------------------------------------------------------------
    // Auto analyze (real-time style)
    // ------------------------------------------------------------------
    useEffect(() => {
        if (!capturing) return

        const timer = setInterval(() => {
            if (analyzing) return
            // Don't spam if nothing new arrived.
            if (packets.length <= lastAutoAnalyzePacketsRef.current) return
            if (packets.length < 10) return

            lastAutoAnalyzePacketsRef.current = packets.length
            analyze()
        }, 2500)

        return () => clearInterval(timer)
    }, [capturing, analyzing, packets.length, modelType])

    // ------------------------------------------------------------------
    // Analyze
    // ------------------------------------------------------------------
    const analyze = async () => {
        setAnalyzing(true)
        setError(null)
        try {
            const res = await fetch(`${API}/api/capture/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ modelType }),
            })
            const data = await res.json()
            if (!res.ok || data.error) {
                setError(data.error || 'Analysis failed')
                return
            }
            const det: DetectionResult = {
                prediction: data.prediction,
                confidence: data.confidence,
                attackType: data.attackType,
                packetCount: data.packetCount,
                normalCount: data.normalCount,
                suspiciousCount: data.suspiciousCount,
                maliciousCount: data.maliciousCount,
                protocolCounts: data.protocolCounts,
                perModel: data.perModel,
                threatTargets: data.threatTargets,
                decisionRule: data.decisionRule,
            }
            setResult(det)
            addDetection({
                id: crypto.randomUUID(),
                timestamp: new Date().toISOString(),
                input: { packetData: `Live capture — ${data.packetCount} packets`, modelUsed: modelType === 'cnn' ? 'tl' : 'ml' },
                output: { ...det, modelType: modelType === 'cnn' ? 'TL' : 'ML' },
            })
        } catch (e: any) {
            setError(e.message || 'Analysis failed')
        } finally {
            setAnalyzing(false)
        }
    }

    // ------------------------------------------------------------------
    // Simulate malicious traffic for testing (UI helper)
    // ------------------------------------------------------------------
    const simulateAttack = async () => {
        setError(null)
        setSimulating(true)
        try {
            const body =
                simAttackKind === 'syn_flood'
                    ? { kind: 'syn_flood', count: 160, port: 4444 }
                    : { kind: 'port_scan', count: 140 }

            const res = await fetch(`${API}/api/capture/simulate-attack`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            })
            const data = await res.json()
            if (!res.ok || data.error) {
                setError(data.error || 'Attack simulation failed')
                return
            }
            // Trigger immediate analysis after injecting dummy attack packets.
            analyze()
        } catch (e: any) {
            setError(e.message || 'Attack simulation failed')
        } finally {
            setSimulating(false)
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------
    const fmtTime = (ts: number) =>
        new Date(ts * 1000).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })

    const protoClass = (p: string) => {
        if (p === 'TCP') return 'proto-tcp'
        if (p === 'UDP') return 'proto-udp'
        if (p === 'ICMP') return 'proto-icmp'
        return 'proto-other'
    }

    const isSynFlood = packets.filter(p =>
        p.protocol === 'TCP' && p.flags.includes('S') && !p.flags.includes('A')
    ).length / (packets.length || 1)

    // ------------------------------------------------------------------
    return (
        <div className="lm-page">
            <header className="lm-header">
                <div className="lm-header-left">
                    <h1>
                        <Radio className="lm-header-icon" />
                        Live Monitor
                    </h1>
                    <p>Real-time packet capture &amp; AI-powered threat detection</p>
                </div>
                <div className={`lm-status-badge ${capturing ? 'lm-status-live' : 'lm-status-idle'}`}>
                    <span className="lm-pulse-dot" />
                    {capturing ? 'CAPTURING' : 'IDLE'}
                </div>
            </header>

            {/* ── Controls Bar ── */}
            <div className="lm-controls-bar">
                <div className="lm-control-group">
                    <label><Wifi size={14} /> Interface</label>
                    <select
                        value={selectedIface}
                        onChange={e => setSelectedIface(e.target.value)}
                        disabled={capturing}
                    >
                        {interfaces.length === 0
                            ? <option value="">Auto-detect</option>
                            : interfaces.map(ifc => <option key={ifc.id || ifc.guid} value={ifc.id}>{ifc.label}</option>)
                        }
                    </select>
                </div>

                <div className="lm-control-group">
                    <label><Layers size={14} /> Model</label>
                    <div className="lm-model-pills">
                        {MODEL_OPTIONS.map(opt => (
                            <button
                                key={opt.key}
                                className={`lm-pill ${modelType === opt.key ? 'active' : ''}`}
                                onClick={() => setModelType(opt.key)}
                            >
                                {opt.label}
                            </button>
                        ))}
                    </div>
                </div>

                <div className="lm-btn-group">
                    {!capturing ? (
                        <button className="lm-btn lm-btn-start" onClick={startCapture}>
                            <Play size={16} /> Start Capture
                        </button>
                    ) : (
                        <button className="lm-btn lm-btn-stop" onClick={stopCapture}>
                            <Square size={16} /> Stop
                        </button>
                    )}
                    <button
                        className="lm-btn lm-btn-analyze"
                        onClick={analyze}
                        disabled={analyzing || packets.length === 0}
                    >
                        {analyzing
                            ? <><Loader2 size={16} className="spin" /> Analyzing…</>
                            : <><Activity size={16} /> Analyze</>
                        }
                    </button>
                    <select
                        value={simAttackKind}
                        onChange={e => setSimAttackKind(e.target.value as SimAttackKind)}
                        disabled={!capturing || simulating}
                        style={{ minWidth: 130 }}
                    >
                        <option value="port_scan">Test: Port Scan</option>
                        <option value="syn_flood">Test: SYN Flood</option>
                    </select>
                    <button
                        className="lm-btn"
                        onClick={simulateAttack}
                        disabled={!capturing || simulating}
                        style={{ borderColor: 'var(--danger)', color: 'var(--danger)' }}
                    >
                        {simulating ? <><Loader2 size={16} className="spin" /> Injecting…</> : <><AlertTriangle size={16} /> Test Attack</>}
                    </button>
                </div>
            </div>

            {scapyAvailable === false && (
                <div className="lm-warning-banner">
                    ⚠ <strong>scapy not installed</strong> — run <code>pip install scapy</code> in your backend venv,
                    and install <a href="https://npcap.com/" target="_blank" rel="noreferrer">Npcap</a> for Windows packet capture.
                    The backend must also run <strong>as Administrator</strong>.
                </div>
            )}

            {error && <div className="lm-error-banner">⚠ {error}</div>}

            {/* ── Main Grid ── */}
            <div className="lm-grid">

                {/* ── Stats Cards ── */}
                <div className="lm-stats-row">
                    <div className="lm-stat-card">
                        <span className="lm-stat-label">Total Packets</span>
                        <span className="lm-stat-value">{stats.total.toLocaleString()}</span>
                    </div>
                    <div className="lm-stat-card proto-tcp">
                        <span className="lm-stat-label">TCP</span>
                        <span className="lm-stat-value">{stats.tcp}</span>
                    </div>
                    <div className="lm-stat-card proto-udp">
                        <span className="lm-stat-label">UDP</span>
                        <span className="lm-stat-value">{stats.udp}</span>
                    </div>
                    <div className="lm-stat-card proto-icmp">
                        <span className="lm-stat-label">ICMP</span>
                        <span className="lm-stat-value">{stats.icmp}</span>
                    </div>
                    <div className="lm-stat-card">
                        <span className="lm-stat-label">Pkts/sec</span>
                        <span className="lm-stat-value">{stats.pps}</span>
                    </div>
                    {isSynFlood > 0.4 && (
                        <div className="lm-stat-card lm-stat-threat">
                            <span className="lm-stat-label">⚠ SYN Ratio</span>
                            <span className="lm-stat-value">{(isSynFlood * 100).toFixed(0)}%</span>
                        </div>
                    )}
                </div>

                {/* ── Packet Feed Table ── */}
                <div className="lm-panel lm-feed-panel">
                    <div className="lm-panel-header">
                        <Server size={16} /> Live Packet Feed
                        <span className="lm-count-badge">{packets.length}</span>
                    </div>
                    <div className="lm-table-wrap" ref={tableRef}>
                        {packets.length === 0 ? (
                            <div className="lm-empty">
                                {capturing
                                    ? <><Loader2 size={32} className="spin lm-empty-icon" /><p>Waiting for packets…</p></>
                                    : <><Radio size={32} className="lm-empty-icon" /><p>Start capture to see live packets</p></>
                                }
                            </div>
                        ) : (
                            <table className="lm-table">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Proto</th>
                                        <th>Src IP:Port</th>
                                        <th>Dst IP:Port</th>
                                        <th>Len</th>
                                        <th>Flags</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {packets.map(p => (
                                        <tr key={p.id}>
                                            <td className="lm-mono">{fmtTime(p.timestamp)}</td>
                                            <td><span className={`lm-proto-badge ${protoClass(p.protocol)}`}>{p.protocol}</span></td>
                                            <td className="lm-mono lm-ip">{p.src_ip ?? '—'}:{p.src_port || '—'}</td>
                                            <td className="lm-mono lm-ip">{p.dst_ip ?? '—'}:{p.dst_port || '—'}</td>
                                            <td className="lm-mono">{p.length}</td>
                                            <td className="lm-mono lm-flags">{p.flags || '—'}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        )}
                    </div>
                </div>

                {/* ── Detection Result Panel ── */}
                <div className="lm-panel lm-result-panel">
                    <div className="lm-panel-header">
                        <Activity size={16} /> Detection Result
                    </div>

                    {result ? (
                        <div className={`lm-result-display ${result.prediction}`}>
                            <div className="lm-result-icon">
                                {result.prediction === 'malicious'
                                    ? <AlertTriangle size={52} />
                                    : <ShieldCheck size={52} />
                                }
                            </div>
                            <div className={`lm-result-label ${result.prediction}`}>
                                {result.prediction === 'malicious' ? 'THREAT DETECTED' : 'NORMAL TRAFFIC'}
                            </div>

                            <div className="lm-confidence-wrap">
                                <div className="lm-confidence-label">
                                    Confidence: <strong>{(result.confidence * 100).toFixed(1)}%</strong>
                                </div>
                                <div className="lm-confidence-bar-bg">
                                    <div
                                        className={`lm-confidence-bar ${result.prediction}`}
                                        style={{ width: `${(result.confidence * 100).toFixed(1)}%` }}
                                    />
                                </div>
                            </div>

                            {result.attackType && result.attackType !== 'Unknown' && (
                                <div className="lm-attack-type">
                                    Attack Type: <strong>{result.attackType}</strong>
                                </div>
                            )}

                            {result.prediction === 'malicious' && result.threatTargets?.topDstIpPorts?.length ? (
                                <div className="lm-attack-type" style={{ marginTop: '0.75rem' }}>
                                    Malicious Targets:{' '}
                                    <strong>
                                        {result.threatTargets.topDstIpPorts.slice(0, 3).map(t => t.value).join(', ')}
                                    </strong>
                                </div>
                            ) : null}

                            {result.prediction === 'malicious' && result.threatTargets?.topDomains?.length ? (
                                <div className="lm-attack-type" style={{ marginTop: '0.5rem' }}>
                                    Malicious Domains:{' '}
                                    <strong>
                                        {result.threatTargets.topDomains.slice(0, 3).map(t => t.value).join(', ')}
                                    </strong>
                                </div>
                            ) : null}

                            {result.perModel ? (
                                <div className="lm-result-meta" style={{ marginTop: '0.75rem' }}>
                                    <span>RF: <strong>{result.perModel.rf?.prediction ?? '—'}</strong> ({((result.perModel.rf?.confidence ?? 0) * 100).toFixed(1)}%)</span>
                                    <span>SVM: <strong>{result.perModel.svm?.prediction ?? '—'}</strong> ({((result.perModel.svm?.confidence ?? 0) * 100).toFixed(1)}%)</span>
                                    <span>ANN: <strong>{result.perModel.ann?.prediction ?? '—'}</strong> ({((result.perModel.ann?.confidence ?? 0) * 100).toFixed(1)}%)</span>
                                    <span>TL: <strong>{result.perModel.tl?.prediction ?? '—'}</strong> ({((result.perModel.tl?.confidence ?? 0) * 100).toFixed(1)}%)</span>
                                </div>
                            ) : null}

                            <div className="lm-result-meta">
                                <span>Total Packets: <strong>{result.packetCount ?? '—'}</strong></span>
                                <span>Normal (Safe): <strong style={{ color: 'var(--accent)' }}>{result.normalCount ?? '—'}</strong></span>
                                <span>Suspicious (Tested): <strong style={{ color: 'var(--warning)' }}>{result.suspiciousCount ?? '—'}</strong></span>
                                <span>Malicious Found: <strong style={{ color: 'var(--danger)' }}>{result.maliciousCount ?? '—'}</strong></span>
                                <span style={{ width: '100%', marginTop: '0.5rem' }}>Model: <strong>{MODEL_OPTIONS.find(m => m.key === modelType)?.label}</strong></span>
                                {result.decisionRule ? (
                                    <span style={{ width: '100%', marginTop: '0.35rem', opacity: 0.9 }}>
                                        Rule: <strong>{result.decisionRule}</strong>
                                    </span>
                                ) : null}
                            </div>

                            {result.protocolCounts && (
                                <div className="lm-proto-summary">
                                    {Object.entries(result.protocolCounts).map(([k, v]) =>
                                        v > 0 ? (
                                            <span key={k} className={`lm-proto-badge ${protoClass(k)}`}>
                                                {k}: {v}
                                            </span>
                                        ) : null
                                    )}
                                </div>
                            )}
                        </div>
                    ) : (
                        <div className="lm-result-empty">
                            {analyzing ? (
                                <><Loader2 size={40} className="spin lm-empty-icon" /><p>Running {MODEL_OPTIONS.find(m => m.key === modelType)?.label}…</p></>
                            ) : (
                                <>
                                    <Activity size={40} className="lm-empty-icon" />
                                    <p>Capture packets, then click <strong>Analyze</strong></p>
                                    <span className="lm-hint">ML model will classify the traffic</span>
                                </>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    )
}
