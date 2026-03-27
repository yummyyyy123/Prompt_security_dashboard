'use client'

import { useState, useEffect } from 'react'
import {
    Shield,
    AlertTriangle,
    Info,
    Lock,
    RefreshCw,
    Filter,
    Clock,
    User,
    Globe,
    Activity,
    Github,
    X,
    Copy
} from 'lucide-react'

import GitHubSecurityDashboard from '@/components/GitHubSecurityDashboard'

// Force dynamic rendering to prevent build-time prerender errors with env vars
export const dynamic = 'force-dynamic'

interface SecurityLog {
    id: string
    event_type: string
    severity: 'info' | 'warning' | 'critical'
    ip_address: string
    user_agent: string
    details: any
    created_at: string
}

export default function SecurityDashboard() {
    const [logs, setLogs] = useState<SecurityLog[]>([])
    const [loading, setLoading] = useState(true)
    const [refreshing, setRefreshing] = useState(false)
    const [filter, setFilter] = useState('threats')
    const [activeTab, setActiveTab] = useState<'monitoring' | 'github'>('monitoring')
    const [selectedLog, setSelectedLog] = useState<SecurityLog | null>(null)
    const [showPayloadModal, setShowPayloadModal] = useState(false)
    const [lastUpdate, setLastUpdate] = useState<Date>(new Date())
    const [blockedIPs, setBlockedIPs] = useState<any[]>([])
    const [blockingIP, setBlockingIP] = useState<string | null>(null)

    const fetchBlockedIPs = async () => {
        try {
            const response = await fetch('/api/admin/security/block-ip')
            const data = await response.json()
            if (data.blocked_ips) {
                setBlockedIPs(data.blocked_ips)
            }
        } catch (error) {
            console.error('Failed to fetch blocked IPs:', error)
        }
    }

    const handleBlockIP = async (threatIP: string) => {
        setBlockingIP(threatIP)
        try {
            const response = await fetch('/api/admin/security/block-ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: threatIP })
            })
            
            if (response.ok) {
                const result = await response.json()
                console.log('✅ IP blocked:', result.message)
                // Refresh blocked IPs list
                await fetchBlockedIPs()
                // Refresh logs to show updated status
                await fetchLogs(false)
                // Show success message
                alert(`IP ${threatIP} blocked for 1 day`)
            } else {
                const error = await response.json()
                alert(`Failed to block IP: ${error.error}`)
            }
        } catch (error) {
            console.error('Failed to block IP:', error)
            alert('Failed to block IP')
        } finally {
            setBlockingIP(null)
        }
    }

    const fetchLogs = async (isRefresh = false) => {
        if (!isRefresh) {
            setLoading(true)
        } else {
            setRefreshing(true)
        }
        
        try {
            const response = await fetch(`/api/admin/security/logs?filter=${filter}&limit=100&t=${Date.now()}`, { // Increased limit to 100
                cache: 'no-store',
                headers: { 'Cache-Control': 'no-cache' }
            })
            const data = await response.json()

            if (data.logs) {
                setLogs(data.logs)
                if (isRefresh) {
                    setLastUpdate(new Date())
                }
            } else {
                console.error('❌ Failed to fetch logs:', data.error)
            }
        } catch (error) {
            console.error('💥 Error fetching logs:', error)
        } finally {
            if (!isRefresh) {
                setLoading(false)
            } else {
                setRefreshing(false)
            }
        }
    }

    useEffect(() => {
        if (activeTab === 'monitoring') {
            fetchLogs(false) // Initial load
            fetchBlockedIPs() // Fetch blocked IPs
            
            // Add auto-refresh every 5 seconds for real-time updates
            const interval = setInterval(() => {
                if (document.visibilityState === 'visible') {
                    fetchLogs(true) // Background refresh
                }
            }, 15000)
            
            return () => clearInterval(interval)
        }
    }, [filter, activeTab])

    const getSeverityColor = (severity: string) => {
        switch (severity) {
            case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/20'
            case 'warning': return 'text-amber-500 bg-amber-500/10 border-amber-500/20'
            case 'info': return 'text-blue-400 bg-blue-400/10 border-blue-400/20'
            default: return 'text-gray-500 bg-gray-500/10 border-gray-500/20'
        }
    }

    const getEventIcon = (type: string) => {
        if (type.includes('failure') || type.includes('bypass') || type.includes('unauthorized')) {
            return <AlertTriangle className="w-4 h-4" />
        }
        if (type.includes('rate_limit')) {
            return <Lock className="w-4 h-4" />
        }
        if (type.includes('curl') || type.includes('suspicious')) {
            return <AlertTriangle className="w-4 h-4 text-amber-400" />
        }
        if (type.includes('vulnerability_scan') || type.includes('behavioral_scanner') || type.includes('honeypot')) {
            return <Shield className="w-4 h-4 text-red-400" />
        }
        if (type.includes('file')) {
            return <Lock className="w-4 h-4 text-red-400" />
        }
        if (type.includes('database') || type.includes('security_log')) {
            return <Lock className="w-4 h-4 text-purple-400" />
        }
        if (type.includes('api_access_monitored')) {
            return <Activity className="w-4 h-4 text-blue-400" />
        }
        return <Info className="w-4 h-4" />
    }

    const handleViewPayload = (log: SecurityLog) => {
        setSelectedLog(log)
        setShowPayloadModal(true)
    }

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text)
    }

    const formatJson = (obj: any): string => {
        try {
            return JSON.stringify(obj, null, 2)
        } catch {
            return JSON.stringify(obj)
        }
    }

    return (
        <div className="min-h-screen bg-[#050505] text-white p-8 font-sans">
            <div className="max-w-7xl mx-auto">
                {/* Header & Tabs */}
                <div className="mb-8 border-b border-white/10 pb-6">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-8">
                        <div className="flex items-center gap-3">
                            <div className="p-3 bg-blue-600/20 rounded-xl border border-blue-600/30">
                                <Shield className="w-8 h-8 text-blue-500" />
                            </div>
                            <div>
                                <h1 className="text-3xl font-bold bg-gradient-to-r from-white to-white/60 bg-clip-text text-transparent">
                                    Security Dashboard
                                </h1>
                                <div className="flex items-center gap-4 mt-1">
                                    <p className="text-white/40 text-sm">Comprehensive threat detection and scanning</p>
                                    <div className="flex items-center gap-2">
                                        <div className={`w-2 h-2 rounded-full ${refreshing ? 'bg-green-500 animate-pulse' : 'bg-gray-500'}`} />
                                        <span className="text-xs text-white/60">
                                            {refreshing ? 'Updating...' : `Last: ${lastUpdate.toLocaleTimeString()}`}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="flex items-center bg-white/5 border border-white/10 rounded-xl p-1">
                            <button
                                onClick={() => setActiveTab('monitoring')}
                                className={`flex items-center gap-2 px-6 py-2.5 rounded-lg text-sm font-semibold transition-all ${activeTab === 'monitoring' ? 'bg-blue-600 text-white shadow-lg' : 'text-white/40 hover:text-white/60'
                                    }`}
                            >
                                <Activity className="w-4 h-4" />
                                Internal Monitoring
                            </button>
                            <button
                                onClick={() => setActiveTab('github')}
                                className={`flex items-center gap-2 px-6 py-2.5 rounded-lg text-sm font-semibold transition-all ${activeTab === 'github' ? 'bg-blue-600 text-white shadow-lg' : 'text-white/40 hover:text-white/60'
                                    }`}
                            >
                                <Github className="w-4 h-4" />
                                GitHub Security Scan
                            </button>
                        </div>
                    </div>

                    {activeTab === 'monitoring' && (
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2 text-white/40 text-sm">
                                <Activity className="w-4 h-4" />
                                <span className="uppercase tracking-widest text-[10px] font-bold">Real-time Activity Log</span>
                            </div>

                            <div className="flex items-center gap-4">
                                <div className="flex items-center bg-white/5 border border-white/10 rounded-lg p-1">
                                    {['threats', 'noise', 'critical', 'warnings', 'scanner', 'api', 'file', 'curl', 'database', 'all'].map((item) => (
                                        <button
                                            key={item}
                                            onClick={() => setFilter(item)}
                                            className={`px-4 py-1.5 rounded-md text-sm transition-all ${filter === item ? 'bg-white/10 text-white shadow-lg' : 'text-white/40 hover:text-white/60'
                                                }`}
                                        >
                                            {item.charAt(0).toUpperCase() + item.slice(1)}
                                            {item === 'threats' && ' Only'}
                                            {item === 'noise' && ' Only'}
                                            {item === 'scanner' && ' Detection'}
                                            {item === 'curl' && ' Requests'}
                                            {item === 'file' && ' Operations'}
                                            {item === 'api' && ' Access'}
                                            {item === 'database' && ' Events'}
                                        </button>
                                    ))}
                                </div>
                                <button
                                    onClick={() => fetchLogs(false)}
                                    className="p-2.5 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition-all text-white/60 hover:text-white"
                                >
                                    <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
                                </button>
                            </div>
                        </div>
                    )}
                </div>

                {activeTab === 'monitoring' ? (
                    <>
                        {/* Blocked IPs Panel */}
                        {blockedIPs.length > 0 && (
                            <div className="bg-red-600/10 border border-red-600/30 rounded-2xl p-6 mb-8 backdrop-blur-xl">
                                <h3 className="text-red-500 font-semibold mb-4 flex items-center gap-2">
                                    <Shield className="w-5 h-5" />
                                    Blocked IPs ({blockedIPs.length}) - 1 Day Duration
                                </h3>
                                <div className="space-y-3">
                                    {blockedIPs.map(ip => (
                                        <div key={ip.ip_address} className="flex justify-between items-center bg-red-600/5 rounded-lg p-3">
                                            <div className="flex items-center gap-3">
                                                <div className="w-2 h-2 bg-red-500 rounded-full" />
                                                <span className="text-red-200 font-mono text-sm">{ip.ip_address}</span>
                                            </div>
                                            <div className="flex items-center gap-4">
                                                <span className="text-xs text-red-400">
                                                    Expires: {new Date(ip.expires_at).toLocaleString()}
                                                </span>
                                                <span className="text-xs text-red-300">
                                                    {Math.ceil((new Date(ip.expires_at).getTime() - Date.now()) / 60000)}m left
                                                </span>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                                <div className="mt-4 text-xs text-red-300">
                                    Blocks automatically expire after 1 day - no manual unblock needed
                                </div>
                            </div>
                        )}

                        {/* Status Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8 mt-8">
                            <div className="bg-white/5 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
                                <p className="text-white/40 text-sm mb-2">Total Events (30d)</p>
                                <h3 className="text-4xl font-bold">{logs.length}</h3>
                            </div>
                            <div className="bg-white/5 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
                                <p className="text-white/40 text-sm mb-2">Active Threats</p>
                                <h3 className="text-4xl font-bold text-amber-500">
                                    {logs.filter(l => l.severity === 'warning').length}
                                </h3>
                            </div>
                            <div className="bg-white/5 border border-white/10 rounded-2xl p-6 backdrop-blur-xl border-red-500/20">
                                <p className="text-white/40 text-sm mb-2">Critical Alerts</p>
                                <h3 className="text-4xl font-bold text-red-500">
                                    {logs.filter(l => l.severity === 'critical').length}
                                </h3>
                            </div>
                            <div className="bg-white/5 border border-white/10 rounded-2xl p-6 backdrop-blur-xl border-blue-500/20">
                                <p className="text-white/40 text-sm mb-2">Monitored Traffic</p>
                                <h3 className="text-4xl font-bold text-blue-400">
                                    {logs.filter(l => l.severity === 'info').length}
                                </h3>
                            </div>
                        </div>

                        {/* Logs Table */}
                        <div className="bg-white/5 border border-white/10 rounded-2xl overflow-hidden backdrop-blur-xl">
                            <div className="overflow-x-auto max-h-[600px] overflow-y-auto custom-scrollbar">
                                <table className="w-full text-left border-collapse sticky-header">
                                    <thead className="sticky top-0 z-10 bg-[#050505]">
                                        <tr className="border-b border-white/5 bg-white/[0.02]">
                                            <th className="px-6 py-4 text-sm font-medium text-white/40">Event</th>
                                            <th className="px-6 py-4 text-sm font-medium text-white/40">Severity</th>
                                            <th className="px-6 py-4 text-sm font-medium text-white/40">Origin</th>
                                            <th className="px-6 py-4 text-sm font-medium text-white/40">Timestamp</th>
                                            <th className="px-6 py-4 text-sm font-medium text-white/40 text-right">Details</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-white/5">
                                        {logs.length === 0 && !loading ? (
                                            <tr>
                                                <td colSpan={5} className="px-6 py-12 text-center text-white/20 italic">
                                                    No security events recorded.
                                                </td>
                                            </tr>
                                        ) : (
                                            logs.map((log) => (
                                                <tr key={log.id} className="hover:bg-white/[0.02] transition-colors group">
                                                    <td className="px-6 py-4">
                                                        <div className="flex items-center gap-3">
                                                            <div className={`p-2 rounded-lg ${getSeverityColor(log.severity)}`}>
                                                                {getEventIcon(log.event_type)}
                                                            </div>
                                                            <div>
                                                                <p className="font-medium text-white/90 capitalize">
                                                                    {log.event_type.replace(/_/g, ' ')}
                                                                </p>
                                                                <p className="text-xs text-white/30 truncate max-w-[200px]">
                                                                    {log.user_agent}
                                                                </p>
                                                            </div>
                                                        </div>
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider border transition-all ${getSeverityColor(log.severity)}`}>
                                                            {log.severity}
                                                        </span>
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <div className="flex flex-col">
                                                            <div className="flex items-center gap-1.5 text-sm text-white/70">
                                                                <Globe className="w-3 h-3" />
                                                                {log.ip_address || 'unknown'}
                                                            </div>
                                                            <div className="flex items-center gap-1.5 text-xs text-white/30">
                                                                <User className="w-3 h-3" />
                                                                {log.details?.username || 'N/A'}
                                                            </div>
                                                        </div>
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <div className="flex items-center gap-1.5 text-sm text-white/40">
                                                            <Clock className="w-3 h-3" />
                                                            {new Date(log.created_at).toLocaleString()}
                                                        </div>
                                                    </td>
                                                    <td className="px-6 py-4 text-right">
                                                        <div className="flex items-center gap-2 justify-end">
                                                            {/* Check if this IP is already blocked */}
                                                            {blockedIPs.some(ip => ip.ip_address === log.ip_address) ? (
                                                                <span className="text-xs text-red-400 font-medium">
                                                                    🚫 Blocked
                                                                </span>
                                                            ) : (
                                                                <button 
                                                                    onClick={() => handleBlockIP(log.ip_address)}
                                                                    disabled={blockingIP === log.ip_address}
                                                                    className="text-xs px-2 py-1 bg-red-600/20 text-red-400 border border-red-600/30 rounded-lg hover:bg-red-600/40 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                                                                >
                                                                    {blockingIP === log.ip_address ? '...' : 'Block IP'}
                                                                </button>
                                                            )}
                                                            <button 
                                                                onClick={() => handleViewPayload(log)}
                                                                className="text-xs text-blue-400 hover:text-blue-300 transition-colors font-medium underline underline-offset-4"
                                                            >
                                                                View Payload
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                            ))
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </>
                ) : (
                    <div className="mt-8">
                        <GitHubSecurityDashboard />
                    </div>
                )}
            </div>

            {/* Payload Modal */}
            {showPayloadModal && selectedLog && (
                <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
                    <div className="bg-[#050505] border border-white/10 rounded-2xl p-6 max-w-4xl max-h-[80vh] w-full mx-4 overflow-hidden flex flex-col">
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="text-xl font-semibold text-white">Security Event Payload</h3>
                            <button
                                onClick={() => setShowPayloadModal(false)}
                                className="p-2 hover:bg-white/10 rounded-lg transition-colors"
                            >
                                <X className="w-5 h-5 text-white/60" />
                            </button>
                        </div>

                        <div className="space-y-4 overflow-y-auto pr-2 custom-scrollbar">
                            {/* Event Summary */}
                            <div className="bg-white/5 border border-white/10 rounded-lg p-4">
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                                    <div>
                                        <p className="text-white/40 mb-1">Event Type</p>
                                        <p className="text-white font-medium capitalize">{selectedLog.event_type.replace(/_/g, ' ')}</p>
                                    </div>
                                    <div>
                                        <p className="text-white/40 mb-1">Severity</p>
                                        <span className={`px-2 py-1 rounded-full text-[10px] font-bold uppercase ${getSeverityColor(selectedLog.severity)}`}>
                                            {selectedLog.severity}
                                        </span>
                                    </div>
                                    <div>
                                        <p className="text-white/40 mb-1">IP Address</p>
                                        <p className="text-white font-medium">{selectedLog.ip_address || 'unknown'}</p>
                                    </div>
                                    <div>
                                        <p className="text-white/40 mb-1">Timestamp</p>
                                        <p className="text-white font-medium">{new Date(selectedLog.created_at).toLocaleString()}</p>
                                    </div>
                                </div>
                            </div>

                            {/* Payload Details */}
                            <div className="bg-white/5 border border-white/10 rounded-lg p-4">
                                <div className="flex items-center justify-between mb-4">
                                    <h4 className="text-lg font-medium text-white">Event Details</h4>
                                    <button
                                        onClick={() => copyToClipboard(formatJson(selectedLog.details))}
                                        className="flex items-center gap-2 px-3 py-1.5 bg-white/10 hover:bg-white/20 rounded-lg transition-colors text-sm text-white/80"
                                    >
                                        <Copy className="w-4 h-4" />
                                        Copy JSON
                                    </button>
                                </div>
                                <div className="bg-black/40 rounded-lg p-4 overflow-x-auto">
                                    <pre className="text-sm text-green-400 font-mono">
                                        {formatJson(selectedLog.details)}
                                    </pre>
                                </div>
                            </div>

                            {/* Additional Info */}
                            {selectedLog.user_agent && (
                                <div className="bg-white/5 border border-white/10 rounded-lg p-4">
                                    <h4 className="text-lg font-medium text-white mb-2">User Agent</h4>
                                    <p className="text-sm text-white/80 font-mono break-all">{selectedLog.user_agent}</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}

            <style jsx global>{`
                @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
                tr { animation: fadeIn 0.3s ease-out forwards; }
                
                .custom-scrollbar::-webkit-scrollbar {
                    width: 6px;
                    height: 6px;
                }
                .custom-scrollbar::-webkit-scrollbar-track {
                    background: transparent;
                }
                .custom-scrollbar::-webkit-scrollbar-thumb {
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 10px;
                }
                .custom-scrollbar::-webkit-scrollbar-thumb:hover {
                    background: rgba(255, 255, 255, 0.2);
                }
                
                .sticky-header thead th {
                    position: sticky;
                    top: 0;
                    background: #0d0d0d;
                    z-index: 10;
                }
            `}</style>
        </div>
    )
}
