'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Shield, AlertTriangle, CheckCircle, XCircle,
    Github, Lock, Bug, ShieldAlert, RefreshCw,
    ExternalLink, Clock, ChevronDown, ChevronUp,
    ShieldCheck, AlertCircle
} from 'lucide-react'

interface GitHubAlert {
    number: number
    state: string
    created_at: string
    html_url: string
    security_advisory?: {
        summary: string
        severity: string
        ghsa_id: string
    }
    rule?: {
        description: string
        severity: string
    }
    most_recent_instance?: {
        location: {
            path: string
        }
    }
    secret_type?: string
}

interface GithubSecurityData {
    dependabot: GitHubAlert[]
    codeScanning: GitHubAlert[]
    secretScanning: GitHubAlert[]
    repository: {
        owner: string
        repo: string
    }
}

export default function GitHubSecurityDashboard() {
    const [data, setData] = useState<GithubSecurityData | null>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)
    const [expandedSection, setExpandedSection] = useState<string | null>('codeScanning')

    const fetchData = async () => {
        setLoading(true)
        setError(null)
        try {
            const response = await fetch('/api/admin/github-security')
            const result = await response.json()
            if (result.success) {
                setData(result.data)
            } else {
                setError(result.error)
            }
        } catch (err: any) {
            setError('Failed to connect to security API')
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchData()
    }, [])

    const getTotalAlerts = () => {
        if (!data) return 0
        return data.dependabot.length + data.codeScanning.length + data.secretScanning.length
    }

    const getSeverityColor = (severity: string) => {
        switch (severity?.toLowerCase()) {
            case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/20'
            case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/20'
            case 'medium': return 'text-amber-500 bg-amber-500/10 border-amber-500/20'
            default: return 'text-blue-500 bg-blue-500/10 border-blue-500/20'
        }
    }

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center py-20 bg-slate-900/40 rounded-3xl border border-slate-800 backdrop-blur-xl">
                <RefreshCw className="w-10 h-10 text-emerald-500 animate-spin mb-4" />
                <p className="text-slate-400 font-medium animate-pulse">Syncing with GitHub Security Central...</p>
            </div>
        )
    }

    if (error) {
        return (
            <div className="p-8 bg-red-500/5 border border-red-500/20 rounded-3xl backdrop-blur-xl text-center">
                <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
                <h3 className="text-xl font-bold text-white mb-2">GitHub Sync Failed</h3>
                <p className="text-red-400 mb-6">{error}</p>
                <button
                    onClick={fetchData}
                    className="px-6 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl transition-all border border-slate-700 flex items-center gap-2 mx-auto"
                >
                    <RefreshCw className="w-4 h-4" /> Try Again
                </button>
            </div>
        )
    }

    return (
        <div className="space-y-8">
            {/* Premium Header/Status Card */}
            <div className="relative overflow-hidden bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 rounded-3xl border border-slate-700 p-8 shadow-2xl">
                <div className="absolute top-0 right-0 p-8 opacity-10">
                    <Github size={120} />
                </div>

                <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-8">
                    <div>
                        <div className="flex items-center gap-3 mb-4">
                            <div className="p-2 bg-emerald-500/20 rounded-lg">
                                <ShieldCheck className="w-6 h-6 text-emerald-400" />
                            </div>
                            <h2 className="text-2xl font-bold text-white">GitHub Security Status</h2>
                        </div>
                        <p className="text-slate-400 max-w-md">
                            Real-time monitoring of <span className="text-white font-mono">{data?.repository.owner}/{data?.repository.repo}</span> security posture powered by GitHub Advanced Security.
                        </p>
                    </div>

                    <div className="flex gap-4">
                        <div className="px-6 py-4 bg-slate-950/50 rounded-2xl border border-slate-700/50 text-center min-w-[120px]">
                            <p className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-1">Open Alerts</p>
                            <p className={`text-3xl font-bold ${getTotalAlerts() > 0 ? 'text-amber-500' : 'text-emerald-500'}`}>
                                {getTotalAlerts()}
                            </p>
                        </div>
                        <div className="px-6 py-4 bg-slate-950/50 rounded-2xl border border-slate-700/50 text-center min-w-[120px]">
                            <p className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-1">Risk Level</p>
                            <p className={`text-3xl font-bold ${getTotalAlerts() > 5 ? 'text-red-500' : getTotalAlerts() > 0 ? 'text-amber-500' : 'text-emerald-500'}`}>
                                {getTotalAlerts() > 5 ? 'High' : getTotalAlerts() > 0 ? 'Med' : 'Low'}
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Alert Sections */}
            <div className="grid grid-cols-1 gap-6">
                {/* Code Scanning (CodeQL) */}
                <Section
                    title="Code Scanning Alerts"
                    subtitle="Static analysis for vulnerabilities and coding errors"
                    icon={<Bug className="w-5 h-5 text-purple-400" />}
                    alerts={data?.codeScanning || []}
                    id="codeScanning"
                    expanded={expandedSection === 'codeScanning'}
                    onToggle={() => setExpandedSection(expandedSection === 'codeScanning' ? null : 'codeScanning')}
                    renderAlert={(alert) => (
                        <div key={alert.number} className="group p-4 bg-slate-800/40 hover:bg-slate-800/60 rounded-2xl border border-slate-700/50 transition-all">
                            <div className="flex items-start justify-between gap-4">
                                <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-2">
                                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${getSeverityColor(alert.rule?.severity || '')}`}>
                                            {alert.rule?.severity || 'unknown'}
                                        </span>
                                        <span className="text-xs text-slate-500 font-mono">#{alert.number}</span>
                                    </div>
                                    <h4 className="text-white font-semibold mb-1 group-hover:text-emerald-400 transition-colors">
                                        {alert.rule?.description || 'Potential security vulnerability'}
                                    </h4>
                                    <p className="text-xs text-slate-400 flex items-center gap-1">
                                        <Lock className="w-3 h-3" /> {alert.most_recent_instance?.location.path || 'Unknown file'}
                                    </p>
                                </div>
                                <a
                                    href={alert.html_url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="p-2 bg-slate-700/50 hover:bg-slate-600 rounded-lg text-slate-400 hover:text-white transition-all flex-shrink-0"
                                >
                                    <ExternalLink className="w-4 h-4" />
                                </a>
                            </div>
                        </div>
                    )}
                />

                {/* Secret Scanning */}
                <Section
                    title="Secret Scanning"
                    subtitle="Detection of hardcoded secrets and sensitive tokens"
                    icon={<ShieldAlert className="w-5 h-5 text-red-400" />}
                    alerts={data?.secretScanning || []}
                    id="secretScanning"
                    expanded={expandedSection === 'secretScanning'}
                    onToggle={() => setExpandedSection(expandedSection === 'secretScanning' ? null : 'secretScanning')}
                    renderAlert={(alert) => (
                        <div key={alert.number} className="group p-4 bg-red-500/5 hover:bg-red-500/10 rounded-2xl border border-red-500/20 transition-all">
                            <div className="flex items-start justify-between gap-4">
                                <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-2">
                                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border text-red-500 bg-red-500/10 border-red-500/20">
                                            Critical
                                        </span>
                                        <span className="text-xs text-slate-500 font-mono">#{alert.number}</span>
                                    </div>
                                    <h4 className="text-white font-semibold mb-1">
                                        Leaked {alert.secret_type || 'Secret'} Detected
                                    </h4>
                                    <p className="text-xs text-slate-400">
                                        A sensitive credential was found exposed in the codebase.
                                    </p>
                                </div>
                                <a
                                    href={alert.html_url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="p-2 bg-red-500/10 hover:bg-red-500/20 rounded-lg text-red-400 transition-all flex-shrink-0"
                                >
                                    <ExternalLink className="w-4 h-4" />
                                </a>
                            </div>
                        </div>
                    )}
                />

                {/* Dependabot */}
                <Section
                    title="Dependabot Alerts"
                    subtitle="Vulnerabilities in project dependencies"
                    icon={<Shield className="w-5 h-5 text-blue-400" />}
                    alerts={data?.dependabot || []}
                    id="dependabot"
                    expanded={expandedSection === 'dependabot'}
                    onToggle={() => setExpandedSection(expandedSection === 'dependabot' ? null : 'dependabot')}
                    renderAlert={(alert) => (
                        <div key={alert.number} className="group p-4 bg-slate-800/40 hover:bg-slate-800/60 rounded-2xl border border-slate-700/50 transition-all">
                            <div className="flex items-start justify-between gap-4">
                                <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-2">
                                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${getSeverityColor(alert.security_advisory?.severity || '')}`}>
                                            {alert.security_advisory?.severity || 'unknown'}
                                        </span>
                                        <span className="text-xs text-slate-500 font-mono">{alert.security_advisory?.ghsa_id}</span>
                                    </div>
                                    <h4 className="text-white font-semibold mb-1">
                                        {alert.security_advisory?.summary}
                                    </h4>
                                    <p className="text-xs text-slate-400">
                                        Open security advisory in dependency chain.
                                    </p>
                                </div>
                                <a
                                    href={alert.html_url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="p-2 bg-slate-700/50 hover:bg-slate-600 rounded-lg text-slate-400 hover:text-white transition-all flex-shrink-0"
                                >
                                    <ExternalLink className="w-4 h-4" />
                                </a>
                            </div>
                        </div>
                    )}
                />
            </div>
        </div>
    )
}

function Section({
    title,
    subtitle,
    icon,
    alerts,
    id,
    expanded,
    onToggle,
    renderAlert
}: {
    title: string
    subtitle: string
    icon: React.ReactNode
    alerts: any[]
    id: string
    expanded: boolean
    onToggle: () => void
    renderAlert: (alert: any) => React.ReactNode
}) {
    return (
        <div className="bg-slate-900/60 backdrop-blur-xl rounded-3xl border border-slate-800/80 overflow-hidden transition-all">
            <button
                onClick={onToggle}
                className="w-full flex items-center justify-between p-6 hover:bg-slate-800/30 transition-colors"
            >
                <div className="flex items-center gap-4 text-left">
                    <div className="p-2.5 bg-slate-800 rounded-xl border border-slate-700">
                        {icon}
                    </div>
                    <div>
                        <h3 className="text-lg font-bold text-white leading-tight">{title}</h3>
                        <p className="text-xs text-slate-500">{subtitle}</p>
                    </div>
                </div>
                <div className="flex items-center gap-4">
                    <span className={`text-sm font-bold px-2 py-0.5 rounded-lg ${alerts.length > 0 ? 'bg-amber-500/10 text-amber-500' : 'bg-emerald-500/10 text-emerald-500'}`}>
                        {alerts.length}
                    </span>
                    {expanded ? <ChevronUp className="w-5 h-5 text-slate-500" /> : <ChevronDown className="w-5 h-5 text-slate-500" />}
                </div>
            </button>

            <AnimatePresence>
                {expanded && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden"
                    >
                        <div className="p-6 pt-0 space-y-3">
                            {alerts.length > 0 ? (
                                alerts.map(renderAlert)
                            ) : (
                                <div className="flex flex-col items-center justify-center py-10 bg-slate-950/20 rounded-2xl border border-dashed border-slate-800">
                                    <CheckCircle className="w-8 h-8 text-emerald-500/40 mb-2" />
                                    <p className="text-slate-500 text-sm font-medium">No active alerts found</p>
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    )
}
