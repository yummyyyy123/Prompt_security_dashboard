'use client'

import { usePathname } from 'next/navigation'
import Link from 'next/link'
import { Shield, Bug, FlaskConical, LayoutDashboard, LogOut } from 'lucide-react'
import { logout } from '@/lib/auth-simple'

const navItems = [
    { href: '/admin', label: 'Dashboard', icon: LayoutDashboard, exact: true },
    { href: '/admin/security', label: 'Security Testing', icon: FlaskConical },
]

export default function AdminLayout({ children }: { children: React.ReactNode }) {
    const pathname = usePathname()

    // Don't render the shared nav on the login page
    if (pathname?.startsWith('/admin/login')) {
        return <>{children}</>
    }

    const isActive = (href: string, exact?: boolean) => {
        if (exact) return pathname === href
        return pathname?.startsWith(href)
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-950 to-slate-900 flex">
            {/* Sidebar */}
            <aside className="w-64 shrink-0 bg-gray-900/90 border-r border-gray-800 flex flex-col">
                {/* Logo */}
                <div className="flex items-center gap-3 px-6 py-5 border-b border-gray-800">
                    <div className="p-2 rounded-lg bg-emerald-600">
                        <Shield className="w-5 h-5 text-white" />
                    </div>
                    <div>
                        <h1 className="text-sm font-bold text-white">Admin Panel</h1>
                        <p className="text-xs text-gray-500">Prompt Library</p>
                    </div>
                </div>

                {/* Navigation */}
                <nav className="flex-1 px-3 py-4 space-y-1">
                    {navItems.map(({ href, label, icon: Icon, exact }) => {
                        const active = isActive(href, exact)
                        return (
                            <Link
                                key={href}
                                href={href}
                                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${active
                                    ? 'bg-emerald-600/20 text-emerald-400 border border-emerald-600/30'
                                    : 'text-gray-400 hover:text-white hover:bg-white/5'
                                    }`}
                            >
                                <Icon className={`w-4 h-4 ${active ? 'text-emerald-400' : 'text-gray-500'}`} />
                                {label}
                            </Link>
                        )
                    })}
                </nav>

                {/* Logout */}
                <div className="px-3 py-4 border-t border-gray-800">
                    <button
                        onClick={() => logout()}
                        className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-sm font-medium text-gray-400 hover:text-red-400 hover:bg-red-500/10 transition-all duration-150"
                    >
                        <LogOut className="w-4 h-4" />
                        Sign Out
                    </button>
                </div>
            </aside>

            {/* Main content */}
            <main className="flex-1 overflow-auto">
                {children}
            </main>
        </div>
    )
}
