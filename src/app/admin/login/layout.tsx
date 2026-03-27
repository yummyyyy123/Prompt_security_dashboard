import { Metadata } from 'next'

export const metadata: Metadata = {
    title: 'Admin Login | Prompt Library',
    description: 'Access the administrative control center.',
}

export default function AdminLoginLayout({
    children,
}: {
    children: React.ReactNode
}) {
    return <>{children}</>
}
