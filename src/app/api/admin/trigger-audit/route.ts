import { NextRequest, NextResponse } from 'next/server'
import { withAdminAuth } from '../../../../lib/admin-auth'

export const POST = withAdminAuth(async (request: NextRequest) => {
    const GITHUB_TOKEN = process.env.GITHUB_TOKEN
    const GITHUB_OWNER = process.env.GITHUB_OWNER
    const GITHUB_REPO = process.env.GITHUB_REPO
    const WORKFLOW_ID = 'security.yml' // File name of the workflow

    if (!GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO) {
        return NextResponse.json({
            success: false,
            error: 'GitHub credentials missing in environment variables'
        }, { status: 500 })
    }

    try {
        console.log(`🚀 Triggering GitHub Workflow: ${WORKFLOW_ID}...`)

        const response = await fetch(
            `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/actions/workflows/${WORKFLOW_ID}/dispatches`,
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${GITHUB_TOKEN}`,
                    'Accept': 'application/vnd.github+json',
                    'X-GitHub-Api-Version': '2022-11-28'
                },
                body: JSON.stringify({
                    ref: 'main', // Or branch name
                })
            }
        )

        if (!response.ok) {
            const errorData = await response.json()
            throw new Error(errorData.message || 'Failed to trigger workflow')
        }

        return NextResponse.json({
            success: true,
            message: 'Scan triggered successfully on GitHub Actions',
            githubUrl: `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/actions`,
            timestamp: new Date().toISOString()
        })

    } catch (error: any) {
        console.error('Workflow Trigger Error:', error)
        return NextResponse.json({
            success: false,
            error: error.message
        }, { status: 500 })
    }
})
