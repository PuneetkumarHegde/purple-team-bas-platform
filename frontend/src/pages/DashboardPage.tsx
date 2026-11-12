// ===========================
// DashboardPage.tsx
// ©AngelaMos | 2025
// Integrated with OpenAPI Crawler & AI Threat Defense BAS Suite
// ===========================

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/common/Button'
import { NewScanForm } from '@/components/scan/NewScanForm'
import { ScansList } from '@/components/scan/ScansList'
import { PurpleTeamScanner } from '@/components/purpleteam/PurpleTeamScanner'
import { useAuthStore } from '@/store/authStore'
import './DashboardPage.css'

export const DashboardPage = (): React.ReactElement => {
  const navigate = useNavigate()
  const clearAuth = useAuthStore((state) => state.clearAuth)
  const user = useAuthStore((state) => state.user)
  const [activeTab, setActiveTab] = useState<'crawler' | 'single'>('crawler')

  const handleLogout = (): void => {
    clearAuth()
    void navigate('/login')
  }

  return (
    <div className="dashboard">
      <div className="dashboard__container">
        <header className="dashboard__header">
          <div className="dashboard__header-content">
            <div className="dashboard__header-text">
              <h1 className="dashboard__title">API Security & AI Threat Platform</h1>
              <p className="dashboard__subtitle">
                Automated OpenAPI Crawler, OWASP Attack Fuzzing & Real-time AI Defense Simulation
              </p>
            </div>
            <div className="dashboard__header-actions">
              <span className="dashboard__user-email">{user?.email}</span>
              <Button onClick={handleLogout} variant="secondary">
                Logout
              </Button>
            </div>
          </div>

          {/* Navigation Mode Tabs */}
          <div
            style={{
              display: 'flex',
              gap: '1rem',
              marginTop: '1.25rem',
              borderBottom: '1px solid #1f2937',
              paddingBottom: '0.5rem',
            }}
          >
            <button
              onClick={() => setActiveTab('crawler')}
              style={{
                background: 'transparent',
                border: 'none',
                borderBottom: activeTab === 'crawler' ? '2px solid #8b5cf6' : 'none',
                color: activeTab === 'crawler' ? '#c084fc' : '#9ca3af',
                fontWeight: 600,
                fontSize: '0.95rem',
                padding: '0.5rem 1rem',
                cursor: 'pointer',
              }}
            >
              🕷️ Automated Crawler & AI Purple-Team Audit
            </button>

            <button
              onClick={() => setActiveTab('single')}
              style={{
                background: 'transparent',
                border: 'none',
                borderBottom: activeTab === 'single' ? '2px solid #8b5cf6' : 'none',
                color: activeTab === 'single' ? '#c084fc' : '#9ca3af',
                fontWeight: 600,
                fontSize: '0.95rem',
                padding: '0.5rem 1rem',
                cursor: 'pointer',
              }}
            >
              🎯 Single Endpoint Quick Scan
            </button>
          </div>
        </header>

        <div className="dashboard__content">
          {activeTab === 'crawler' ? (
            <section className="dashboard__section">
              <PurpleTeamScanner />
            </section>
          ) : (
            <>
              <section className="dashboard__section">
                <h2 className="dashboard__section-title">Single Endpoint Scan</h2>
                <NewScanForm />
              </section>

              <section className="dashboard__section">
                <h2 className="dashboard__section-title">Recent Scans</h2>
                <ScansList />
              </section>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
