import React, { useState } from 'react'
import { scanMutations } from '@/services/scanService'
import type {
  DiscoveredEndpoint,
  PurpleTeamResponse,
  PurpleTeamTelemetry,
  ScanTestType,
} from '@/types/scan.types'
import { SCAN_TEST_TYPES, TEST_TYPE_LABELS } from '@/config/constants'
import { Button } from '@/components/common/Button'
import './PurpleTeamScanner.css'

export const PurpleTeamScanner: React.FC = () => {
  const [crawlUrl, setCrawlUrl] = useState('http://127.0.0.1:8000/openapi.json')
  const [crawlMode, setCrawlMode] = useState<'auto' | 'openapi' | 'spider'>('auto')
  const [isCrawling, setIsCrawling] = useState(false)
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState<DiscoveredEndpoint[]>([])
  const [crawlMessage, setCrawlMessage] = useState<string | null>(null)

  // Audit configuration
  const [authToken, setAuthToken] = useState('')
  const [tokenAttacker, setTokenAttacker] = useState('')
  const [selectedTests, setSelectedTests] = useState<ScanTestType[]>([
    SCAN_TEST_TYPES.SQLI,
    SCAN_TEST_TYPES.AUTH,
    SCAN_TEST_TYPES.RATE_LIMIT,
    SCAN_TEST_TYPES.IDOR,
  ])
  const [isAuditing, setIsAuditing] = useState(false)
  const [auditResult, setAuditResult] = useState<PurpleTeamResponse | null>(null)
  const [expandedRow, setExpandedRow] = useState<number | null>(null)

  const [auditError, setAuditError] = useState<string | null>(null)

  const handleCrawl = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!crawlUrl.trim()) return

    setIsCrawling(true)
    setCrawlMessage(null)
    setAuditResult(null)
    setAuditError(null)

    try {
      const res = await scanMutations.crawlApi({
        target_url: crawlUrl.trim(),
        crawl_mode: crawlMode,
      })
      setDiscoveredEndpoints(res.endpoints || [])
      setCrawlMessage(`${res.message} (Source: ${res.source})`)
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'Crawl failed. Ensure the backend is running.'
      setCrawlMessage(`Error: ${msg}`)
    } finally {
      setIsCrawling(false)
    }
  }

  const handleToggleTest = (testType: ScanTestType) => {
    setSelectedTests((prev) =>
      prev.includes(testType) ? prev.filter((t) => t !== testType) : [...prev, testType]
    )
  }

  const handleRunAudit = async () => {
    if (discoveredEndpoints.length === 0 || selectedTests.length === 0) return

    setIsAuditing(true)
    setAuditError(null)
    try {
      const res = await scanMutations.executePurpleTeam({
        base_url: crawlUrl,
        endpoints: discoveredEndpoints,
        tests_to_run: selectedTests,
        auth_token: authToken.trim() || null,
        token_attacker: tokenAttacker.trim() || null,
      })
      setAuditResult(res)
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.message || 'Check backend logs.'
      setAuditError(`Audit failed: ${detail}`)
    } finally {
      setIsAuditing(false)
    }
  }

  const handleDownloadReport = () => {
    if (!auditResult) return

    // Open a report window with the styled HTML
    const reportWindow = window.open('', '_blank')
    if (reportWindow) {
      fetch('/api/scans/report/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('auth_token') || ''}`,
        },
        body: JSON.stringify(auditResult),
      })
        .then((res) => res.text())
        .then((html) => {
          reportWindow.document.open()
          reportWindow.document.write(html)
          reportWindow.document.close()
        })
        .catch(() => {
          reportWindow.document.write('<h3>Failed to generate report.</h3>')
        })
    }
  }

  return (
    <div className="purpleteam-container">
      {/* 1. Crawler Input Card */}
      <div className="purpleteam-card">
        <div className="purpleteam-card__header">
          <div className="purpleteam-card__title">
            <span>🕷️</span> Automated API Crawler & Attack Surface Discovery
          </div>
          <p className="purpleteam-card__desc">
            Automatically discover all endpoints via OpenAPI / Swagger specifications or JavaScript bundle crawling.
          </p>
        </div>

        <form onSubmit={handleCrawl} className="purpleteam-form">
          <div className="purpleteam-form__row">
            <div className="purpleteam-form__group" style={{ flex: 3 }}>
              <label className="purpleteam-form__label">Target Base URL or OpenAPI Spec URL</label>
              <input
                type="text"
                className="purpleteam-form__input"
                value={crawlUrl}
                onChange={(e) => setCrawlUrl(e.target.value)}
                placeholder="e.g. http://127.0.0.1:8000/openapi.json or https://petstore.swagger.io/v2/swagger.json"
                required
              />
            </div>

            <div className="purpleteam-form__group" style={{ flex: 1 }}>
              <label className="purpleteam-form__label">Discovery Mode</label>
              <select
                className="purpleteam-form__select"
                value={crawlMode}
                onChange={(e) => setCrawlMode(e.target.value as any)}
              >
                <option value="auto">Auto-Detect (OpenAPI + Spider)</option>
                <option value="openapi">OpenAPI / Swagger Only</option>
                <option value="spider">Web Spider (HTML/JS)</option>
              </select>
            </div>

            <Button type="submit" disabled={isCrawling}>
              {isCrawling ? 'Crawling...' : 'Crawl Endpoints'}
            </Button>
          </div>
        </form>

        {crawlMessage && (
          <p style={{ marginTop: '0.75rem', fontSize: '0.85rem', color: '#93c5fd' }}>
            ℹ️ {crawlMessage}
          </p>
        )}

        {/* Discovered Endpoints Box */}
        {discoveredEndpoints.length > 0 && (
          <div style={{ marginTop: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h4 style={{ color: '#f3f4f6', margin: 0, fontSize: '0.95rem' }}>
                Discovered Endpoints ({discoveredEndpoints.length})
              </h4>
              <span style={{ fontSize: '0.75rem', color: '#9ca3af' }}>Ready for multi-vector audit</span>
            </div>

            <div className="endpoints-box">
              {discoveredEndpoints.map((ep, idx) => (
                <div key={idx} className="endpoint-item">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <span className={`endpoint-pill method-${ep.method}`}>{ep.method}</span>
                    <span style={{ color: '#f3f4f6' }}>{ep.path}</span>
                    {ep.summary && <span style={{ color: '#6b7280', fontSize: '0.75rem' }}>— {ep.summary}</span>}
                  </div>
                  <span style={{ color: '#4b5563', fontSize: '0.75rem' }}>
                    {ep.requires_auth ? '🔒 Auth Required' : '🌐 Public'}
                  </span>
                </div>
              ))}
            </div>

            {/* Test Selection & Dual-Token Purple Team Trigger */}
            <div style={{ marginTop: '1.5rem', borderTop: '1px solid #1f2937', paddingTop: '1.25rem' }}>
              <h4 style={{ color: '#f3f4f6', marginBottom: '0.75rem', fontSize: '0.95rem' }}>
                Configure Purple-Team Security Audit
              </h4>

              <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
                {Object.values(SCAN_TEST_TYPES).map((type) => (
                  <label
                    key={type}
                    style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#e5e7eb', fontSize: '0.875rem', cursor: 'pointer' }}
                  >
                    <input
                      type="checkbox"
                      checked={selectedTests.includes(type)}
                      onChange={() => handleToggleTest(type)}
                    />
                    {TEST_TYPE_LABELS[type]}
                  </label>
                ))}
              </div>

              {/* Dual-Token BOLA Inputs */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                <div className="purpleteam-form__group">
                  <label className="purpleteam-form__label">
                    Token A: Victim / User 1 (Baseline Auth)
                  </label>
                  <input
                    type="text"
                    className="purpleteam-form__input"
                    value={authToken}
                    onChange={(e) => setAuthToken(e.target.value)}
                    placeholder="Bearer eyJhbGci..."
                  />
                </div>

                <div className="purpleteam-form__group">
                  <label className="purpleteam-form__label">
                    Token B: Attacker / User 2 (Dual-Token BOLA Engine)
                  </label>
                  <input
                    type="text"
                    className="purpleteam-form__input"
                    value={tokenAttacker}
                    onChange={(e) => setTokenAttacker(e.target.value)}
                    placeholder="Bearer eyJhbGci... (Used to test cross-tenant data leaks)"
                  />
                </div>
              </div>

              {auditError && (
                <p style={{ color: '#f87171', fontSize: '0.85rem', margin: '0.5rem 0' }}>
                  ⚠️ {auditError}
                </p>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
                <Button onClick={handleRunAudit} disabled={isAuditing} style={{ background: '#7c3aed' }}>
                  {isAuditing ? '⚡ Running Purple-Team Simulation...' : '⚡ Launch Purple-Team Audit'}
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 2. Purple Team Results, WAF Perimeter & AI Defense Telemetry */}
      {auditResult && (
        <div className="purpleteam-card">
          <div className="purpleteam-card__header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div className="purpleteam-card__title">
                <span>🟣</span> Closed-Loop Purple-Team BAS Results
              </div>
              <p className="purpleteam-card__desc">
                Correlation between Offensive OWASP test execution and Defensive AI Threat ML detection.
              </p>
            </div>

            <Button onClick={handleDownloadReport} variant="secondary" style={{ borderColor: '#6366f1', color: '#a5b4fc' }}>
              📄 Download Audit Report
            </Button>
          </div>

          {/* WAF & Perimeter Detection Badge */}
          {auditResult.waf_info && (
            <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '0.5rem', padding: '1rem', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div>
                  <span style={{ color: '#94a3b8', fontSize: '0.75rem', textTransform: 'uppercase', fontWeight: 600 }}>Edge Perimeter: </span>
                  <span style={{ color: '#38bdf8', fontWeight: 700, marginLeft: '0.25rem' }}>
                    🛡️ {auditResult.waf_info.detected_waf || 'Direct Origin / No WAF'}
                  </span>
                </div>

                <div>
                  <span style={{ color: '#94a3b8', fontSize: '0.75rem', textTransform: 'uppercase', fontWeight: 600 }}>CORS Status: </span>
                  <span style={{ color: auditResult.waf_info.cors_status?.vulnerable ? '#f87171' : '#4ade80', fontWeight: 600, marginLeft: '0.25rem' }}>
                    {auditResult.waf_info.cors_status?.vulnerable ? 'Vulnerable' : 'Secure'}
                  </span>
                </div>

                <div>
                  <span style={{ color: '#94a3b8', fontSize: '0.75rem', textTransform: 'uppercase', fontWeight: 600 }}>Security Headers Grade: </span>
                  <span style={{ color: '#fbbf24', fontWeight: 700, marginLeft: '0.25rem' }}>
                    {auditResult.waf_info.security_rating || 'B'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Stat Cards */}
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-card__label">Endpoints Audited</div>
              <div className="stat-card__value">{auditResult.total_endpoints_scanned}</div>
            </div>

            <div className="stat-card">
              <div className="stat-card__label">Attacks Simulated</div>
              <div className="stat-card__value">{auditResult.total_attacks_simulated}</div>
            </div>

            <div className="stat-card">
              <div className="stat-card__label">Vulnerabilities Found</div>
              <div className="stat-card__value stat-alert">{auditResult.vulnerabilities_found}</div>
            </div>

            <div className="stat-card">
              <div className="stat-card__label">AI Defense Coverage</div>
              <div className="stat-card__value stat-highlight">{auditResult.defense_coverage_percent}%</div>
            </div>
          </div>

          {/* Coverage Bar */}
          <div style={{ marginTop: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: '#9ca3af' }}>
              <span>AI Detection Coverage Rate</span>
              <span>{auditResult.ai_detected_count} Detected / {auditResult.ai_bypassed_count} Stealth Bypasses</span>
            </div>
            <div className="coverage-bar">
              <div className="coverage-fill" style={{ width: `${auditResult.defense_coverage_percent}%` }}></div>
            </div>
          </div>

          {/* Telemetry Table */}
          <div style={{ overflowX: 'auto', marginTop: '1.5rem' }}>
            <table className="telemetry-table">
              <thead>
                <tr>
                  <th>Method & Path</th>
                  <th>Attack Module</th>
                  <th>Offensive Status</th>
                  <th>AI Threat Score</th>
                  <th>Defense Classification</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {auditResult.telemetry.map((t: PurpleTeamTelemetry, idx: number) => (
                  <React.Fragment key={idx}>
                    <tr>
                      <td>
                        <span className={`endpoint-pill method-${t.method}`} style={{ marginRight: '0.5rem' }}>
                          {t.method}
                        </span>
                        <code>{t.endpoint}</code>
                      </td>
                      <td>
                        <strong>{t.test_name}</strong>
                      </td>
                      <td>
                        <span
                          style={{
                            color: t.vulnerability_status === 'vulnerable' ? '#f87171' : '#4ade80',
                            fontWeight: 600,
                          }}
                        >
                          {t.vulnerability_status.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>
                          {(t.ai_threat_score * 100).toFixed(0)}%
                        </span>
                      </td>
                      <td>
                        <span
                          className={`verdict-badge ${
                            t.defense_verdict === 'CAUGHT_BY_AI' ? 'verdict-caught' : 'verdict-bypass'
                          }`}
                        >
                          {t.defense_verdict === 'CAUGHT_BY_AI' ? '🛡️ CAUGHT BY AI' : '⚠️ STEALTH BYPASS'}
                        </span>
                      </td>
                      <td>
                        <button
                          onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                          style={{
                            background: 'transparent',
                            border: '1px solid #4b5563',
                            borderRadius: '0.25rem',
                            color: '#cbd5e1',
                            padding: '0.25rem 0.5rem',
                            cursor: 'pointer',
                            fontSize: '0.75rem',
                          }}
                        >
                          {expandedRow === idx ? 'Hide Audit' : 'Inspect'}
                        </button>
                      </td>
                    </tr>

                    {expandedRow === idx && (
                      <tr>
                        <td colSpan={6} style={{ background: '#0b1329', padding: '1rem' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                            <div>
                              <span style={{ color: '#94a3b8', fontSize: '0.75rem', fontWeight: 600 }}>Simulated Attack Vector: </span>
                              <code style={{ color: '#f59e0b', wordBreak: 'break-all' }}>{t.payload_sample || 'Standard Header Injection'}</code>
                            </div>

                            {t.ai_matched_rules.length > 0 && (
                              <div>
                                <span style={{ color: '#94a3b8', fontSize: '0.75rem', fontWeight: 600 }}>Defensive AI Matches: </span>
                                <span style={{ color: '#c084fc', fontSize: '0.8rem' }}>
                                  {t.ai_matched_rules.map((r) => `[${r}]`).join(' ')}
                                </span>
                              </div>
                            )}

                            <div>
                              <span style={{ color: '#94a3b8', fontSize: '0.75rem', fontWeight: 600 }}>Developer Remediation Patch:</span>
                              <pre className="remediation-box">{t.remediation_patch}</pre>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
