"""
Executive HTML / Printable Security Audit Report Generator
Creates a professional, branded assessment report with CVSS severity badges and remediation code.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime


class ReportGenerator:
    """
    Renders standalone, responsive HTML/Printable executive security reports.
    """

    @classmethod
    def generate_html_report(
        cls,
        target_url: str,
        waf_info: dict[str, Any],
        telemetry: list[dict[str, Any]],
        stats: dict[str, Any]
    ) -> str:
        scan_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Build telemetry rows
        rows_html = ""
        for t in telemetry:
            status = t.get("vulnerability_status", "safe").upper()
            status_color = "#dc2626" if status == "VULNERABLE" else "#16a34a"
            score = int(t.get("ai_threat_score", 0.0) * 100)
            verdict = t.get("defense_verdict", "UNKNOWN")
            verdict_badge = (
                f"<span style='background: #8b5cf6; color: #fff; padding: 2px 6px; border-radius: 4px;'>CAUGHT BY AI</span>"
                if verdict == "CAUGHT_BY_AI"
                else f"<span style='background: #f59e0b; color: #000; padding: 2px 6px; border-radius: 4px;'>STEALTH BYPASS</span>"
            )

            rows_html += f"""
            <tr style="border-bottom: 1px solid #e5e7eb;">
                <td style="padding: 10px; font-family: monospace;"><strong>{t.get('method', 'GET')}</strong> {t.get('endpoint')}</td>
                <td style="padding: 10px;"><strong>{t.get('test_name')}</strong></td>
                <td style="padding: 10px;"><span style="color: {status_color}; font-weight: 700;">{status}</span></td>
                <td style="padding: 10px; font-family: monospace;">{score}%</td>
                <td style="padding: 10px;">{verdict_badge}</td>
            </tr>
            <tr>
                <td colspan="5" style="background: #f9fafb; padding: 10px; font-size: 0.85rem;">
                    <strong>Simulated Payload:</strong> <code style="color: #b45309;">{t.get('payload_sample', 'N/A')}</code><br>
                    <strong>Mitigation Patch:</strong>
                    <pre style="background: #1e293b; color: #38bdf8; padding: 8px; border-radius: 4px; overflow-x: auto; margin-top: 4px;">{t.get('remediation_patch', 'N/A')}</pre>
                </td>
            </tr>
            """

        missing_headers_html = "".join(f"<li>⚠️ Missing {h}</li>" for h in waf_info.get("missing_security_headers", []))
        if not missing_headers_html:
            missing_headers_html = "<li style='color: #16a34a;'>✓ All standard security headers are enforced</li>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>API Security & Threat Audit Report - {target_url}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 40px; background: #fff; color: #1f2937; line-height: 1.5; }}
        .header {{ border-bottom: 2px solid #6366f1; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; color: #1e1b4b; font-size: 26px; }}
        .meta {{ color: #6b7280; font-size: 14px; margin-top: 5px; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 25px 0; }}
        .card {{ background: #f3f4f6; border-radius: 8px; padding: 15px; border-left: 4px solid #6366f1; }}
        .card h4 {{ margin: 0; font-size: 12px; color: #6b7280; text-transform: uppercase; }}
        .card p {{ margin: 5px 0 0 0; font-size: 24px; font-weight: 700; color: #111827; }}
        .section-title {{ font-size: 18px; font-weight: 700; margin-top: 35px; border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }}
        th {{ background: #f3f4f6; text-align: left; padding: 10px; border-bottom: 2px solid #d1d5db; }}
        .print-btn {{ background: #6366f1; color: #fff; border: none; padding: 8px 16px; border-radius: 4px; font-weight: 600; cursor: pointer; float: right; }}
        @media print {{ .print-btn {{ display: none; }} body {{ padding: 0; }} }}
    </style>
</head>
<body>
    <button class="print-btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
    <div class="header">
        <h1>API Security Assessment & AI Defense Report</h1>
        <div class="meta">Target: <strong>{target_url}</strong> | Generated: {scan_date}</div>
    </div>

    <div class="grid">
        <div class="card">
            <h4>Endpoints Audited</h4>
            <p>{stats.get('total_endpoints', 0)}</p>
        </div>
        <div class="card" style="border-left-color: #ef4444;">
            <h4>Vulnerabilities Found</h4>
            <p style="color: #ef4444;">{stats.get('vulnerabilities_found', 0)}</p>
        </div>
        <div class="card" style="border-left-color: #8b5cf6;">
            <h4>AI Defense Coverage</h4>
            <p style="color: #8b5cf6;">{stats.get('defense_coverage_percent', 0)}%</p>
        </div>
        <div class="card" style="border-left-color: #10b981;">
            <h4>Detected WAF</h4>
            <p style="font-size: 16px; margin-top: 10px;">{waf_info.get('detected_waf', 'None')}</p>
        </div>
    </div>

    <div class="section-title">🛡️ Perimeter & WAF Fingerprinting</div>
    <div style="background: #f9fafb; padding: 15px; border-radius: 6px; margin-top: 10px; font-size: 14px;">
        <p><strong>WAF Protection:</strong> {waf_info.get('detected_waf', 'None')}</p>
        <p><strong>CORS Policy Status:</strong> {waf_info.get('cors_status', {}).get('details', 'N/A')}</p>
        <p><strong>Security Headers Check:</strong></p>
        <ul>{missing_headers_html}</ul>
    </div>

    <div class="section-title">🔍 Detailed Vulnerability & AI Telemetry Log</div>
    <table>
        <thead>
            <tr>
                <th>Endpoint & Method</th>
                <th>Attack Vector</th>
                <th>Offensive Finding</th>
                <th>AI Threat Score</th>
                <th>Defense Classification</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>

    <div style="margin-top: 50px; text-align: center; color: #9ca3af; font-size: 12px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
        Report generated by Unified API Security & Threat Intelligence Platform • Confidential Audit
    </div>
</body>
</html>"""

