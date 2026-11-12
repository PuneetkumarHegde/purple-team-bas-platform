"""
WAF (Web Application Firewall) & Security Header / CORS Scanner
Detects edge protections (Cloudflare, AWS WAF, Akamai) and audits dangerous CORS misconfigurations.
"""

from __future__ import annotations

import httpx
from typing import Any
from urllib.parse import urlparse

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status", "cloudflare"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id", "awselb", "aws-waf"],
    "Akamai": ["x-akamai-transformed", "akamai-origin-hop", "akamaighost"],
    "ModSecurity": ["mod_security", "NOYB"],
    "F5 BIG-IP": ["bigipserver", "x-cnection", "f5"],
    "Imperva / Incapsula": ["x-iinfo", "incap_ses", "visid_incap"],
}


class WAFAndHeaderScanner:
    """
    Audits edge WAF protections, CORS policies, and security headers.
    """

    @classmethod
    async def analyze(cls, target_url: str, client: httpx.AsyncClient | None = None) -> dict[str, Any]:
        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True)
            should_close = True

        try:
            parsed = urlparse(target_url)
            root_url = f"{parsed.scheme}://{parsed.netloc}"

            # 1. Normal baseline request
            normal_res = await client.get(target_url)
            headers = {k.lower(): v for k, v in normal_res.headers.items()}
            server_header = headers.get("server", "Unknown")

            # Detect WAF
            detected_waf = "None / Direct Origin"
            for waf_name, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if any(sig in k or sig in v.lower() for k, v in headers.items()):
                        detected_waf = waf_name
                        break
                if detected_waf != "None / Direct Origin":
                    break

            # 2. CORS Misconfiguration Audit (Origin Reflection test)
            evil_origin = "https://evil-attacker.com"
            cors_res = await client.get(target_url, headers={"Origin": evil_origin})
            cors_headers = {k.lower(): v for k, v in cors_res.headers.items()}

            acao = cors_headers.get("access-control-allow-origin", "")
            acac = cors_headers.get("access-control-allow-credentials", "").lower()

            cors_vulnerable = False
            cors_details = "CORS policy is secure or not present."

            if acao == "*" and acac == "true":
                cors_vulnerable = True
                cors_details = "CRITICAL: Wildcard CORS with Allow-Credentials enabled."
            elif acao == evil_origin:
                cors_vulnerable = True
                cors_details = f"HIGH: Arbitrary Origin Reflection detected. Server trusts '{evil_origin}'."

            # 3. Security Headers Audit
            missing_headers = []
            if "strict-transport-security" not in headers and target_url.startswith("https"):
                missing_headers.append("HSTS (Strict-Transport-Security)")
            if "x-content-type-options" not in headers:
                missing_headers.append("X-Content-Type-Options: nosniff")
            if "x-frame-options" not in headers and "content-security-policy" not in headers:
                missing_headers.append("X-Frame-Options (Clickjacking protection)")

            return {
                "target_url": target_url,
                "detected_waf": detected_waf,
                "server_technology": server_header,
                "cors_status": {
                    "vulnerable": cors_vulnerable,
                    "details": cors_details,
                    "allow_origin": acao,
                    "allow_credentials": acac,
                },
                "missing_security_headers": missing_headers,
                "security_rating": "A" if not cors_vulnerable and len(missing_headers) == 0 else ("B" if not cors_vulnerable else "F")
            }
        except Exception as e:
            return {
                "target_url": target_url,
                "detected_waf": "Error probing target",
                "server_technology": "Unknown",
                "cors_status": {"vulnerable": False, "details": str(e)},
                "missing_security_headers": [],
                "security_rating": "N/A"
            }
        finally:
            if should_close:
                await client.aclose()

