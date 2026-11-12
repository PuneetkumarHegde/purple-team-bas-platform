"""
Dual-Token BOLA / Broken Object Level Authorization Engine
OWASP API1:2023 - Tests cross-tenant unauthorized data access between User A and User B.
"""

from __future__ import annotations

import httpx
from typing import Any


class DualTokenBOLAEngine:
    """
    Executes automated horizontal privilege escalation tests using two distinct user credentials.
    """

    @classmethod
    async def test_bola(
        cls,
        endpoint_url: str,
        token_a: str,
        token_b: str,
        client: httpx.AsyncClient | None = None
    ) -> dict[str, Any]:
        """
        Executes a dual-token replay test:
        1. Accesses endpoint with Token A (Victim).
        2. Replays request with Token B (Attacker).
        3. Flags BOLA if Token B receives Victim's resource.
        """
        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0, verify=False)
            should_close = True

        headers_a = {"Authorization": f"Bearer {token_a.replace('Bearer ', '').strip()}"}
        headers_b = {"Authorization": f"Bearer {token_b.replace('Bearer ', '').strip()}"}

        try:
            # 1. Access as Victim (User A)
            res_a = await client.get(endpoint_url, headers=headers_a)
            if res_a.status_code not in [200, 201]:
                return {
                    "vulnerable": False,
                    "status": "safe",
                    "details": f"Endpoint returned HTTP {res_a.status_code} for Token A (no baseline data to cross-test).",
                    "victim_status": res_a.status_code,
                    "attacker_status": None,
                }

            # 2. Replay as Attacker (User B)
            res_b = await client.get(endpoint_url, headers=headers_b)

            # If Attacker also gets 200 OK with data:
            if res_b.status_code == 200:
                # Compare responses: if both return data without tenant separation
                return {
                    "vulnerable": True,
                    "status": "vulnerable",
                    "severity": "CRITICAL",
                    "details": "CRITICAL BOLA (API1:2023): User B successfully accessed User A's private resource without receiving 403 Forbidden.",
                    "victim_status": res_a.status_code,
                    "attacker_status": res_b.status_code,
                    "evidence": {
                        "endpoint": endpoint_url,
                        "token_a_response_length": len(res_a.text),
                        "token_b_response_length": len(res_b.text),
                        "sample_leak": res_b.text[:150]
                    },
                    "recommendation": "Enforce object-level tenancy checks: verify `resource.owner_id == current_user.id` before returning data."
                }
            elif res_b.status_code in [401, 403, 404]:
                return {
                    "vulnerable": False,
                    "status": "safe",
                    "severity": "INFO",
                    "details": f"Proper Authorization Enforced: Server rejected User B with HTTP {res_b.status_code}.",
                    "victim_status": res_a.status_code,
                    "attacker_status": res_b.status_code,
                }
            else:
                return {
                    "vulnerable": False,
                    "status": "info",
                    "details": f"Attacker received status {res_b.status_code}.",
                    "victim_status": res_a.status_code,
                    "attacker_status": res_b.status_code,
                }

        except Exception as e:
            return {
                "vulnerable": False,
                "status": "error",
                "details": f"BOLA test error: {str(e)}"
            }
        finally:
            if should_close:
                await client.aclose()

