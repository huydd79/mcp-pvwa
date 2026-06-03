"""
Standalone connectivity test for CyberArk PVWA MCP Server.
Run via: docker compose run --rm test
"""

import asyncio
import os
import sys
import json
import httpx

PVWA_URL  = os.environ.get("CYBERARK_PVWA_URL", "").rstrip("/")
AUTH_TYPE = os.environ.get("CYBERARK_AUTH_TYPE", "CyberArk")
USERNAME  = os.environ.get("CYBERARK_USERNAME", "")
PASSWORD  = os.environ.get("CYBERARK_PASSWORD", "")
VERIFY_SSL = os.environ.get("CYBERARK_VERIFY_SSL", "true").lower() != "false"

BASE_API = f"{PVWA_URL}/PasswordVault/API"

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"


def check_env() -> bool:
    missing = [v for v in ("CYBERARK_PVWA_URL", "CYBERARK_USERNAME", "CYBERARK_PASSWORD") if not os.environ.get(v)]
    if missing:
        print(f"{FAIL} Missing env vars: {', '.join(missing)}")
        return False
    print(f"{INFO} PVWA URL   : {PVWA_URL}")
    print(f"{INFO} Auth type  : {AUTH_TYPE}")
    print(f"{INFO} Username   : {USERNAME}")
    print(f"{INFO} Verify SSL : {VERIFY_SSL}")
    return True


async def run_tests() -> bool:
    passed = 0
    failed = 0
    token = None

    async with httpx.AsyncClient(verify=VERIFY_SSL, timeout=15) as client:

        # 1. Logon
        print(f"\n--- Test 1: Logon ---")
        try:
            resp = await client.post(
                f"{BASE_API}/auth/{AUTH_TYPE}/Logon",
                json={"username": USERNAME, "password": PASSWORD, "concurrentSession": True},
            )
            resp.raise_for_status()
            token = resp.json()
            print(f"{PASS} Logon OK  (token length: {len(token)} chars)")
            passed += 1
        except Exception as e:
            print(f"{FAIL} Logon FAILED: {e}")
            failed += 1
            return False  # no point continuing without a token

        headers = {"Authorization": token, "Content-Type": "application/json"}

        # 2. System Health Summary
        print(f"\n--- Test 2: System Health Summary ---")
        try:
            resp = await client.get(f"{BASE_API}/ComponentsMonitoringSummary/", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            components = data.get("Components", [])
            print(f"{PASS} Health summary OK  ({len(components)} components)")
            for c in components:
                status = "UP" if c.get("ConnectedComponentCount", 0) > 0 else "DOWN"
                color = "\033[92m" if status == "UP" else "\033[91m"
                print(f"       {color}{status}\033[0m  {c['ComponentName']} "
                      f"({c['ConnectedComponentCount']}/{c['ComponentTotalCount']} connected)")
            passed += 1
        except Exception as e:
            print(f"{FAIL} Health summary FAILED: {e}")
            failed += 1

        # 3. System Health Details (PVWA component)
        print(f"\n--- Test 3: Health Details (PVWA) ---")
        try:
            resp = await client.get(f"{BASE_API}/ComponentsMonitoringDetails/PVWA", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            details = data.get("ComponentsDetails", [])
            if details:
                d = details[0]
                print(f"{PASS} Health details OK")
                print(f"       Version  : {d.get('ComponentVersion')}")
                print(f"       IP       : {d.get('ComponentIP')}")
                print(f"       LoggedOn : {d.get('IsLoggedOn')}")
            passed += 1
        except Exception as e:
            print(f"{FAIL} Health details FAILED: {e}")
            failed += 1

        # 4. Logoff
        print(f"\n--- Test 4: Logoff ---")
        try:
            resp = await client.post(f"{BASE_API}/Auth/Logoff/", headers=headers)
            resp.raise_for_status()
            print(f"{PASS} Logoff OK")
            passed += 1
        except Exception as e:
            print(f"{FAIL} Logoff FAILED: {e}")
            failed += 1

    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
    print(f"{'='*40}\n")
    return failed == 0


async def main() -> None:
    print("\n=== CyberArk PVWA MCP Server — Connection Test ===\n")
    if not check_env():
        sys.exit(1)
    ok = await run_tests()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
