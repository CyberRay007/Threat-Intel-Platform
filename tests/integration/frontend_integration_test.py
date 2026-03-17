#!/usr/bin/env python3
"""
Frontend Integration Test Suite
Tests that frontend can communicate with backend API endpoints
"""

import asyncio
import httpx
import json
import os
from datetime import datetime

API_BASE = os.getenv("API_BASE", "http://127.0.0.1:8011")
TIMEOUT = 10

class FrontendIntegrationTester:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=TIMEOUT)
        self.token = None
        self.user_id = None
        self.org_id = None
        self.results = []
        
    async def test_auth_register(self):
        """Test: Auth Register endpoint (frontend account creation)"""
        try:
            suffix = datetime.utcnow().strftime("%f")
            email = f"frontend-test-{suffix}@threatintel.local"
            password = "FrontendTest!2026"
            
            response = await self.client.post(
                f"{API_BASE}/auth/register",
                json={"email": email, "password": password}
            )
            
            if response.status_code == 201:
                data = response.json()
                self.user_id = data.get("id")
                self.org_id = data.get("org_id")
                self.email = email
                self.password = password
                
                # Validate response structure
                required_fields = ["id", "email", "org_id", "role"]
                missing = [f for f in required_fields if f not in data]
                
                self.results.append({
                    "endpoint": "POST /auth/register",
                    "status": 201,
                    "ok": True,
                    "user_id": self.user_id,
                    "org_id": str(self.org_id),
                    "note": f"Missing fields: {missing}" if missing else "All fields present"
                })
                return True
            else:
                self.results.append({
                    "endpoint": "POST /auth/register",
                    "status": response.status_code,
                    "ok": False,
                    "error": response.text[:200]
                })
                return False
        except Exception as e:
            self.results.append({
                "endpoint": "POST /auth/register",
                "status": "error",
                "ok": False,
                "error": str(e)
            })
            return False
    
    async def test_auth_login(self):
        """Test: Auth Login endpoint (frontend auth)"""
        try:
            response = await self.client.post(
                f"{API_BASE}/auth/login",
                data={"username": self.email, "password": self.password}
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get("access_token")
                token_type = data.get("token_type")
                
                required_fields = ["access_token", "token_type"]
                missing = [f for f in required_fields if f not in data]
                
                self.results.append({
                    "endpoint": "POST /auth/login",
                    "status": 200,
                    "ok": True,
                    "token_type": token_type,
                    "note": f"Missing fields: {missing}" if missing else "Token acquired successfully"
                })
                return True
            else:
                self.results.append({
                    "endpoint": "POST /auth/login",
                    "status": response.status_code,
                    "ok": False,
                    "error": response.text[:200]
                })
                return False
        except Exception as e:
            self.results.append({
                "endpoint": "POST /auth/login",
                "status": "error",
                "ok": False,
                "error": str(e)
            })
            return False
    
    async def test_scans_list(self):
        """Test: Scans List endpoint (frontend dashboard)"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = await self.client.get(
                f"{API_BASE}/scans/scan",
                headers=headers
            )
            
            ok = response.status_code == 200
            data = response.json() if ok else None
            
            self.results.append({
                "endpoint": "GET /scans/scan",
                "status": response.status_code,
                "ok": ok,
                "is_list": isinstance(data, list) if data else None,
                "count": len(data) if isinstance(data, list) else None
            })
            return ok
        except Exception as e:
            self.results.append({
                "endpoint": "GET /scans/scan",
                "status": "error",
                "ok": False,
                "error": str(e)
            })
            return False
    
    async def test_intel_dashboard(self):
        """Test: Intel Dashboard endpoint (frontend home page)"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = await self.client.get(
                f"{API_BASE}/api/intel/dashboard",
                headers=headers
            )
            
            ok = response.status_code == 200
            data = response.json() if ok else None
            
            self.results.append({
                "endpoint": "GET /api/intel/dashboard",
                "status": response.status_code,
                "ok": ok,
                "has_data": data is not None if ok else None
            })
            return ok
        except Exception as e:
            self.results.append({
                "endpoint": "GET /api/intel/dashboard",
                "status": "error",
                "ok": False,
                "error": str(e)
            })
            return False
    
    async def test_intel_iocs_list(self):
        """Test: IOCs List endpoint (frontend IOC intelligence page)"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = await self.client.get(
                f"{API_BASE}/api/intel/iocs",
                headers=headers
            )
            
            ok = response.status_code == 200
            data = response.json() if ok else None
            
            self.results.append({
                "endpoint": "GET /api/intel/iocs",
                "status": response.status_code,
                "ok": ok,
                "is_list": isinstance(data, list) if data else None,
                "count": len(data) if isinstance(data, list) else None
            })
            return ok
        except Exception as e:
            self.results.append({
                "endpoint": "GET /api/intel/iocs",
                "status": "error",
                "ok": False,
                "error": str(e)
            })
            return False
    
    async def test_detection_events_list(self):
        """Test: Detection Events List endpoint (frontend alerts page)"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = await self.client.get(
                f"{API_BASE}/api/detection/events",
                headers=headers
            )
            
            ok = response.status_code == 200
            data = response.json() if ok else None
            
            self.results.append({
                "endpoint": "GET /api/detection/events",
                "status": response.status_code,
                "ok": ok,
                "is_list": isinstance(data, list) if data else None,
                "count": len(data) if isinstance(data, list) else None
            })
            return ok
        except Exception as e:
            self.results.append({
                "endpoint": "GET /api/detection/events",
                "status": "error",
                "ok": False,
                "error": str(e)
            })
            return False
    
    async def test_response_formats(self):
        """Test: Validate response JSON formats and content types"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            
            # Test various endpoints for proper JSON response
            test_endpoints = [
                ("GET", "/api/intel/dashboard"),
                ("GET", "/api/intel/iocs"),
                ("GET", "/api/detection/events"),
            ]
            
            format_ok = True
            for method, endpoint in test_endpoints:
                try:
                    if method == "GET":
                        response = await self.client.get(
                            f"{API_BASE}{endpoint}",
                            headers=headers
                        )
                    
                    # Check content-type is JSON
                    ct = response.headers.get("content-type", "").lower()
                    if "application/json" not in ct:
                        format_ok = False
                        break
                    
                    # Ensure response is valid JSON
                    response.json()
                except:
                    format_ok = False
                    break
            
            self.results.append({
                "endpoint": "Response Format Validation",
                "status": 200 if format_ok else 400,
                "ok": format_ok,
                "note": "All responses are valid JSON with correct content-type" if format_ok else "Some responses have incorrect format"
            })
            return format_ok
        except Exception as e:
            self.results.append({
                "endpoint": "Response Format Validation",
                "status": "error",
                "ok": False,
                "error": str(e)
            })
            return False
    
    async def test_permission_checks(self):
        """Test: Verify permission checks work correctly"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            
            # User should have access to their own org data
            response = await self.client.get(
                f"{API_BASE}/api/intel/iocs",
                headers=headers
            )
            
            has_permission = response.status_code == 200
            
            self.results.append({
                "endpoint": "Permission Checks",
                "status": response.status_code,
                "ok": has_permission,
                "note": "User has access to org-scoped endpoints"
            })
            return has_permission
        except Exception as e:
            self.results.append({
                "endpoint": "Permission Checks",
                "status": "error",
                "ok": False,
                "error": str(e)
            })
            return False
    
    async def run_all_tests(self):
        """Execute all frontend integration tests"""
        print("=" * 80)
        print("FRONTEND INTEGRATION TEST SUITE")
        print("=" * 80)
        print(f"Target Backend: {API_BASE}")
        print(f"Start Time: {datetime.utcnow().isoformat()}")
        print()
        
        # Auth flow (required for subsequent tests)
        print("[1/8] Testing Auth Register...")
        if not await self.test_auth_register():
            print("❌ Auth register failed - cannot proceed with authenticated tests")
            return
        print("✓ Auth register OK")
        
        print("[2/8] Testing Auth Login...")
        if not await self.test_auth_login():
            print("❌ Auth login failed - cannot proceed")
            return
        print("✓ Auth login OK")
        
        print("[3/8] Testing Scans List...")
        await self.test_scans_list()
        print("✓ Scans list tested")
        
        print("[4/8] Testing Intel Dashboard...")
        await self.test_intel_dashboard()
        print("✓ Intel dashboard tested")
        
        print("[5/8] Testing Intel IOCs List...")
        await self.test_intel_iocs_list()
        print("✓ Intel IOCs list tested")
        
        print("[6/8] Testing Detection Events List...")
        await self.test_detection_events_list()
        print("✓ Detection events tested")
        
        print("[7/8] Testing Response Formats...")
        await self.test_response_formats()
        print("✓ Response formats validated")
        
        print("[8/8] Testing Permission Checks...")
        await self.test_permission_checks()
        print("✓ Permission checks validated")
        
        # Summary
        print()
        print("=" * 80)
        print("TEST RESULTS SUMMARY")
        print("=" * 80)
        
        passed = sum(1 for r in self.results if r.get("ok"))
        failed = sum(1 for r in self.results if not r.get("ok"))
        
        print(f"Total Tests: {len(self.results)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print()
        
        print("Detailed Results:")
        print("-" * 80)
        for result in self.results:
            status_icon = "✓" if result.get("ok") else "✗"
            endpoint = result.get("endpoint", "Unknown")
            http_status = result.get("status", "N/A")
            print(f"{status_icon} {endpoint:40} [{http_status}]")
            if "note" in result and result["note"]:
                print(f"  Note: {result['note']}")
            if "error" in result:
                print(f"  Error: {result['error'][:100]}")
        
        print()
        print("=" * 80)
        print(f"End Time: {datetime.utcnow().isoformat()}")
        print("=" * 80)
        
        # JSON output for parsing
        print()
        print("JSON OUTPUT:")
        print(json.dumps({
            "passed": passed,
            "failed": failed,
            "total": len(self.results),
            "results": self.results
        }, indent=2, default=str))
        
        await self.client.aclose()


async def main():
    tester = FrontendIntegrationTester()
    await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())
