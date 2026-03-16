"""
Example usage for testing the DECIPHER suspicious login analyzer.

Demonstrates two testing approaches:
1. Direct analyzer usage (local testing without REST API)
2. REST API testing via HTTP requests (integration testing)
"""
import json
import httpx
from decipher.analyzers.registry import AnalyzerRegistry
from decipher.commons.log_utils import setup_logging, get_logger


setup_logging(enable_file_logging=False)  # Console only for testing
logger = get_logger(__name__)

# Example Wazuh alert data
alert_data = {
    "username": "admin", 
    # "username": "auth-server",
    "target_host": "10.0.0.1",
    # "target_host": "10.0.0.8",
    # "src_ips": ["185.220.100.42", "45.155.204.30"], 
    # "src_ips": ["130.0.0.33"],
    "src_ips": ["146.112.61.105"],
    "timestamp": "2026-02-11T14:30:00Z"
}

# ---------------------------------------------
# EXAMPLE USAGE - LOCAL TESTING
# ---------------------------------------------
def test_analyzer_direct():
    """Test analyzer directly without REST API (useful for development)."""
    print("=" * 60)
    print("TEST 1: Direct Analyzer Testing (No REST API)")
    print("=" * 60)
    
    print(f"\nAlert Data:")
    print(json.dumps(alert_data, indent=2))
    
    try:
        # Use AnalyzerRegistry to validate and analyze
        analysis = AnalyzerRegistry.analyze("suspicious_login", alert_data)
        
        print(f"\nAnalysis Completed Successfully")
        print(f"\nResults:")
        print(analysis)   
    except ValueError as e:
        logger.exception(f"Error: Unknown analyzer type: {e}")
    except Exception as e:
        print(f"\nAnalysis failed: {e}")
        import traceback
        traceback.print_exc()


# ---------------------------------------------
# EXAMPLE USAGE - REST API TESTING
# ---------------------------------------------
def test_via_rest_api(base_url: str = "http://host.docker.internal:8000"):
    """Test the DECIPHER REST service via HTTP requests."""
    print("\n" + "=" * 60)
    print("TEST 2: REST API Testing (Integration Test)")
    print("=" * 60)
    print(f"\nAPI Base URL: {base_url}")
    
    print(f"\nAlert Data:")
    print(json.dumps(alert_data, indent=2))
    
    try:
        # Test 1: List available analyzers
        print(f"\n🔍 Step 1: Discovering available analyzers...")
        response = httpx.get(f"{base_url}/api/v0.1/analyzers", timeout=5.0)
        
        if response.status_code == 200:
            analyzers = response.json()
            print(f"Found {len(analyzers)} analyzer(s): {', '.join(analyzers.keys())}")
        else:
            print(f"Could not list analyzers: {response.status_code}")
        
        # Test 2: Analyze the alert
        print(f"\nStep 2: Analyzing suspicious login alert...")
        response = httpx.post(
            f"{base_url}/api/v0.1/analyze/suspicious_login",
            json=alert_data,
            timeout=10.0
        )
        
        if response.status_code == 200:
            result = response.json()
            
            print(f"\nAnalysis Completed Successfully")
            print(f"\nResults: {result}")

            print(f"Case created: {result.get('created_case')}")
            
            print(f"\nAnalysis Details:")
            analysis = result.get('report', {})
            print(json.dumps(analysis, indent=2))
        elif response.status_code == 404:
            print(f"Error 404: Analyzer not found")
            print(f"   {response.json()}")
        elif response.status_code == 400:
            print(f"Error 400: Invalid alert data")
            print(f"   {json.dumps(response.json(), indent=2)}")
        else:
            print(f"Error {response.status_code}: {response.text}")
            
    except httpx.ConnectError:
        print(f"\nConnection Error: Could not connect to {base_url}")
        print(f"   Make sure DECIPHER service is running:")
        print(f"   $ poetry run uvicorn decipher.api:app --host 0.0.0.0 --port 8000")
    except httpx.TimeoutException:
        print(f"\nTimeout: Request took too long")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()


# ---------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------
def main():
    """Run both test scenarios."""
    print("\nDECIPHER Suspicious Login Analyzer - Test Suite")
    
    # Test 1: Direct analyzer testing
    test_analyzer_direct()
    
    # Test 2: REST API testing
    print("\n")
    test_via_rest_api()
    
    print("\n" + "=" * 60)
    print("Test Suite Completed")
    print("=" * 60)


if __name__ == "__main__":
    main()
