"""
Example usage for testing the DECIPHER incident creation endpoint.

Demonstrates incident case creation in Flowintel using the /incident/{alert_type} endpoint
with a RADAR case bundle including score, title, and additional metadata.
"""
import json
from pathlib import Path
import httpx
from pyflowintel import PyFlowintel
from decipher.commons.log_utils import setup_logging, get_logger
from decipher.settings import DECIPHER_CONFIG_PATH, API_VERSION


setup_logging(enable_file_logging=False)  # Console only for testing
logger = get_logger(__name__)

# Load RADAR case bundle from test data
RADAR_BUNDLE_PATH = Path(__file__).parent.parent / "data" / "radar-case-bundle.json"


def test_incident_creation_api(base_url: str = "http://host.docker.internal:8000"):
    """Test the DECIPHER incident creation endpoint via HTTP requests."""
    print(f"\nAPI Base URL: {base_url}")
    
    # Load case bundle
    with open(RADAR_BUNDLE_PATH, "r") as f:
        incident_data = json.load(f)

    print(f"\nLoaded case bundle from {RADAR_BUNDLE_PATH.name}:")
    print(json.dumps(incident_data, indent=2))
    
    try:
        # Test 1: Create incident case
        print(f"\nStep 1: Creating incident case for 'suspicious_login' scenario...")
        print(f"\nIncident Request Data:")
        print(f"  Priority: {incident_data['priority_level']}")
        print(f"  Title: {incident_data['title']}")
        
        response = httpx.post(
            f"{base_url}/api/{API_VERSION}/incident",
            json=incident_data,
            timeout=8
        )
        
        if response.status_code == 200:
            result = response.json()
            
            print(f"\nIncident Case Created Successfully")
            print(f"\nResponse:")
            print(json.dumps(result, indent=2))
            
        elif response.status_code == 422:
            print(f"\nError 422: Invalid incident data")
            print(f"   {json.dumps(response.json(), indent=2)}")
        elif response.status_code == 500:
            print(f"\nError 500: Flowintel case creation failed")
            print(f"   {json.dumps(response.json(), indent=2)}")
        else:
            print(f"\nError {response.status_code}: {response.text}")
    except httpx.TimeoutException:
        print(f"\nTimeout: Request took too long")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Run incident creation test."""
    print("\nDECIPHER Incident Creation Endpoint - Test")
    test_incident_creation_api()
    print("Test Completed")

    # with PyFlowintel.from_config(str(DECIPHER_CONFIG_PATH)) as client:
    #     ids = [e.get("id") for e in client.cases.list_all()]

    #     for r in ids:
    #         if r in range(213, 236):
    #             try:
    #                 client.cases.delete(r)
    #             except Exception as e:
    #                 print(e)
    #                 continue


if __name__ == "__main__":
    main()
