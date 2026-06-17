# API Usage Examples

import requests
import json

BASE_URL = "http://localhost:8000/api/evasion"

# Example 1: List available techniques
def list_techniques():
    """GET /api/evasion/techniques"""
    response = requests.get(f"{BASE_URL}/techniques")
    print("Available Techniques:")
    print(json.dumps(response.json(), indent=2))
    return response.json()


# Example 2: Test a technique
def test_technique(technique: str):
    """POST /api/evasion/test"""
    payload = {"technique": technique}
    response = requests.post(f"{BASE_URL}/test", json=payload)
    print(f"\nTest Result for {technique}:")
    print(json.dumps(response.json(), indent=2))
    return response.json()


# Example 3: Upload a payload
def upload_payload(user_id: str, name: str, payload_type: str, file_path: str):
    """POST /api/evasion/payloads"""
    with open(file_path, "rb") as f:
        files = {"file": (file_path, f, "application/octet-stream")}
        params = {
            "user_id": user_id,
            "name": name,
            "type": payload_type
        }
        response = requests.post(f"{BASE_URL}/payloads", files=files, params=params)

    print(f"\nPayload Upload Result:")
    print(json.dumps(response.json(), indent=2))
    return response.json()


# Example 4: List user payloads
def list_payloads(user_id: str):
    """GET /api/evasion/payloads"""
    params = {"user_id": user_id}
    response = requests.get(f"{BASE_URL}/payloads", params=params)
    print(f"\nPayloads for user {user_id}:")
    print(json.dumps(response.json(), indent=2))
    return response.json()


# Example 5: Download a payload
def download_payload(payload_id: str, user_id: str, output_path: str):
    """GET /api/evasion/payloads/{payload_id}/download"""
    params = {"user_id": user_id}
    response = requests.get(f"{BASE_URL}/payloads/{payload_id}/download", params=params)

    with open(output_path, "wb") as f:
        f.write(response.content)

    print(f"\nPayload downloaded to {output_path}")
    return response.status_code


# Example 6: Delete a payload
def delete_payload(payload_id: str, user_id: str):
    """DELETE /api/evasion/payloads/{payload_id}"""
    params = {"user_id": user_id}
    response = requests.delete(f"{BASE_URL}/payloads/{payload_id}", params=params)
    print(f"\nDelete Result:")
    print(json.dumps(response.json(), indent=2))
    return response.json()


# Example 7: Execute evasion against target
def execute_evasion(technique: str, target: str):
    """POST /api/evasion/execute"""
    payload = {
        "technique": technique,
        "target": target
    }
    response = requests.post(f"{BASE_URL}/execute", json=payload)
    print(f"\nExecution Result:")
    print(json.dumps(response.json(), indent=2))
    return response.json()


# Full workflow example
def full_workflow():
    """Complete workflow example"""
    user_id = "user_12345"

    print("=" * 60)
    print("EVASION API - FULL WORKFLOW EXAMPLE")
    print("=" * 60)

    # 1. List techniques
    techniques = list_techniques()

    # 2. Test EDR Evasion
    test_result = test_technique("edr_evasion")

    # 3. Create a dummy payload for upload
    dummy_payload = b"void main() { /* malicious code */ }"
    with open("temp_payload.c", "wb") as f:
        f.write(dummy_payload)

    # 4. Upload payload
    upload_result = upload_payload(user_id, "Test Payload", "C", "temp_payload.c")
    payload_id = upload_result.get("id")

    # 5. List user payloads
    payloads = list_payloads(user_id)

    # 6. Download payload
    if payload_id:
        download_payload(payload_id, user_id, "downloaded_payload.c")

    # 7. Execute evasion technique
    exec_result = execute_evasion("memory_evasion", "192.168.1.100")

    # 8. Delete payload
    if payload_id:
        delete_payload(payload_id, user_id)

    print("\n" + "=" * 60)
    print("WORKFLOW COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    # Run the full workflow
    # Uncomment the line below to execute (requires running FastAPI server)
    # full_workflow()

    print("API Examples Module")
    print("Call specific functions or full_workflow() to test the API")
