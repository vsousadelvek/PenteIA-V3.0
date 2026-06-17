from fastapi import APIRouter, File, UploadFile, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import uuid
import json

# Models
class EvasionTechnique(BaseModel):
    id: str
    name: str
    description: str
    category: str
    risk_level: str


class TestTechniqueRequest(BaseModel):
    technique: str


class TestTechniqueResponse(BaseModel):
    success: bool
    technique: str
    output: str
    timestamp: str


class PayloadUpload(BaseModel):
    name: str
    type: str
    file: Optional[str] = None


class Payload(BaseModel):
    id: str
    user_id: str
    name: str
    type: str
    size: int
    created_at: str
    updated_at: str


class ExecuteEvasionRequest(BaseModel):
    technique: str
    target: str


class ExecuteEvasionResponse(BaseModel):
    success: bool
    technique: str
    target: str
    result: str
    timestamp: str


# Hardcoded techniques database
EVASION_TECHNIQUES = {
    "edr_evasion": {
        "id": "edr_evasion",
        "name": "EDR Evasion",
        "description": "Bypass Endpoint Detection and Response systems",
        "category": "Detection Bypass",
        "risk_level": "High"
    },
    "memory_evasion": {
        "id": "memory_evasion",
        "name": "Memory Evasion",
        "description": "Evade memory-based detection mechanisms",
        "category": "Memory Protection",
        "risk_level": "High"
    },
    "telemetry_bypass": {
        "id": "telemetry_bypass",
        "name": "Telemetry Bypass",
        "description": "Disable or bypass telemetry collection",
        "category": "Telemetry",
        "risk_level": "Critical"
    },
    "sandbox_detection": {
        "id": "sandbox_detection",
        "name": "Sandbox Detection",
        "description": "Detect and evade sandbox environments",
        "category": "Environment Detection",
        "risk_level": "Medium"
    }
}

# Mock storage for payloads (in-memory, replace with database in production)
payloads_storage: dict = {}


# Mock output generators for test responses
def generate_edr_evasion_output() -> str:
    return json.dumps({
        "status": "success",
        "technique": "EDR Evasion",
        "methods_applied": [
            "Disabled Windows Defender Real-time Protection",
            "Removed EDR hooks from kernel",
            "Cleaned execution logs"
        ],
        "detection_risk": "LOW",
        "execution_time_ms": 245
    }, indent=2)


def generate_memory_evasion_output() -> str:
    return json.dumps({
        "status": "success",
        "technique": "Memory Evasion",
        "methods_applied": [
            "Allocated memory in heap gaps",
            "Applied code obfuscation",
            "Encrypted payload in memory"
        ],
        "memory_signature": "CLEAN",
        "execution_time_ms": 189
    }, indent=2)


def generate_telemetry_bypass_output() -> str:
    return json.dumps({
        "status": "success",
        "technique": "Telemetry Bypass",
        "methods_applied": [
            "Disabled ETW tracing",
            "Removed WMI event subscriptions",
            "Cleared event logs"
        ],
        "telemetry_channels": "DISABLED",
        "execution_time_ms": 156
    }, indent=2)


def generate_sandbox_detection_output() -> str:
    return json.dumps({
        "status": "detected",
        "technique": "Sandbox Detection",
        "indicators": [
            "VM artifact detected: QEMU",
            "Sandbox process signature found",
            "Unusual system resource allocation"
        ],
        "environment": "SANDBOX",
        "evasion_applied": True,
        "execution_time_ms": 78
    }, indent=2)


def get_mock_output(technique_id: str) -> str:
    """Generate mock output based on technique"""
    outputs = {
        "edr_evasion": generate_edr_evasion_output,
        "memory_evasion": generate_memory_evasion_output,
        "telemetry_bypass": generate_telemetry_bypass_output,
        "sandbox_detection": generate_sandbox_detection_output
    }

    output_func = outputs.get(technique_id, lambda: json.dumps({"error": "Unknown technique"}))
    return output_func()


# Router
router = APIRouter(prefix="/api/evasion", tags=["evasion"])


@router.get("/techniques", response_model=List[EvasionTechnique])
async def list_techniques():
    """
    GET /api/evasion/techniques
    Returns list of available evasion techniques
    """
    return [EvasionTechnique(**tech) for tech in EVASION_TECHNIQUES.values()]


@router.post("/test", response_model=TestTechniqueResponse)
async def test_technique(request: TestTechniqueRequest):
    """
    POST /api/evasion/test
    Test an evasion technique and return mock output
    """
    if request.technique not in EVASION_TECHNIQUES:
        raise HTTPException(status_code=404, detail="Technique not found")

    output = get_mock_output(request.technique)

    return TestTechniqueResponse(
        success=True,
        technique=request.technique,
        output=output,
        timestamp=datetime.utcnow().isoformat()
    )


@router.post("/payloads")
async def upload_payload(
    user_id: str = Query(..., description="User ID"),
    name: str = Query(..., description="Payload name"),
    type: str = Query(..., description="Payload type (C, ASM, C#)"),
    file: UploadFile = File(...)
):
    """
    POST /api/evasion/payloads
    Upload a payload file
    """
    if type not in ["C", "ASM", "C#"]:
        raise HTTPException(status_code=400, detail="Invalid payload type. Must be C, ASM, or C#")

    # Read file content
    content = await file.read()

    # Create payload record
    payload_id = str(uuid.uuid4())
    payload = {
        "id": payload_id,
        "user_id": user_id,
        "name": name,
        "type": type,
        "size": len(content),
        "content": content,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }

    payloads_storage[payload_id] = payload

    return {
        "id": payload_id,
        "user_id": user_id,
        "name": name,
        "type": type,
        "size": len(content),
        "created_at": payload["created_at"],
        "message": "Payload uploaded successfully"
    }


@router.get("/payloads", response_model=List[Payload])
async def list_payloads(user_id: str = Query(..., description="User ID")):
    """
    GET /api/evasion/payloads
    List all payloads for a user
    """
    user_payloads = [
        Payload(
            id=p["id"],
            user_id=p["user_id"],
            name=p["name"],
            type=p["type"],
            size=p["size"],
            created_at=p["created_at"],
            updated_at=p["updated_at"]
        )
        for p in payloads_storage.values()
        if p["user_id"] == user_id
    ]
    return user_payloads


@router.get("/payloads/{payload_id}/download")
async def download_payload(
    payload_id: str,
    user_id: str = Query(..., description="User ID")
):
    """
    GET /api/evasion/payloads/{payload_id}/download
    Download a payload file
    """
    payload = payloads_storage.get(payload_id)

    if not payload:
        raise HTTPException(status_code=404, detail="Payload not found")

    if payload["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Unauthorized access to payload")

    from fastapi.responses import FileResponse
    import tempfile
    import os

    # Create temporary file to return
    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{payload['type'].lower()}") as tmp:
        tmp.write(payload["content"])
        tmp_path = tmp.name

    return FileResponse(
        path=tmp_path,
        filename=payload["name"],
        media_type="application/octet-stream"
    )


@router.delete("/payloads/{payload_id}")
async def delete_payload(
    payload_id: str,
    user_id: str = Query(..., description="User ID")
):
    """
    DELETE /api/evasion/payloads/{payload_id}
    Delete a payload
    """
    payload = payloads_storage.get(payload_id)

    if not payload:
        raise HTTPException(status_code=404, detail="Payload not found")

    if payload["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Unauthorized access to payload")

    del payloads_storage[payload_id]

    return {"message": "Payload deleted successfully", "payload_id": payload_id}


@router.post("/execute", response_model=ExecuteEvasionResponse)
async def execute_evasion(request: ExecuteEvasionRequest):
    """
    POST /api/evasion/execute
    Execute an evasion technique against a target
    """
    if request.technique not in EVASION_TECHNIQUES:
        raise HTTPException(status_code=404, detail="Technique not found")

    if not request.target:
        raise HTTPException(status_code=400, detail="Target is required")

    output = get_mock_output(request.technique)

    return ExecuteEvasionResponse(
        success=True,
        technique=request.technique,
        target=request.target,
        result=output,
        timestamp=datetime.utcnow().isoformat()
    )
