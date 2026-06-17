# Evasion API Documentation

## Base URL
```
http://localhost:8000/api/evasion
```

## Endpoints

### 1. GET /techniques
List all available evasion techniques.

**Response:**
```json
[
  {
    "id": "edr_evasion",
    "name": "EDR Evasion",
    "description": "Bypass Endpoint Detection and Response systems",
    "category": "Detection Bypass",
    "risk_level": "High"
  },
  {
    "id": "memory_evasion",
    "name": "Memory Evasion",
    "description": "Evade memory-based detection mechanisms",
    "category": "Memory Protection",
    "risk_level": "High"
  },
  {
    "id": "telemetry_bypass",
    "name": "Telemetry Bypass",
    "description": "Disable or bypass telemetry collection",
    "category": "Telemetry",
    "risk_level": "Critical"
  },
  {
    "id": "sandbox_detection",
    "name": "Sandbox Detection",
    "description": "Detect and evade sandbox environments",
    "category": "Environment Detection",
    "risk_level": "Medium"
  }
]
```

**cURL Example:**
```bash
curl -X GET http://localhost:8000/api/evasion/techniques
```

---

### 2. POST /test
Test an evasion technique and receive mock output.

**Request Body:**
```json
{
  "technique": "edr_evasion"
}
```

**Response:**
```json
{
  "success": true,
  "technique": "edr_evasion",
  "output": "{\n  \"status\": \"success\",\n  \"technique\": \"EDR Evasion\",\n  \"methods_applied\": [\n    \"Disabled Windows Defender Real-time Protection\",\n    \"Removed EDR hooks from kernel\",\n    \"Cleaned execution logs\"\n  ],\n  \"detection_risk\": \"LOW\",\n  \"execution_time_ms\": 245\n}",
  "timestamp": "2024-01-15T10:30:45.123456"
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:8000/api/evasion/test \
  -H "Content-Type: application/json" \
  -d '{"technique": "edr_evasion"}'
```

---

### 3. POST /payloads
Upload a payload file.

**Query Parameters:**
- `user_id` (required): User identifier
- `name` (required): Payload name
- `type` (required): Payload type (C, ASM, C#)
- `file` (required): Binary file to upload

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "user_12345",
  "name": "Test Payload",
  "type": "C",
  "size": 1024,
  "created_at": "2024-01-15T10:30:45.123456",
  "message": "Payload uploaded successfully"
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:8000/api/evasion/payloads \
  -F "file=@/path/to/payload.c" \
  -H "user_id: user_12345" \
  -H "name: Test Payload" \
  -H "type: C"
```

**Using Query Parameters:**
```bash
curl -X POST "http://localhost:8000/api/evasion/payloads?user_id=user_12345&name=Test%20Payload&type=C" \
  -F "file=@/path/to/payload.c"
```

---

### 4. GET /payloads
List all payloads for a user.

**Query Parameters:**
- `user_id` (required): User identifier

**Response:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "user_id": "user_12345",
    "name": "Test Payload",
    "type": "C",
    "size": 1024,
    "created_at": "2024-01-15T10:30:45.123456",
    "updated_at": "2024-01-15T10:30:45.123456"
  }
]
```

**cURL Example:**
```bash
curl -X GET "http://localhost:8000/api/evasion/payloads?user_id=user_12345"
```

---

### 5. GET /payloads/{payload_id}/download
Download a payload file.

**Path Parameters:**
- `payload_id` (required): Payload identifier

**Query Parameters:**
- `user_id` (required): User identifier

**Response:** Binary file content

**cURL Example:**
```bash
curl -X GET "http://localhost:8000/api/evasion/payloads/550e8400-e29b-41d4-a716-446655440000/download?user_id=user_12345" \
  -o downloaded_payload.c
```

---

### 6. DELETE /payloads/{payload_id}
Delete a payload.

**Path Parameters:**
- `payload_id` (required): Payload identifier

**Query Parameters:**
- `user_id` (required): User identifier

**Response:**
```json
{
  "message": "Payload deleted successfully",
  "payload_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**cURL Example:**
```bash
curl -X DELETE "http://localhost:8000/api/evasion/payloads/550e8400-e29b-41d4-a716-446655440000?user_id=user_12345"
```

---

### 7. POST /execute
Execute an evasion technique against a target.

**Request Body:**
```json
{
  "technique": "memory_evasion",
  "target": "192.168.1.100"
}
```

**Response:**
```json
{
  "success": true,
  "technique": "memory_evasion",
  "target": "192.168.1.100",
  "result": "{\n  \"status\": \"success\",\n  \"technique\": \"Memory Evasion\",\n  \"methods_applied\": [\n    \"Allocated memory in heap gaps\",\n    \"Applied code obfuscation\",\n    \"Encrypted payload in memory\"\n  ],\n  \"memory_signature\": \"CLEAN\",\n  \"execution_time_ms\": 189\n}",
  "timestamp": "2024-01-15T10:30:45.123456"
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:8000/api/evasion/execute \
  -H "Content-Type: application/json" \
  -d '{"technique": "memory_evasion", "target": "192.168.1.100"}'
```

---

## Error Responses

### 404 Not Found
```json
{
  "detail": "Technique not found"
}
```

### 400 Bad Request
```json
{
  "detail": "Invalid payload type. Must be C, ASM, or C#"
}
```

### 403 Forbidden
```json
{
  "detail": "Unauthorized access to payload"
}
```

---

## Techniques Available

| ID | Name | Category | Risk Level |
|---|---|---|---|
| `edr_evasion` | EDR Evasion | Detection Bypass | High |
| `memory_evasion` | Memory Evasion | Memory Protection | High |
| `telemetry_bypass` | Telemetry Bypass | Telemetry | Critical |
| `sandbox_detection` | Sandbox Detection | Environment Detection | Medium |

---

## Payload Types

- **C**: C language payloads
- **ASM**: Assembly language payloads
- **C#**: C# language payloads

---

## Integration Steps

1. Install dependencies:
   ```bash
   pip install -r evasion_requirements.txt
   ```

2. Import router in your main FastAPI app:
   ```python
   from evasion import router as evasion_router
   app.include_router(evasion_router)
   ```

3. Run the server:
   ```bash
   uvicorn evasion_integration:app --reload --host 0.0.0.0 --port 8000
   ```

4. Access API documentation:
   - Swagger UI: `http://localhost:8000/docs`
   - ReDoc: `http://localhost:8000/redoc`

---

## Mock Output Structure

Each test returns realistic mock output with execution details:

```json
{
  "status": "success|detected|failed",
  "technique": "Technique Name",
  "methods_applied": ["Method 1", "Method 2"],
  "detection_risk": "LOW|MEDIUM|HIGH",
  "execution_time_ms": 245
}
```
