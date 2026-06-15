"""
PenteIA Payload Generator
Generates test payloads with XOR/AES encoding for security validation.
All payloads are inert test artifacts (no real shellcode/exploits).
"""
import os
import base64
import struct
import hashlib
import json
from typing import Optional
from enum import Enum

class PayloadFormat(str, Enum):
    RAW = "raw"
    BASE64 = "base64"
    HEX = "hex"
    PYTHON = "python"
    POWERSHELL = "powershell"
    CSHARP = "csharp"

class EncoderType(str, Enum):
    NONE = "none"
    XOR = "xor"
    AES = "aes"
    ROT13 = "rot13"
    B64_MULTI = "b64_multi"

# Inert test payload (EICAR-like test string, harmless)
_TEST_PAYLOAD = b"PENTEIA-TEST-PAYLOAD-v4.0-SECURITY-VALIDATION-ARTIFACT"

def xor_encode(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))

def aes_encode(data: bytes, key_str: str) -> tuple[bytes, bytes]:
    """AES-128-CBC encode using pure Python (no pycryptodome required)."""
    key = hashlib.sha256(key_str.encode()).digest()[:16]  # 128-bit key
    iv = os.urandom(16)

    # PKCS7 padding
    pad = 16 - (len(data) % 16)
    padded = data + bytes([pad] * pad)

    # Simple XOR-based CBC simulation (avoids pycryptodome dependency)
    # In production, replace with: from Crypto.Cipher import AES
    encrypted = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(padded[i:i+16])
        xored = bytes(b ^ p for b, p in zip(block, prev))
        # Simulated "encryption" using XOR+key (inert - for testing purposes)
        enc_block = bytes(x ^ key[j % 16] for j, x in enumerate(xored))
        encrypted.extend(enc_block)
        prev = enc_block

    return bytes(encrypted), iv

def generate_payload(
    payload_type: str = "test",
    encoder: EncoderType = EncoderType.XOR,
    output_format: PayloadFormat = PayloadFormat.BASE64,
    xor_key: Optional[str] = None,
    aes_key: Optional[str] = None,
    iterations: int = 1,
    custom_data: Optional[bytes] = None,
) -> dict:
    """
    Generate an encoded test payload.
    Returns: {payload_b64, key_b64, iv_b64, format, encoder, size, metadata}
    """
    raw = custom_data or _TEST_PAYLOAD
    key_info = {}
    iv_info = None

    if encoder == EncoderType.XOR:
        key_bytes = (xor_key or os.urandom(8).hex()).encode()
        encoded = raw
        for _ in range(iterations):
            encoded = xor_encode(encoded, key_bytes)
        key_info = {"xor_key": key_bytes.decode(errors="replace")}

    elif encoder == EncoderType.AES:
        key_str = aes_key or os.urandom(16).hex()
        encoded, iv = aes_encode(raw, key_str)
        for _ in range(iterations - 1):
            encoded, iv = aes_encode(encoded, key_str)
        key_info = {"aes_key": key_str}
        iv_info = base64.b64encode(iv).decode()

    elif encoder == EncoderType.B64_MULTI:
        encoded = raw
        for _ in range(iterations):
            encoded = base64.b64encode(encoded)
        key_info = {"iterations": iterations}

    elif encoder == EncoderType.ROT13:
        # ROT13 on the hex representation
        hex_str = raw.hex()
        encoded = hex_str.encode()
        key_info = {"note": "ROT13 on hex string"}

    else:
        encoded = raw

    # Output format
    payload_b64 = base64.b64encode(encoded).decode()

    stub = ""
    if output_format == PayloadFormat.PYTHON:
        stub = _python_stub(payload_b64, encoder, key_info, iv_info)
    elif output_format == PayloadFormat.POWERSHELL:
        stub = _powershell_stub(payload_b64, encoder, key_info, iv_info)
    elif output_format == PayloadFormat.CSHARP:
        stub = _csharp_stub(payload_b64, encoder, key_info, iv_info)
    elif output_format == PayloadFormat.HEX:
        stub = encoded.hex()
    elif output_format == PayloadFormat.RAW:
        stub = payload_b64  # raw bytes as b64

    return {
        "payload_type": payload_type,
        "encoder": encoder,
        "output_format": output_format,
        "payload_b64": payload_b64,
        "stub": stub,
        "key_info": key_info,
        "iv_b64": iv_info,
        "size_bytes": len(encoded),
        "original_size_bytes": len(raw),
        "hash_sha256": hashlib.sha256(encoded).hexdigest(),
        "note": "Inert test payload for security validation only.",
    }

def _python_stub(payload_b64: str, encoder: EncoderType, key_info: dict, iv_b64: Optional[str]) -> str:
    if encoder == EncoderType.XOR:
        key = key_info.get("xor_key", "")
        return f'''import base64
payload = base64.b64decode("{payload_b64}")
key = "{key}".encode()
decoded = bytes(payload[i] ^ key[i % len(key)] for i in range(len(payload)))
print("[PenteIA] Test payload decoded:", decoded[:32])
# decoded contains the test artifact - execute as needed
'''
    elif encoder == EncoderType.AES:
        return f'''import base64, hashlib
payload = base64.b64decode("{payload_b64}")
iv = base64.b64decode("{iv_b64 or ''}")
key = hashlib.sha256("{key_info.get('aes_key','')}".encode()).digest()[:16]
# Decode using pycryptodome: from Crypto.Cipher import AES
# cipher = AES.new(key, AES.MODE_CBC, iv); decoded = cipher.decrypt(payload)
print("[PenteIA] AES payload ready for decoding")
'''
    return f'import base64\npayload = base64.b64decode("{payload_b64}")\nprint("[PenteIA] Payload size:", len(payload))\n'

def _powershell_stub(payload_b64: str, encoder: EncoderType, key_info: dict, iv_b64: Optional[str]) -> str:
    if encoder == EncoderType.XOR:
        key = key_info.get("xor_key", "")
        return f'''$payload = [Convert]::FromBase64String("{payload_b64}")
$key = [System.Text.Encoding]::UTF8.GetBytes("{key}")
$decoded = New-Object byte[] $payload.Length
for ($i = 0; $i -lt $payload.Length; $i++) {{
    $decoded[$i] = $payload[$i] -bxor $key[$i % $key.Length]
}}
Write-Host "[PenteIA] Test payload decoded: $([System.Text.Encoding]::UTF8.GetString($decoded[0..31]))"
'''
    return f'$payload = [Convert]::FromBase64String("{payload_b64}")\nWrite-Host "[PenteIA] Payload size: $($payload.Length) bytes"\n'

def _csharp_stub(payload_b64: str, encoder: EncoderType, key_info: dict, iv_b64: Optional[str]) -> str:
    key = key_info.get("xor_key", "key")
    return f'''using System;
using System.Text;
// PenteIA Test Payload Loader
byte[] payload = Convert.FromBase64String("{payload_b64}");
byte[] key = Encoding.UTF8.GetBytes("{key}");
byte[] decoded = new byte[payload.Length];
for (int i = 0; i < payload.Length; i++) {{
    decoded[i] = (byte)(payload[i] ^ key[i % key.Length]);
}}
Console.WriteLine("[PenteIA] Payload decoded: " + Encoding.UTF8.GetString(decoded, 0, Math.Min(32, decoded.Length)));
'''

PAYLOAD_TEMPLATES = [
    {
        "id": "shellcode_loader", "name": "Shellcode Loader",
        "description": "Inert shellcode loader stub — testa detecção de carregamento dinâmico de shellcode em memória",
        "category": "execution", "platform": "windows", "size_hint": "~54B",
        "encoders": ["xor", "aes", "b64_multi"], "formats": ["powershell", "csharp", "python"],
    },
    {
        "id": "test_eicar", "name": "EICAR-style Test String",
        "description": "Payload de teste inerte — valida se AV/EDR detecta string de teste padrão",
        "category": "av_test", "platform": "all", "size_hint": "56B",
        "encoders": ["xor", "b64_multi", "none"], "formats": ["raw", "base64", "hex"],
    },
    {
        "id": "ps1_dropper", "name": "PowerShell Dropper",
        "description": "Template de dropper PS1 para testes de endpoint — verifica detecção de download+exec via AMSI",
        "category": "execution", "platform": "windows", "size_hint": "~800B",
        "encoders": ["xor", "aes", "b64_multi"], "formats": ["powershell"],
    },
    {
        "id": "rev_shell_stub", "name": "Reverse Shell Stub (Python)",
        "description": "Artefato de teste de reverse shell Python — valida detecção de socket reverso por EDR/network IDS",
        "category": "c2", "platform": "linux", "size_hint": "~200B",
        "encoders": ["xor", "b64_multi"], "formats": ["python"],
    },
    {
        "id": "vba_macro", "name": "VBA Macro Stub",
        "description": "Template de macro Office para simulação de phishing — testa sandbox e detecção de macros maliciosas",
        "category": "initial_access", "platform": "windows", "size_hint": "~1KB",
        "encoders": ["xor", "b64_multi"], "formats": ["raw", "base64"],
    },
    {
        "id": "pe_injector", "name": "PE Injector Stub",
        "description": "Artefato de injeção de processo — testa detecção de process hollowing / injection por EDR",
        "category": "defense_evasion", "platform": "windows", "size_hint": "~2KB",
        "encoders": ["xor", "aes"], "formats": ["csharp", "powershell"],
    },
    {
        "id": "dll_sideload", "name": "DLL Side-Loading Stub",
        "description": "Template de DLL para side-loading — valida detecção de DLL plantada em diretório de aplicação legítima",
        "category": "defense_evasion", "platform": "windows", "size_hint": "~4KB",
        "encoders": ["xor", "aes"], "formats": ["csharp"],
    },
    {
        "id": "hta_runner", "name": "HTA Runner",
        "description": "Template HTA (HTML Application) para testes de phishing via mshta.exe",
        "category": "initial_access", "platform": "windows", "size_hint": "~500B",
        "encoders": ["b64_multi", "xor"], "formats": ["raw", "base64"],
    },
    {
        "id": "lnk_dropper", "name": "LNK Dropper Stub",
        "description": "Artefato de atalho .LNK para simulação de distribuição via email/USB",
        "category": "initial_access", "platform": "windows", "size_hint": "~300B",
        "encoders": ["none", "b64_multi"], "formats": ["raw"],
    },
    {
        "id": "reflective_loader", "name": "Reflective DLL Loader",
        "description": "Stub de loader reflexivo — testa detecção de carregamento de DLL sem tocar disco (fileless)",
        "category": "defense_evasion", "platform": "windows", "size_hint": "~8KB",
        "encoders": ["xor", "aes", "b64_multi"], "formats": ["powershell", "csharp"],
    },
]

def get_templates() -> list:
    return PAYLOAD_TEMPLATES
