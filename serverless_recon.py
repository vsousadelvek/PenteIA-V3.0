#!/usr/bin/env python
# -*- coding: utf-8 -*-
import http.client
import ssl
import re
import json
import socket
from typing import Dict

_API_PATHS = [
    '/api', '/api/health', '/api/status', '/api/hello', '/api/v1', '/api/v2',
    '/api/user', '/api/users', '/api/auth', '/api/login', '/api/register',
    '/api/products', '/api/search', '/api/contact', '/api/submit', '/api/newsletter',
    '/api/checkout', '/api/cart', '/api/order', '/api/orders', '/api/me',
    '/api/profile', '/api/config', '/api/data', '/api/feed', '/api/posts',
    '/api/comments', '/api/categories', '/api/tags', '/api/settings', '/api/upload',
    '/api/image', '/api/send', '/api/email', '/api/verify', '/api/reset',
    '/api/token', '/api/session', '/api/webhook', '/api/callback',
    '/api/v1/status', '/api/v1/health', '/api/v1/user', '/api/v1/products',
    '/api/v2/status', '/api/v2/health', '/api/graphql', '/api/trpc',
]

_SERVERLESS_HEADERS = {
    'x-vercel-execution-region', 'x-lambda-id', 'x-vercel-id',
    'x-vercel-cache', 'x-aws-request-id', 'x-netlify-id',
}

_PLATFORM_SIGS = {
    'vercel': ['vercel', 'x-vercel-id', 'x-vercel-cache', 'x-vercel-execution-region'],
    'netlify': ['netlify', 'x-netlify-id', 'x-nf-request-id'],
    'aws_lambda': ['x-lambda-id', 'x-aws-request-id', 'x-amzn-requestid'],
    'cloudflare_workers': ['cf-ray', 'cloudflare'],
}


def _make_conn(domain: str, use_ssl: bool):
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(domain, port=443, timeout=3, context=ctx)
    return http.client.HTTPConnection(domain, port=80, timeout=3)


def _head(domain: str, path: str, use_ssl: bool):
    try:
        conn = _make_conn(domain, use_ssl)
        conn.request('HEAD', path, headers={'Host': domain, 'User-Agent': 'Mozilla/5.0'})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, headers
    except Exception:
        return None, {}


def _get_text(domain: str, path: str, use_ssl: bool, max_bytes: int = 32768) -> str:
    try:
        conn = _make_conn(domain, use_ssl)
        conn.request('GET', path, headers={'Host': domain, 'User-Agent': 'Mozilla/5.0'})
        resp = conn.getresponse()
        if resp.status != 200:
            conn.close()
            return ''
        data = resp.read(max_bytes).decode('utf-8', errors='replace')
        conn.close()
        return data
    except Exception:
        return ''


def _detect_platform(headers: dict, server_header: str = '') -> str:
    srv = server_header.lower() if server_header else headers.get('server', '').lower()
    all_h = set(headers.keys()) | {srv}
    for platform, sigs in _PLATFORM_SIGS.items():
        for sig in sigs:
            if sig in all_h or any(sig in v.lower() for v in headers.values()):
                return platform
    return 'unknown'


def _is_serverless(headers: dict) -> bool:
    h_keys = set(headers.keys())
    if h_keys & _SERVERLESS_HEADERS:
        return True
    srv = headers.get('server', '').lower()
    if 'vercel' in srv or 'netlify' in srv or 'lambda' in srv:
        return True
    return False


def _is_cached(headers: dict) -> bool:
    cache_val = headers.get('x-vercel-cache', headers.get('x-cache', '')).upper()
    if 'HIT' in cache_val:
        return True
    cc = headers.get('cache-control', '').lower()
    if 'no-cache' in cc or 'no-store' in cc:
        return False
    age = headers.get('age', '')
    if age and age.isdigit() and int(age) > 0:
        return True
    return False


def _probe_platform(domain: str, use_ssl: bool) -> str:
    status, headers = _head(domain, '/', use_ssl)
    if headers:
        return _detect_platform(headers)
    return 'unknown'


def _extract_paths_from_js(js: str) -> list:
    matches = re.findall(r'["\'](/api/[^"\'?#\s]{1,80})["\']', js)
    return list(set(matches))


def _try_next_manifests(domain: str, use_ssl: bool) -> list:
    routes = []
    # routes manifest
    txt = _get_text(domain, '/_next/routes-manifest.json', use_ssl)
    if txt:
        try:
            data = json.loads(txt)
            for key in ('dynamicRoutes', 'staticRoutes', 'dataRoutes'):
                for r in data.get(key, []):
                    p = r.get('page') or r.get('dataRouteRegex', '')
                    if p and p.startswith('/api'):
                        routes.append(p)
        except Exception:
            pass
    # build manifest
    txt2 = _get_text(domain, '/_next/static/development/_buildManifest.js', use_ssl)
    if not txt2:
        txt2 = _get_text(domain, '/_next/static/chunks/pages/_buildManifest.js', use_ssl)
    if txt2:
        found = re.findall(r'["\'](/[^"\'?#\s]{1,80})["\']', txt2)
        routes += [f for f in found if f.startswith('/api')]
    return list(set(routes))


def find_serverless_endpoints(domain: str, use_ssl: bool = True) -> Dict:
    domain = domain.strip().lower().removeprefix('http://').removeprefix('https://').split('/')[0].split('?')[0]

    platform = _probe_platform(domain, use_ssl)
    next_routes = _try_next_manifests(domain, use_ssl)

    # add next_routes to probe list (deduplicated)
    probe_paths = list(dict.fromkeys(_API_PATHS + [r for r in next_routes if r not in _API_PATHS]))

    endpoints = []
    for path in probe_paths:
        status, headers = _head(domain, path, use_ssl)
        if status is None or status == 404:
            continue
        serverless = _is_serverless(headers)
        cached = _is_cached(headers)
        endpoints.append({
            'path': path,
            'method': 'GET',
            'status': status,
            'cached': cached,
            'serverless': serverless,
            'headers_hint': {k: v for k, v in headers.items() if k in _SERVERLESS_HEADERS},
        })
        if platform == 'unknown' and headers:
            p = _detect_platform(headers)
            if p != 'unknown':
                platform = p

    recommended = [e['path'] for e in endpoints if e['serverless'] and not e['cached']]

    return {
        'platform': platform,
        'endpoints': endpoints,
        'next_routes': next_routes,
        'recommended_targets': recommended,
    }
