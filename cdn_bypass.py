#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CDN Bypass / Origin IP Discovery — PenteIA v4.0
Descobre o IP real do servidor por trás de CDNs (Cloudflare, CloudFront, Akamai, etc.)
usando múltiplas fontes: DNS history, crt.sh, MX, SPF, subdomínios comuns.
"""

import socket
import urllib.request
import urllib.error
import json
import re
import ssl
import http.client
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor


def _fetch(url: str, timeout: int = 8) -> Optional[str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode('utf-8', errors='replace')
    except Exception:
        return None


def _doh(name: str, qtype: str) -> List[Dict]:
    """DNS query via Google DNS-over-HTTPS — cross-platform, sem dependências."""
    raw = _fetch(f'https://dns.google/resolve?name={name}&type={qtype}')
    if not raw:
        return []
    try:
        return json.loads(raw).get('Answer', []) or []
    except Exception:
        return []


# ── CDN detection ─────────────────────────────────────────────────────────────

CDN_SERVER_SIGNATURES = {
    'cloudflare': 'Cloudflare', 'cloudflarealwaysonline': 'Cloudflare',
    'awselb': 'AWS ALB', 'amazons3': 'AWS S3',
    'fastly': 'Fastly', 'akamai': 'Akamai',
    'sucuri': 'Sucuri', 'incapsula': 'Imperva/Incapsula',
}

def detect_cdn(domain: str) -> Dict:
    """Detecta se o domínio está atrás de CDN pelos headers HTTP de resposta."""
    result = {'behind_cdn': False, 'cdn': None, 'server': None, 'headers': {}}
    for scheme, cls, port in [('https', http.client.HTTPSConnection, 443), ('http', http.client.HTTPConnection, 80)]:
        try:
            if scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = cls(domain, port, timeout=6, context=ctx)
            else:
                conn = cls(domain, port, timeout=6)
            conn.request('HEAD', '/', headers={'Host': domain, 'User-Agent': 'Mozilla/5.0'})
            resp = conn.getresponse()
            headers = {k.lower(): v.lower() for k, v in resp.getheaders()}
            conn.close()
            result['headers'] = headers
            result['server'] = headers.get('server', '')

            if 'cf-ray' in headers:
                result['behind_cdn'] = True; result['cdn'] = 'Cloudflare'; break
            if 'x-amz-cf-id' in headers:
                result['behind_cdn'] = True; result['cdn'] = 'AWS CloudFront'; break
            if 'x-sucuri-id' in headers or 'x-sucuri-cache' in headers:
                result['behind_cdn'] = True; result['cdn'] = 'Sucuri'; break
            if 'x-akamai-transformed' in headers or 'akamai-grn' in headers:
                result['behind_cdn'] = True; result['cdn'] = 'Akamai'; break
            if 'x-served-by' in headers and 'fastly' in headers.get('x-served-by', ''):
                result['behind_cdn'] = True; result['cdn'] = 'Fastly'; break
            server = headers.get('server', '')
            for sig, name in CDN_SERVER_SIGNATURES.items():
                if sig in server:
                    result['behind_cdn'] = True; result['cdn'] = name; break
            break
        except Exception:
            continue
    return result


# ── Origin discovery sources ──────────────────────────────────────────────────

def get_subdomains_crt(domain: str) -> List[str]:
    """Subdomínios via certificate transparency logs (crt.sh)."""
    raw = _fetch(f'https://crt.sh/?q=%.{domain}&output=json', timeout=12)
    if not raw:
        return []
    try:
        subs = set()
        for entry in json.loads(raw):
            for name in entry.get('name_value', '').split('\n'):
                name = name.strip().lstrip('*.')
                if name.endswith(f'.{domain}') or name == domain:
                    subs.add(name)
        return sorted(subs)
    except Exception:
        return []


def get_dns_history(domain: str) -> List[str]:
    """IPs históricos via HackerTarget API (free tier)."""
    raw = _fetch(f'https://api.hackertarget.com/hostsearch/?q={domain}', timeout=10)
    if not raw or raw.strip().startswith('error') or len(raw) < 10:
        return []
    ips = []
    for line in raw.strip().split('\n'):
        parts = line.split(',')
        if len(parts) >= 2:
            ip = parts[-1].strip()
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                ips.append(ip)
    return list(set(ips))


def get_mx_ips(domain: str) -> List[Tuple[str, str]]:
    """IPs dos servidores MX — frequentemente revelam IP real do hosting."""
    results = []
    for record in _doh(domain, 'MX'):
        mx_host = record.get('data', '').split()[-1].rstrip('.') if record.get('data') else ''
        if not mx_host:
            continue
        try:
            ip = socket.gethostbyname(mx_host)
            results.append((mx_host, ip))
        except Exception:
            pass
    return results


def get_spf_ips(domain: str) -> List[str]:
    """IPs do registro SPF — podem revelar servidor de email/origem."""
    ips = []
    for record in _doh(domain, 'TXT'):
        data = record.get('data', '')
        if 'v=spf1' not in data:
            continue
        for ip in re.findall(r'ip4:([0-9./]+)', data):
            ips.append(ip.split('/')[0])
        for include in re.findall(r'include:(\S+)', data):
            try:
                ips.append(socket.gethostbyname(include.rstrip('.')))
            except Exception:
                pass
    return list(set(ips))


def get_a_records(domain: str) -> List[str]:
    """IPs diretos do domínio (A records)."""
    ips = []
    for r in _doh(domain, 'A'):
        d = r.get('data', '').strip()
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', d):
            ips.append(d)
    return ips


BYPASS_PREFIXES = [
    'mail', 'smtp', 'pop', 'imap', 'ftp', 'cpanel', 'webmail', 'whm',
    'direct', 'origin', 'server', 'host', 'www2', 'ns1', 'ns2', 'admin',
    'remote', 'vpn', 'api', 'dev', 'staging', 'test', 'beta', 'demo',
    'secure', 'portal', 'crm', 'shop', 'store', 'blog', 'media', 'cdn',
    'static', 'assets', 'img', 'files', 'backup', 'old', 'new',
]

def resolve_bypass_subdomains(domain: str, crt_subs: List[str]) -> List[Dict]:
    """Resolve subdomínios comuns que frequentemente bypassam CDN."""
    candidates = set(crt_subs)
    for prefix in BYPASS_PREFIXES:
        candidates.add(f'{prefix}.{domain}')

    def resolve_one(sub):
        try:
            ip = socket.gethostbyname(sub)
            return {'subdomain': sub, 'ip': ip}
        except Exception:
            return None

    results = []
    with ThreadPoolExecutor(max_workers=25) as pool:
        for r in pool.map(resolve_one, list(candidates)):
            if r:
                results.append(r)
    return results


# ── Origin verification ───────────────────────────────────────────────────────

def verify_origin(ip: str, domain: str) -> Dict:
    """Verifica se um IP responde como servidor de origem (sem CDN headers)."""
    result = {'ip': ip, 'open_ports': [], 'responds_http': False, 'behind_cdn': False,
              'server': '', 'status_code': None}

    for port in [80, 443, 8080, 8443]:
        try:
            s = socket.socket(); s.settimeout(2)
            s.connect((ip, port)); s.close()
            result['open_ports'].append(port)
        except Exception:
            pass

    if not result['open_ports']:
        return result

    # Testa HTTP com Host: domain direto no IP (bypassa CDN routing)
    for port in result['open_ports'][:2]:
        try:
            if port in (443, 8443):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(ip, port, timeout=4, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=4)
            conn.request('HEAD', '/', headers={'Host': domain, 'User-Agent': 'Mozilla/5.0'})
            resp = conn.getresponse()
            headers = {k.lower(): v.lower() for k, v in resp.getheaders()}
            conn.close()
            result['responds_http'] = True
            result['status_code'] = resp.status
            result['server'] = headers.get('server', '')
            result['behind_cdn'] = 'cf-ray' in headers or 'cloudflare' in result['server']
            result['headers_sample'] = dict(list(headers.items())[:6])
            break
        except Exception:
            pass

    return result


# ── Main pipeline ─────────────────────────────────────────────────────────────

def find_origin_ip(domain: str) -> Dict:
    """
    Pipeline completo: detecta CDN, coleta candidatos de múltiplas fontes,
    verifica cada IP candidato diretamente.
    """
    report = {
        'domain': domain,
        'behind_cdn': False,
        'cdn_name': None,
        'historical_ips': [],
        'mx_records': [],
        'spf_ips': [],
        'subdomains_found': 0,
        'candidates': [],
        'verified_origins': [],
    }

    # 1. Detecta CDN
    cdn_info = detect_cdn(domain)
    report['behind_cdn'] = cdn_info.get('behind_cdn', False)
    report['cdn_name'] = cdn_info.get('cdn')
    report['server_header'] = cdn_info.get('server', '')

    # 2. Coleta candidatos em paralelo
    with ThreadPoolExecutor(max_workers=4) as pool:
        f_crt  = pool.submit(get_subdomains_crt, domain)
        f_hist = pool.submit(get_dns_history, domain)
        f_mx   = pool.submit(get_mx_ips, domain)
        f_spf  = pool.submit(get_spf_ips, domain)

    crt_subs = f_crt.result()  or []
    hist_ips = f_hist.result() or []
    mx_list  = f_mx.result()   or []
    spf_ips  = f_spf.result()  or []

    report['historical_ips'] = hist_ips
    report['mx_records']     = [{'host': h, 'ip': i} for h, i in mx_list]
    report['spf_ips']        = spf_ips
    report['subdomains_found'] = len(crt_subs)

    # 3. Resolve subdomínios
    sub_results = resolve_bypass_subdomains(domain, crt_subs[:40])
    report['subdomains_resolved'] = sub_results[:25]

    # 4. IPs diretos do CDN para excluir
    cdn_ips = set(get_a_records(domain))

    # 5. Agrega todos os IPs candidatos (remove o IP do CDN)
    all_ips = (
        set(hist_ips)
        | {ip for _, ip in mx_list}
        | set(spf_ips)
        | {r['ip'] for r in sub_results}
    ) - cdn_ips

    report['candidates'] = sorted(all_ips)[:25]

    # 6. Verifica cada candidato
    with ThreadPoolExecutor(max_workers=12) as pool:
        verified = list(pool.map(lambda ip: verify_origin(ip, domain), list(all_ips)[:25]))

    report['verified_origins'] = sorted(
        [r for r in verified if r.get('responds_http') and not r.get('behind_cdn')],
        key=lambda r: r.get('status_code') or 999
    )

    return report
