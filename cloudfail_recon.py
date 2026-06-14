#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CloudFail-like OSINT module — PenteIA v4.0
Descobre IPs reais atrás do Cloudflare via brute-force de subdomínios.
"""

import socket
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional


# Subnets IPv4 do Cloudflare (atualizado 2025)
_CF_SUBNETS = [
    ipaddress.ip_network(n) for n in [
        '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '104.16.0.0/13', '104.24.0.0/14', '108.162.192.0/18',
        '131.0.96.0/22', '141.101.64.0/18', '162.158.0.0/15',
        '172.64.0.0/13', '173.245.48.0/20', '188.114.96.0/20',
        '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17',
    ]
]

# 120 subdomínios mais comuns baseados no wordlist do CloudFail
WORDLIST = [
    'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'mx',
    'email', 'webmail', 'api', 'dev', 'staging', 'test', 'admin', 'blog',
    'shop', 'store', 'portal', 'vpn', 'remote', 'secure', 'origin',
    'direct', 'backup', 'm', 'mobile', 'img', 'images', 'cdn', 'files',
    'uploads', 'static', 'assets', 'media', 'server', 'host', 'web', 'app',
    'apps', 'cloud', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
    'webdisk', 'wap', 'wiki', 'demo', 'beta', 'alpha', 'git', 'svn',
    'jira', 'jenkins', 'ci', 'docker', 'k8s', 'grafana', 'prometheus',
    'monitor', 'status', 'health', 'ping', 'ns3', 'ns4', 'dns', 'dns1',
    'dns2', 'mail2', 'smtp2', 'pop3', 'imap4', 'webmail2', 'help', 'support',
    'forum', 'forums', 'news', 'new', 'old', 'bk', 'backup2', 'vpn2',
    'gw', 'gateway', 'proxy', 'sip', 'voip', 'meet', 'conference',
    'office', 'exchange', 'owa', 'sharepoint', 'teams', 'zoom',
    'legacy', 'old2', 'new2', 'v1', 'v2', 'v3', 'internal', 'intranet',
    'extranet', 'corp', 'corporate', 'network', 'net', 'db', 'database',
    'mysql', 'postgres', 'redis', 'mongo', 'elastic', 'kibana', 'logstash',
    'nagios', 'zabbix', 'cacti', 'snmp', 'nms', 'fw', 'firewall', 'router',
    'switch', 'lb', 'loadbalancer', 'haproxy', 'nginx', 'apache',
    'tomcat', 'node', 'ruby', 'php', 'python', 'java', 'go',
    'download', 'downloads', 'update', 'updates', 'patch', 'patches',
    'release', 'releases', 'build', 'builds', 'artifact', 'registry',
]


def is_cloudflare(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _CF_SUBNETS)
    except ValueError:
        return False


def resolve_host(hostname: str, timeout: float = 2.0) -> List[str]:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return list({info[4][0] for info in infos})
    except (socket.gaierror, OSError):
        return []
    finally:
        socket.setdefaulttimeout(old)


def check_domain_cloudflare(domain: str) -> Dict:
    ips = resolve_host(domain)
    if not ips:
        return {'resolves': False, 'ips': [], 'behind_cloudflare': False}
    behind = all(is_cloudflare(ip) for ip in ips)
    return {'resolves': True, 'ips': ips, 'behind_cloudflare': behind}


# ── Job queue ─────────────────────────────────────────────────────────────────

_jobs: Dict[str, Dict] = {}
_jobs_lock = threading.Lock()


def get_job(job_id: str) -> Optional[Dict]:
    with _jobs_lock:
        return _jobs.get(job_id)


def start_job(job_id: str, domain: str, wordlist: List[str], workers: int = 30) -> Dict:
    job = {
        'status': 'starting',
        'domain': domain,
        'domain_info': {},
        'progress': 0,
        'total': len(wordlist),
        'found': [],
        'error': None,
        'started_at': time.time(),
        'completed_at': None,
    }
    with _jobs_lock:
        _jobs[job_id] = job

    threading.Thread(target=_run_job, args=(job_id, domain, wordlist, workers), daemon=True).start()
    return job


def _run_job(job_id: str, domain: str, wordlist: List[str], workers: int):
    job = _jobs[job_id]
    try:
        job['status'] = 'running'
        job['domain_info'] = check_domain_cloudflare(domain)

        found = []

        def _probe(sub):
            fqdn = f"{sub}.{domain}"
            ips = resolve_host(fqdn)
            return sub, fqdn, ips

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_probe, sub): sub for sub in wordlist}
            for future in as_completed(futures):
                sub, fqdn, ips = future.result()
                job['progress'] += 1
                for ip in ips:
                    cf = is_cloudflare(ip)
                    found.append({
                        'subdomain': fqdn,
                        'ip': ip,
                        'is_cloudflare': cf,
                        'exposed': not cf,
                    })

        job['found'] = sorted(found, key=lambda x: (x['is_cloudflare'], x['subdomain']))
        job['status'] = 'completed'
    except Exception as e:
        job['status'] = 'error'
        job['error'] = str(e)
    finally:
        job['completed_at'] = time.time()


def cleanup_old_jobs(max_age_seconds: int = 3600):
    cutoff = time.time() - max_age_seconds
    with _jobs_lock:
        stale = [jid for jid, j in _jobs.items()
                 if j['status'] in ('completed', 'error') and (j['completed_at'] or 0) < cutoff]
        for jid in stale:
            del _jobs[jid]
