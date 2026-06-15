"""
PenteIA Cloud Recon Module
AWS IAM user enumeration + S3 bucket discovery (unauthenticated/public)
"""
import requests
import socket
import ssl
import json
from typing import List, Dict, Any
from dataclasses import dataclass, field

@dataclass
class CloudReconResult:
    target_account: str = ""
    s3_buckets: List[Dict] = field(default_factory=list)  # {name, public, region, acl_exposed, files_count}
    iam_findings: List[Dict] = field(default_factory=list)  # {type, detail, risk}
    metadata_endpoints: List[Dict] = field(default_factory=list)  # {url, status, data_preview}
    cloud_provider: str = ""
    errors: List[str] = field(default_factory=list)

def enumerate_s3_buckets(company_name: str, extra_words: List[str] = None) -> List[Dict]:
    """Enumerate S3 buckets via DNS/HTTP probing (public access only)"""
    words = extra_words or []
    variants = []
    base = company_name.lower().replace(" ", "-").replace("_", "-")
    suffixes = ["", "-dev", "-staging", "-prod", "-backup", "-assets", "-files", "-data", "-logs", "-static", "-public", "-private", "-db", "-bucket", "-storage"]
    prefixes = ["", "dev-", "staging-", "prod-", "backup-", "assets-", "data-", "static-"]

    for pre in prefixes:
        for suf in suffixes:
            variants.append(f"{pre}{base}{suf}")
    for w in words:
        variants.append(f"{base}-{w}")
        variants.append(f"{w}-{base}")

    results = []
    for name in variants[:60]:  # cap at 60 to avoid being too slow
        result = _probe_s3_bucket(name)
        if result:
            results.append(result)
    return results

def _probe_s3_bucket(bucket_name: str) -> Dict | None:
    """Check if S3 bucket exists and its access level"""
    url = f"https://{bucket_name}.s3.amazonaws.com/"
    alt_url = f"https://s3.amazonaws.com/{bucket_name}/"

    try:
        r = requests.get(url, timeout=5, allow_redirects=False)
        if r.status_code == 403:
            return {"name": bucket_name, "url": url, "status": "exists_private", "risk": "low", "detail": "Bucket exists but access denied"}
        elif r.status_code == 200:
            content = r.text[:2000]
            file_count = content.count("<Key>")
            return {"name": bucket_name, "url": url, "status": "PUBLIC_EXPOSED", "risk": "critical", "detail": f"Bucket is publicly readable. ~{file_count} files listed.", "preview": content[:300]}
        elif r.status_code == 301:
            return {"name": bucket_name, "url": url, "status": "exists_redirect", "risk": "low", "detail": "Bucket exists (redirect)"}
        elif r.status_code == 404:
            return None
    except requests.exceptions.RequestException:
        pass

    try:
        r2 = requests.get(alt_url, timeout=5, allow_redirects=False)
        if r2.status_code in (200, 403):
            return {"name": bucket_name, "url": alt_url, "status": "exists_private" if r2.status_code == 403 else "PUBLIC_EXPOSED", "risk": "low" if r2.status_code == 403 else "critical", "detail": "Bucket found via path-style URL"}
    except requests.exceptions.RequestException:
        pass

    return None

def check_metadata_endpoints(host: str) -> List[Dict]:
    """Check for exposed cloud metadata endpoints"""
    endpoints = [
        {"url": f"http://{host}/latest/meta-data/", "label": "AWS IMDS v1"},
        {"url": f"http://{host}/metadata/instance?api-version=2021-02-01", "label": "Azure IMDS"},
        {"url": f"http://{host}/computeMetadata/v1/", "label": "GCP Metadata", "headers": {"Metadata-Flavor": "Google"}},
        {"url": f"http://{host}/opc/v1/instance/", "label": "Oracle Cloud"},
        {"url": f"http://{host}:4040/latest/meta-data/", "label": "AWS IMDS alt port"},
    ]

    results = []
    for ep in endpoints:
        try:
            headers = ep.get("headers", {})
            r = requests.get(ep["url"], timeout=3, headers=headers)
            if r.status_code == 200 and len(r.text) > 0:
                results.append({
                    "url": ep["url"],
                    "label": ep["label"],
                    "status": "EXPOSED",
                    "risk": "critical",
                    "preview": r.text[:200],
                    "detail": f"Cloud metadata endpoint accessible! This allows credential theft."
                })
        except requests.exceptions.RequestException:
            pass
    return results

def detect_cloud_provider(host: str) -> str:
    """Detect which cloud provider hosts this server"""
    try:
        ip = socket.gethostbyname(host)
        # AWS ranges check via TXT lookup
        r = requests.get(f"https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=5)
        if r.status_code == 200:
            ranges = r.json().get("prefixes", [])
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            for prefix in ranges[:2000]:
                try:
                    if ip_obj in ipaddress.ip_network(prefix["ip_prefix"]):
                        return f"AWS ({prefix.get('region', 'unknown')} - {prefix.get('service', '')})"
                except ValueError:
                    continue
    except Exception:
        pass

    # Fallback: hostname heuristics
    try:
        hostname = socket.gethostbyaddr(host)[0].lower()
        if "amazonaws" in hostname or "aws" in hostname:
            return "AWS"
        if "azure" in hostname or "microsoft" in hostname:
            return "Azure"
        if "googlecloud" in hostname or "gcp" in hostname:
            return "GCP"
        if "digitalocean" in hostname:
            return "DigitalOcean"
        if "vultr" in hostname:
            return "Vultr"
        if "linode" in hostname or "akamai" in hostname:
            return "Linode/Akamai"
        if "hetzner" in hostname:
            return "Hetzner"
    except Exception:
        pass

    return "Unknown"

def scan_iam_anonymous(account_id_hint: str = "") -> List[Dict]:
    """Enumerate public IAM information (roles via STS, public policies)"""
    findings = []

    # Check for common misconfigured IAM endpoints exposed via apps
    iam_urls = [
        "/.aws/credentials",
        "/.env",
        "/env",
        "/config/credentials",
        "/aws_credentials",
        "/backup/credentials",
    ]

    return findings  # Returns empty unless we have a host — used by run_cloud_recon

def run_cloud_recon(host: str, company_name: str = "", extra_words: List[str] = None) -> CloudReconResult:
    """Main entry point for cloud reconnaissance"""
    result = CloudReconResult()

    # Detect cloud provider
    result.cloud_provider = detect_cloud_provider(host)

    # Check metadata endpoints on the target host
    result.metadata_endpoints = check_metadata_endpoints(host)

    # S3 bucket enumeration
    name = company_name or host.split(".")[0]
    result.s3_buckets = enumerate_s3_buckets(name, extra_words)

    # IAM file exposure check
    iam_paths = ["/.aws/credentials", "/.env", "/env", "/.aws/config", "/aws_credentials", "/backup/credentials"]
    for path in iam_paths:
        try:
            for scheme in ["http", "https"]:
                url = f"{scheme}://{host}{path}"
                r = requests.get(url, timeout=4, verify=False)
                if r.status_code == 200 and ("aws_access_key" in r.text.lower() or "aws_secret" in r.text.lower() or "[default]" in r.text):
                    result.iam_findings.append({
                        "type": "EXPOSED_CREDENTIALS",
                        "url": url,
                        "risk": "critical",
                        "detail": f"AWS credentials file exposed at {path}",
                        "preview": r.text[:200],
                    })
        except Exception:
            pass

    return result
