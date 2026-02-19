#!/usr/bin/env python3
"""
Cloud Host Scanner - Multi-Provider Detection
Scanne les IPs par pays et détecte l'hébergeur (Heroku, AWS, GCP, Azure, etc.)
"""

import requests
import time
import os
import sys
from typing import Dict, List, Optional
from dataclasses import dataclass
import concurrent.futures

# ── Configuration ──────────────────────────────────────────────
API_ENDPOINT = os.getenv("API_ENDPOINT", "http://localhost:5000")
API_KEY = os.getenv("API_KEY", "")
TIMEOUT = 3  # secondes
MAX_WORKERS = 50  # threads parallèles
BATCH_SIZE = 100

# ── Providers détectables ─────────────────────────────────────
PROVIDERS = {
    "heroku": {
        "headers": ["via=vegur", "server=cowboy"],
        "domains": [".herokuapp.com"],
        "name": "Heroku",
        "icon": "🟣"
    },
    "aws": {
        "headers": ["server=amazons3", "x-amz-", "server=awselb"],
        "domains": [".amazonaws.com", ".elasticbeanstalk.com", ".awsglobalaccelerator.com"],
        "name": "Amazon AWS",
        "icon": "🟠"
    },
    "gcp": {
        "headers": ["server=google frontend", "x-goog-", "server=gws"],
        "domains": [".appspot.com", ".run.app", ".cloudfunctions.net"],
        "name": "Google Cloud",
        "icon": "🔵"
    },
    "azure": {
        "headers": ["server=microsoft-iis", "x-azure-", "server=microsoft-httpapi"],
        "domains": [".azurewebsites.net", ".azure.com", ".cloudapp.azure.com"],
        "name": "Microsoft Azure",
        "icon": "🔷"
    },
    "digitalocean": {
        "headers": ["server=nginx/droplet"],
        "domains": [".digitaloceanspaces.com", ".ondigitalocean.app"],
        "name": "DigitalOcean",
        "icon": "🟢"
    },
    "cloudflare": {
        "headers": ["server=cloudflare", "cf-ray"],
        "domains": [".pages.dev", ".workers.dev"],
        "name": "Cloudflare",
        "icon": "🟡"
    },
    "ovh": {
        "headers": ["server=apache (ovh)", "x-ovh-"],
        "domains": [".ovh.net"],
        "name": "OVH",
        "icon": "🔴"
    },
    "netlify": {
        "headers": ["server=netlify", "x-nf-"],
        "domains": [".netlify.app", ".netlify.com"],
        "name": "Netlify",
        "icon": "🟤"
    },
    "vercel": {
        "headers": ["server=vercel", "x-vercel-"],
        "domains": [".vercel.app", ".vercel.sh"],
        "name": "Vercel",
        "icon": "⚫"
    },
    "render": {
        "headers": ["x-render-"],
        "domains": [".onrender.com"],
        "name": "Render",
        "icon": "🟠"
    },
    "scalingo": {
        "headers": ["x-scalingo-"],
        "domains": [".scalingo.io", ".osc-fr1.scalingo.io"],
        "name": "Scalingo",
        "icon": "🇫🇷"
    },
    "railway": {
        "headers": [],
        "domains": [".railway.app", ".up.railway.app"],
        "name": "Railway",
        "icon": "🚂"
    },
    "fly": {
        "headers": ["via=fly.io", "fly-request-id"],
        "domains": [".fly.dev"],
        "name": "Fly.io",
        "icon": "✈️"
    }
}

@dataclass
class ScanResult:
    ip: str
    domain: Optional[str]
    provider: str
    country: str
    headers: Dict[str, str]
    status_code: int


class CloudScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (CloudScanner/1.0)'
        })

    def detect_provider(self, headers: Dict[str, str], domain: str = "") -> Optional[str]:
        """Détecte le provider cloud basé sur les headers et le domaine."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        headers_str = " ".join([f"{k}={v}" for k, v in headers_lower.items()])

        for provider_key, provider_info in PROVIDERS.items():
            # Check headers
            for pattern in provider_info["headers"]:
                if pattern.lower() in headers_str:
                    return provider_key

            # Check domain
            for domain_pattern in provider_info["domains"]:
                if domain_pattern.lower() in domain.lower():
                    return provider_key

        return None

    def scan_ip(self, ip: str, country: str) -> Optional[ScanResult]:
        """Scanne une IP et détecte le provider."""
        for protocol in ["http", "https"]:
            try:
                url = f"{protocol}://{ip}"
                resp = self.session.get(
                    url,
                    timeout=TIMEOUT,
                    allow_redirects=True,
                    verify=False
                )

                # Extraire le domaine final (après redirections)
                final_domain = resp.url.split("//")[1].split("/")[0] if "//" in resp.url else ip

                provider = self.detect_provider(dict(resp.headers), final_domain)

                if provider:
                    return ScanResult(
                        ip=ip,
                        domain=final_domain,
                        provider=provider,
                        country=country,
                        headers=dict(resp.headers),
                        status_code=resp.status_code
                    )
            except:
                continue

        return None

    def send_to_api(self, results: List[ScanResult]):
        """Envoie les résultats à l'API."""
        if not results:
            return

        data = [
            {
                "ip": r.ip,
                "domain": r.domain,
                "provider": r.provider,
                "country": r.country,
                "headers": r.headers,
                "status_code": r.status_code
            }
            for r in results
        ]

        try:
            resp = requests.post(
                f"{API_ENDPOINT}/api/results",
                json={"results": data, "api_key": API_KEY},
                timeout=10
            )
            print(f"✅ Envoyé {len(results)} résultats à l'API (status: {resp.status_code})")
        except Exception as e:
            print(f"❌ Erreur envoi API: {e}")

    def scan_batch(self, ips: List[str], country: str):
        """Scanne un batch d'IPs en parallèle."""
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(self.scan_ip, ip, country): ip for ip in ips}

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        provider_info = PROVIDERS.get(result.provider, {})
                        icon = provider_info.get("icon", "❓")
                        name = provider_info.get("name", result.provider)
                        print(f"{icon} {name} | {result.domain} ({result.ip}) | {country}")
                except Exception as e:
                    pass

        if results:
            self.send_to_api(results)

        return len(results)


def get_ip_ranges_for_country(country_code: str) -> List[str]:
    """Récupère les ranges d'IPs pour un pays via ipinfo.io."""
    if not IPINFO_TOKEN:
        print("❌ IPINFO_TOKEN manquant")
        return []

    try:
        # Utiliser l'API ranges de ipinfo.io
        resp = requests.get(
            f"https://ipinfo.io/data/ranges/{country_code.lower()}.json",
            params={"token": IPINFO_TOKEN},
            timeout=10
        )

        if resp.status_code != 200:
            print(f"❌ Erreur ipinfo.io: {resp.status_code} - {resp.text}")
            return []

        data = resp.json()

        # Générer des IPs à partir des ranges
        ips = []
        for entry in data[:50]:  # Limiter à 50 premiers ranges
            cidr = entry.get("range", "")
            if not cidr:
                continue

            try:
                network = ipaddress.ip_network(cidr, strict=False)
                # Échantillonner 10 IPs par range
                hosts = list(network.hosts())
                if len(hosts) > 10:
                    step = len(hosts) // 10
                    sample = [str(hosts[i]) for i in range(0, len(hosts), step)][:10]
                else:
                    sample = [str(h) for h in hosts[:10]]
                ips.extend(sample)

                if len(ips) >= 500:
                    break
            except:
                continue

        print(f"📡 {len(ips)} IPs générées")
        return ips[:500]

    except Exception as e:
        print(f"❌ Erreur: {e}")
        return []


def main():
    """Point d'entrée principal du scanner."""
    country = os.getenv("SCAN_COUNTRY", "FR")

    print(f"🌍 Cloud Host Scanner - Pays: {country}")
    print(f"🎯 Détection: {len(PROVIDERS)} providers")
    print("=" * 60)

    scanner = CloudScanner()
    ips = get_ip_ranges_for_country(country)

    print(f"📡 {len(ips)} IPs à scanner...")

    # Scanner par batches
    total_found = 0
    for i in range(0, len(ips), BATCH_SIZE):
        batch = ips[i:i+BATCH_SIZE]
        found = scanner.scan_batch(batch, country)
        total_found += found

        print(f"📊 Batch {i//BATCH_SIZE + 1}: {found} trouvés (total: {total_found})")
        time.sleep(1)  # Rate limiting

    print("=" * 60)
    print(f"✅ Scan terminé: {total_found} sites détectés")


if __name__ == "__main__":
    main()
