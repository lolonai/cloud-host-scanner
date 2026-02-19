#!/usr/bin/env python3
"""
Cloud Host Scanner - Certificate Transparency + Geolocation
Récupère les certificats SSL des providers cloud puis géolocalise par pays
"""

import requests
import time
import os
import sys
import json
import socket
from typing import Dict, List, Optional
from dataclasses import dataclass
import concurrent.futures
from urllib.parse import urlparse

# ── Configuration ──────────────────────────────────────────────
API_ENDPOINT = os.getenv("API_ENDPOINT", "http://localhost:5000")
API_KEY = os.getenv("API_KEY", "")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
SCAN_COUNTRY = os.getenv("SCAN_COUNTRY", "FR")
TIMEOUT = 5
MAX_WORKERS = 20
BATCH_SIZE = 50

# ── Domaines à scanner par provider ───────────────────────────
PROVIDER_DOMAINS = {
    "heroku": [".herokuapp.com"],
    "aws": [".elasticbeanstalk.com", ".awsglobalaccelerator.com"],
    "gcp": [".appspot.com", ".run.app"],
    "azure": [".azurewebsites.net"],
    "digitalocean": [".ondigitalocean.app"],
    "netlify": [".netlify.app"],
    "vercel": [".vercel.app"],
    "render": [".onrender.com"],
    "scalingo": [".scalingo.io"],
    "railway": [".railway.app", ".up.railway.app"],
    "fly": [".fly.dev"]
}

PROVIDERS_INFO = {
    "heroku": {"name": "Heroku", "icon": "🟣"},
    "aws": {"name": "Amazon AWS", "icon": "🟠"},
    "gcp": {"name": "Google Cloud", "icon": "🔵"},
    "azure": {"name": "Microsoft Azure", "icon": "🔷"},
    "digitalocean": {"name": "DigitalOcean", "icon": "🟢"},
    "netlify": {"name": "Netlify", "icon": "🟤"},
    "vercel": {"name": "Vercel", "icon": "⚫"},
    "render": {"name": "Render", "icon": "🟠"},
    "scalingo": {"name": "Scalingo", "icon": "🇫🇷"},
    "railway": {"name": "Railway", "icon": "🚂"},
    "fly": {"name": "Fly.io", "icon": "✈️"}
}

@dataclass
class ScanResult:
    domain: str
    ip: str
    provider: str
    country: str
    status_code: int


class CertScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (CloudScanner/2.0)'
        })
        self.ip_cache = {}
    
    def get_certs_from_crtsh(self, pattern: str, limit: int = 1000) -> List[str]:
        """Récupère les domaines depuis crt.sh."""
        try:
            print(f"🔍 Recherche certificats pour: {pattern}")
            resp = self.session.get(
                "https://crt.sh/",
                params={"q": pattern, "output": "json"},
                timeout=30
            )
            
            if resp.status_code != 200:
                return []
            
            certs = resp.json()
            domains = set()
            
            for cert in certs[:limit]:
                name = cert.get("name_value", "")
                # Nettoyer les wildcards et newlines
                for domain in name.split("\n"):
                    domain = domain.strip().replace("*.", "")
                    if domain and "." in domain:
                        domains.add(domain)
            
            print(f"✅ {len(domains)} domaines uniques trouvés")
            return list(domains)[:limit]
            
        except Exception as e:
            print(f"❌ Erreur crt.sh: {e}")
            return []
    
    def resolve_domain(self, domain: str) -> Optional[str]:
        """Résout un domaine en IP."""
        if domain in self.ip_cache:
            return self.ip_cache[domain]
        
        try:
            ip = socket.gethostbyname(domain)
            self.ip_cache[domain] = ip
            return ip
        except:
            return None
    
    def geolocate_ip(self, ip: str) -> Optional[str]:
        """Géolocalise une IP via ipinfo.io."""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else {}
            
            resp = self.session.get(url, params=params, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("country", "").upper()
            return None
        except:
            return None
    
    def check_domain(self, domain: str, provider: str, target_country: str) -> Optional[ScanResult]:
        """Vérifie si un domaine est actif et dans le bon pays."""
        # Résoudre IP
        ip = self.resolve_domain(domain)
        if not ip:
            return None
        
        # Géolocaliser
        country = self.geolocate_ip(ip)
        if not country or (target_country and country != target_country):
            return None
        
        # Vérifier HTTP
        try:
            resp = self.session.get(
                f"https://{domain}",
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=False
            )
            
            return ScanResult(
                domain=domain,
                ip=ip,
                provider=provider,
                country=country,
                status_code=resp.status_code
            )
        except:
            # Même si HTTP échoue, on garde le domaine
            return ScanResult(
                domain=domain,
                ip=ip,
                provider=provider,
                country=country,
                status_code=0
            )
    
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
                "headers": {},
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
            print(f"✅ Envoyé {len(results)} résultats (status: {resp.status_code})")
        except Exception as e:
            print(f"❌ Erreur API: {e}")
    
    def scan_provider(self, provider: str, patterns: List[str], target_country: str, max_per_pattern: int = 200):
        """Scanne un provider complet."""
        provider_info = PROVIDERS_INFO.get(provider, {})
        icon = provider_info.get("icon", "❓")
        name = provider_info.get("name", provider)
        
        print(f"\n{icon} {name}")
        print("-" * 60)
        
        all_domains = []
        
        # Récupérer les certificats pour chaque pattern
        for pattern in patterns:
            domains = self.get_certs_from_crtsh(f"%{pattern}", limit=max_per_pattern)
            all_domains.extend(domains)
        
        # Dédupliquer
        all_domains = list(set(all_domains))[:500]  # Max 500 par provider
        
        if not all_domains:
            print("⚠️ Aucun domaine trouvé")
            return
        
        print(f"📡 Vérification de {len(all_domains)} domaines...")
        
        # Scanner en parallèle
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(self.check_domain, domain, provider, target_country): domain
                for domain in all_domains
            }
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    print(f"  ✓ {result.domain} → {result.country} ({result.ip})")
        
        # Envoyer par batches
        for i in range(0, len(results), BATCH_SIZE):
            batch = results[i:i+BATCH_SIZE]
            self.send_to_api(batch)
            time.sleep(0.5)
        
        print(f"📊 {len(results)} sites trouvés pour {name}")


def main():
    """Point d'entrée principal."""
    country = SCAN_COUNTRY
    
    print(f"🌍 Cloud Host Scanner - Certificate Transparency")
    print(f"🎯 Pays ciblé: {country}")
    print("=" * 60)
    
    scanner = CertScanner()
    total_found = 0
    
    # Scanner chaque provider
    for provider, patterns in PROVIDER_DOMAINS.items():
        found = scanner.scan_provider(provider, patterns, country, max_per_pattern=200)
        time.sleep(2)  # Rate limiting entre providers
    
    print("=" * 60)
    print(f"✅ Scan terminé !")


if __name__ == "__main__":
    # Désactiver les warnings SSL
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()
