#!/usr/bin/env python3
"""
Cloud Host Scanner - Shodan API Integration
Utilise Shodan pour trouver les hébergements cloud par pays
"""

import requests
import time
import os
import sys
import json
from typing import Dict, List, Optional
from dataclasses import dataclass

# ── Configuration ──────────────────────────────────────────────
API_ENDPOINT = os.getenv("API_ENDPOINT", "http://localhost:5000")
API_KEY = os.getenv("API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
SCAN_COUNTRY = os.getenv("SCAN_COUNTRY", "FR")

# ── Providers et leurs signatures Shodan ──────────────────────
PROVIDERS = {
    "heroku": {
        "query": 'http.headers:"heroku-nel"',
        "name": "Heroku",
        "icon": "🟣"
    },
    "aws": {
        "query": 'http.headers:"x-amz-" OR hostname:"amazonaws.com"',
        "name": "Amazon AWS",
        "icon": "🟠"
    },
    "gcp": {
        "query": 'http.headers:"x-goog-" OR hostname:"appspot.com" OR hostname:"run.app"',
        "name": "Google Cloud",
        "icon": "🔵"
    },
    "azure": {
        "query": 'http.headers:"x-azure-" OR hostname:"azurewebsites.net"',
        "name": "Microsoft Azure",
        "icon": "🔷"
    },
    "digitalocean": {
        "query": 'hostname:"ondigitalocean.app" OR hostname:"digitaloceanspaces.com"',
        "name": "DigitalOcean",
        "icon": "🟢"
    },
    "cloudflare": {
        "query": 'http.headers:"cf-ray"',
        "name": "Cloudflare",
        "icon": "🟡"
    },
    "netlify": {
        "query": 'http.headers:"x-nf-" OR hostname:"netlify.app"',
        "name": "Netlify",
        "icon": "🟤"
    },
    "vercel": {
        "query": 'http.headers:"x-vercel-" OR hostname:"vercel.app"',
        "name": "Vercel",
        "icon": "⚫"
    },
    "render": {
        "query": 'hostname:"onrender.com"',
        "name": "Render",
        "icon": "🟠"
    },
    "scalingo": {
        "query": 'http.headers:"x-scalingo-" OR hostname:"scalingo.io"',
        "name": "Scalingo",
        "icon": "🇫🇷"
    },
    "railway": {
        "query": 'hostname:"railway.app"',
        "name": "Railway",
        "icon": "🚂"
    },
    "fly": {
        "query": 'http.headers:"fly-request-id" OR hostname:"fly.dev"',
        "name": "Fly.io",
        "icon": "✈️"
    }
}

@dataclass
class ScanResult:
    domain: str
    ip: str
    provider: str
    country: str
    status_code: int
    port: int


class ShodanScanner:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"
        self.session = requests.Session()
    
    def search(self, query: str, country: str, page: int = 1) -> List[Dict]:
        """Recherche Shodan avec filtre pays."""
        full_query = f"{query} country:{country}"
        
        try:
            print(f"🔍 Shodan: {full_query}")
            
            resp = self.session.get(
                f"{self.base_url}/shodan/host/search",
                params={
                    "key": self.api_key,
                    "query": full_query,
                    "page": page
                },
                timeout=30
            )
            
            if resp.status_code == 401:
                print("❌ Shodan API key invalide")
                return []
            
            if resp.status_code == 403:
                print("❌ Accès refusé - vérifiez votre plan Shodan")
                return []
            
            if resp.status_code != 200:
                print(f"❌ Erreur Shodan: {resp.status_code}")
                return []
            
            data = resp.json()
            results = data.get("matches", [])
            total = data.get("total", 0)
            
            print(f"✅ {len(results)} résultats (total: {total})")
            return results
            
        except Exception as e:
            print(f"❌ Erreur: {e}")
            return []
    
    def parse_result(self, result: Dict, provider: str, country: str) -> Optional[ScanResult]:
        """Parse un résultat Shodan en ScanResult."""
        try:
            # Extraire le domaine (hostname ou IP)
            hostnames = result.get("hostnames", [])
            domain = hostnames[0] if hostnames else result.get("ip_str", "")
            
            # Extraire les infos
            ip = result.get("ip_str", "")
            port = result.get("port", 443)
            
            # Status code depuis HTTP data
            http_data = result.get("http", {})
            status = http_data.get("status", 0)
            
            # Pays (double check)
            result_country = result.get("location", {}).get("country_code", country)
            
            return ScanResult(
                domain=domain,
                ip=ip,
                provider=provider,
                country=result_country.upper(),
                status_code=status,
                port=port
            )
        except Exception as e:
            print(f"⚠️ Erreur parsing: {e}")
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
    
    def scan_provider(self, provider: str, config: Dict, country: str, max_pages: int = 5):
        """Scanne un provider complet."""
        icon = config.get("icon", "❓")
        name = config.get("name", provider)
        query = config.get("query", "")
        
        print(f"\n{icon} {name}")
        print("-" * 60)
        
        all_results = []
        
        # Paginer les résultats (100 par page)
        for page in range(1, max_pages + 1):
            results = self.search(query, country, page)
            
            if not results:
                break
            
            # Parser les résultats
            for r in results:
                parsed = self.parse_result(r, provider, country)
                if parsed:
                    all_results.append(parsed)
                    print(f"  ✓ {parsed.domain} → {parsed.country} ({parsed.ip})")
            
            # Envoyer par batch de 50
            if len(all_results) >= 50:
                self.send_to_api(all_results[:50])
                all_results = all_results[50:]
            
            time.sleep(1)  # Rate limiting Shodan
        
        # Envoyer le reste
        if all_results:
            self.send_to_api(all_results)
        
        print(f"📊 Total trouvé pour {name}")


def main():
    """Point d'entrée principal."""
    country = SCAN_COUNTRY
    
    print(f"🌍 Cloud Host Scanner - Shodan API")
    print(f"🎯 Pays ciblé: {country}")
    print("=" * 60)
    
    if not SHODAN_API_KEY:
        print("❌ SHODAN_API_KEY manquant")
        print("Ajoutez votre clé API Shodan dans les variables d'environnement")
        sys.exit(1)
    
    scanner = ShodanScanner(SHODAN_API_KEY)
    
    # Scanner chaque provider
    for provider, config in PROVIDERS.items():
        scanner.scan_provider(provider, config, country, max_pages=2)  # 200 résultats max par provider
        time.sleep(2)  # Rate limiting entre providers
    
    print("=" * 60)
    print(f"✅ Scan terminé !")


if __name__ == "__main__":
    main()
