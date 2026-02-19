#!/usr/bin/env python3
"""
Cloud Host Scanner - Backend API
Flask app avec PostgreSQL et interface web
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import psycopg2
import psycopg2.extras
import os
import json
from datetime import datetime
import csv
import io

app = Flask(__name__)
CORS(app)

# ── Configuration ──────────────────────────────────────────────
DATABASE_URL = os.getenv("POSTGRESQL_ADDON_URI") or os.getenv("DATABASE_URL")
API_KEY = os.getenv("API_KEY", "changeme")

# ── Providers info ────────────────────────────────────────────
PROVIDERS_INFO = {
    "heroku": {"name": "Heroku", "icon": "🟣", "color": "#6762a6"},
    "aws": {"name": "Amazon AWS", "icon": "🟠", "color": "#ff9900"},
    "gcp": {"name": "Google Cloud", "icon": "🔵", "color": "#4285f4"},
    "azure": {"name": "Microsoft Azure", "icon": "🔷", "color": "#0078d4"},
    "digitalocean": {"name": "DigitalOcean", "icon": "🟢", "color": "#0080ff"},
    "cloudflare": {"name": "Cloudflare", "icon": "🟡", "color": "#f38020"},
    "ovh": {"name": "OVH", "icon": "🔴", "color": "#123f6d"},
    "netlify": {"name": "Netlify", "icon": "🟤", "color": "#00c7b7"},
    "vercel": {"name": "Vercel", "icon": "⚫", "color": "#000000"},
    "render": {"name": "Render", "icon": "🟠", "color": "#46e3b7"},
    "scalingo": {"name": "Scalingo", "icon": "🇫🇷", "color": "#3b4aff"},
    "railway": {"name": "Railway", "icon": "🚂", "color": "#0b0d0e"},
    "fly": {"name": "Fly.io", "icon": "✈️", "color": "#7b3ff2"}
}

COUNTRIES = {
    "FR": {"name": "France", "icon": "🇫🇷", "continent": "Europe"},
    "BE": {"name": "Belgique", "icon": "🇧🇪", "continent": "Europe"},
    "CH": {"name": "Suisse", "icon": "🇨🇭", "continent": "Europe"},
    "GB": {"name": "Royaume-Uni", "icon": "🇬🇧", "continent": "Europe"},
    "DE": {"name": "Allemagne", "icon": "🇩🇪", "continent": "Europe"},
    "ES": {"name": "Espagne", "icon": "🇪🇸", "continent": "Europe"},
    "IT": {"name": "Italie", "icon": "🇮🇹", "continent": "Europe"},
    "US": {"name": "États-Unis", "icon": "🇺🇸", "continent": "Amérique"},
    "CA": {"name": "Canada", "icon": "🇨🇦", "continent": "Amérique"},
    "BR": {"name": "Brésil", "icon": "🇧🇷", "continent": "Amérique"},
    "MX": {"name": "Mexique", "icon": "🇲🇽", "continent": "Amérique"},
    "JP": {"name": "Japon", "icon": "🇯🇵", "continent": "Asie"},
    "SG": {"name": "Singapour", "icon": "🇸🇬", "continent": "Asie"},
    "IN": {"name": "Inde", "icon": "🇮🇳", "continent": "Asie"},
    "AU": {"name": "Australie", "icon": "🇦🇺", "continent": "Océanie"},
    "ZA": {"name": "Afrique du Sud", "icon": "🇿🇦", "continent": "Afrique"}
}


# ── Database ───────────────────────────────────────────────────
def get_db():
    """Connexion PostgreSQL."""
    return psycopg2.connect(DATABASE_URL, sslmode='require')


def init_db():
    """Initialise la base de données."""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cloud_hosts (
            id SERIAL PRIMARY KEY,
            ip TEXT NOT NULL,
            domain TEXT,
            provider TEXT NOT NULL,
            country TEXT NOT NULL,
            headers JSONB,
            status_code INTEGER,
            selected BOOLEAN DEFAULT FALSE,
            discovered_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(ip, domain)
        )
    """)
    
    # Index pour performances
    cur.execute("CREATE INDEX IF NOT EXISTS idx_provider ON cloud_hosts(provider)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_country ON cloud_hosts(country)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_selected ON cloud_hosts(selected)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_discovered ON cloud_hosts(discovered_at DESC)")
    
    conn.commit()
    cur.close()
    conn.close()
    print("✅ Base de données initialisée")


# ── Routes ─────────────────────────────────────────────────────
@app.route("/")
def index():
    """Page principale."""
    return render_template("index.html", 
                         providers=PROVIDERS_INFO,
                         countries=COUNTRIES)


@app.route("/api/results", methods=["POST"])
def add_results():
    """API pour ajouter des résultats de scan."""
    data = request.get_json()
    
    # Vérif API key
    if data.get("api_key") != API_KEY:
        return jsonify({"error": "Invalid API key"}), 401
    
    results = data.get("results", [])
    
    conn = get_db()
    cur = conn.cursor()
    
    added = 0
    for r in results:
        try:
            cur.execute("""
                INSERT INTO cloud_hosts (ip, domain, provider, country, headers, status_code)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (ip, domain) DO NOTHING
            """, (
                r["ip"],
                r.get("domain"),
                r["provider"],
                r["country"],
                json.dumps(r.get("headers", {})),
                r.get("status_code")
            ))
            added += cur.rowcount
        except Exception as e:
            print(f"❌ Erreur insertion: {e}")
    
    conn.commit()
    cur.close()
    conn.close()
    
    return jsonify({"status": "ok", "added": added}), 200


@app.route("/api/hosts")
def get_hosts():
    """Récupère la liste des hosts avec filtres."""
    provider = request.args.get("provider")
    country = request.args.get("country")
    selected_only = request.args.get("selected") == "true"
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 100))
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Build query
    conditions = []
    params = []
    
    if provider and provider != "all":
        conditions.append("provider = %s")
        params.append(provider)
    
    if country and country != "all":
        conditions.append("country = %s")
        params.append(country)
    
    if selected_only:
        conditions.append("selected = TRUE")
    
    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    
    # Count total
    cur.execute(f"SELECT COUNT(*) as total FROM cloud_hosts {where_clause}", params)
    total = cur.fetchone()["total"]
    
    # Fetch data
    offset = (page - 1) * per_page
    params.extend([per_page, offset])
    
    cur.execute(f"""
        SELECT id, ip, domain, provider, country, status_code, selected, discovered_at
        FROM cloud_hosts
        {where_clause}
        ORDER BY discovered_at DESC
        LIMIT %s OFFSET %s
    """, params)
    
    hosts = cur.fetchall()
    
    cur.close()
    conn.close()
    
    return jsonify({
        "hosts": hosts,
        "total": total,
        "page": page,
        "pages": (total + per_page - 1) // per_page
    })


@app.route("/api/stats")
def get_stats():
    """Statistiques globales."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Total par provider
    cur.execute("""
        SELECT provider, COUNT(*) as count
        FROM cloud_hosts
        GROUP BY provider
        ORDER BY count DESC
    """)
    by_provider = cur.fetchall()
    
    # Total par pays
    cur.execute("""
        SELECT country, COUNT(*) as count
        FROM cloud_hosts
        GROUP BY country
        ORDER BY count DESC
    """)
    by_country = cur.fetchall()
    
    # Total général
    cur.execute("SELECT COUNT(*) as total FROM cloud_hosts")
    total = cur.fetchone()["total"]
    
    # Sélectionnés
    cur.execute("SELECT COUNT(*) as selected FROM cloud_hosts WHERE selected = TRUE")
    selected = cur.fetchone()["selected"]
    
    cur.close()
    conn.close()
    
    return jsonify({
        "total": total,
        "selected": selected,
        "by_provider": by_provider,
        "by_country": by_country
    })


@app.route("/api/toggle/<int:host_id>", methods=["POST"])
def toggle_selection(host_id):
    """Toggle la sélection d'un host."""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("""
        UPDATE cloud_hosts
        SET selected = NOT selected
        WHERE id = %s
        RETURNING selected
    """, (host_id,))
    
    result = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    
    return jsonify({"selected": result[0] if result else False})


@app.route("/api/export")
def export_csv():
    """Exporte les hosts sélectionnés en CSV."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cur.execute("""
        SELECT domain, ip, provider, country, status_code, discovered_at
        FROM cloud_hosts
        WHERE selected = TRUE
        ORDER BY discovered_at DESC
    """)
    
    hosts = cur.fetchall()
    cur.close()
    conn.close()
    
    # Créer CSV en mémoire
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["Domain", "IP", "Provider", "Country", "Status", "Discovered"])
    
    # Data
    for h in hosts:
        writer.writerow([
            h["domain"] or h["ip"],
            h["ip"],
            PROVIDERS_INFO.get(h["provider"], {}).get("name", h["provider"]),
            COUNTRIES.get(h["country"], {}).get("name", h["country"]),
            h["status_code"],
            h["discovered_at"].strftime("%Y-%m-%d %H:%M")
        ])
    
    # Convertir en bytes
    output.seek(0)
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8-sig'))  # BOM pour Excel
    mem.seek(0)
    
    return send_file(
        mem,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'cloud-hosts-{datetime.now().strftime("%Y%m%d")}.csv'
    )


# ── Initialisation ─────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
