# ☁️ Cloud Host Scanner

Scanner automatique multi-providers (Heroku, AWS, GCP, Azure, etc.) avec détection par pays.

## 🎯 Fonctionnalités

- ✅ **13 providers** détectés : Heroku, AWS, GCP, Azure, DigitalOcean, Cloudflare, OVH, Netlify, Vercel, Render, Scalingo, Railway, Fly.io
- ✅ **16 pays** supportés : France, Belgique, Suisse, UK, Allemagne, Espagne, Italie, USA, Canada, Brésil, Mexique, Japon, Singapour, Inde, Australie, Afrique du Sud
- ✅ **Interface web moderne** avec filtres temps réel
- ✅ **Sélection manuelle** des entreprises à exporter
- ✅ **Export CSV** des sélectionnées
- ✅ **Scan automatique 24/7** via GitHub Actions
- ✅ **Base PostgreSQL** pour stockage

---

## 📦 Déploiement sur Clever Cloud

### 1️⃣ Prérequis

```bash
# Installer Clever Tools CLI
npm install -g clever-tools

# Login
clever login
```

### 2️⃣ Créer l'application

```bash
cd cloud-host-scanner

# Créer app Python
clever create --type python cloud-scanner

# Ajouter PostgreSQL
clever addon create postgresql-addon postgres-scanner --link cloud-scanner
```

### 3️⃣ Configuration environnement

```bash
# API Key pour sécuriser l'endpoint
clever env set API_KEY "votre-cle-secrete-random"

# Python version
clever env set CC_PYTHON_VERSION 3.11
```

### 4️⃣ Déployer

```bash
git add .
git commit -m "initial deploy"
clever deploy
```

### 5️⃣ Récupérer l'URL de l'app

```bash
clever domain
# → https://app-xxxxx.cleverapps.io
```

---

## 🤖 Configuration GitHub Actions

### 1️⃣ Créer les secrets GitHub

Allez dans **Settings → Secrets → Actions** de votre repo GitHub :

- `API_ENDPOINT` : `https://app-xxxxx.cleverapps.io`
- `API_KEY` : La même clé que celle dans Clever Cloud

### 2️⃣ Activer le workflow

Le fichier `.github/workflows/scanner.yml` est déjà configuré.

Il scanne automatiquement **16 pays en parallèle, toutes les heures**.

### 3️⃣ Lancer manuellement un scan

Allez dans **Actions → Cloud Host Scanner → Run workflow**

Choisissez un pays spécifique ou laissez par défaut (FR).

---

## 🖥️ Utilisation de l'interface

### Accéder à l'app

```
https://app-xxxxx.cleverapps.io
```

### Filtrer les résultats

1. **Par provider** : Heroku, AWS, GCP, etc.
2. **Par pays** : France, USA, etc.
3. **Par sélection** : Afficher seulement les sélectionnés

### Sélectionner des entreprises

Cochez les cases ✓ à gauche des lignes.

### Exporter en CSV

1. Sélectionnez les entreprises voulues
2. Cliquez sur **📥 Exporter CSV**
3. Le fichier contient : Domain, IP, Provider, Pays, Status, Date

---

## 📊 Architecture

```
┌─────────────────────────────────────────┐
│  GitHub Actions (scan automatique)     │
│  ├─ 16 pays en parallèle               │
│  ├─ Toutes les heures                  │
│  └─ Envoie résultats via API           │
└─────────────────────────────────────────┘
           ↓ POST /api/results
┌─────────────────────────────────────────┐
│  Clever Cloud (Flask + PostgreSQL)     │
│  ├─ Stocke les résultats               │
│  ├─ Interface web                       │
│  └─ Export CSV                          │
└─────────────────────────────────────────┘
```

---

## 🔧 Développement local

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Setup PostgreSQL local

```bash
# Créer une database
createdb cloud_scanner

# Export env vars
export DATABASE_URL="postgresql://user:pass@localhost/cloud_scanner"
export API_KEY="dev-key"
```

### 3. Run

```bash
# Backend
python app.py

# Scanner (dans un autre terminal)
export API_ENDPOINT="http://localhost:5000"
export SCAN_COUNTRY="FR"
python scanner.py
```

### 4. Accéder

```
http://localhost:5000
```

---

## 🎛️ Configuration avancée

### Modifier les pays scannés

Éditez `.github/workflows/scanner.yml` ligne 16 :

```yaml
matrix:
  country: [FR, BE, US]  # Ajoutez/retirez des codes pays
```

### Modifier la fréquence de scan

Éditez `.github/workflows/scanner.yml` ligne 5 :

```yaml
- cron: '0 */2 * * *'  # Toutes les 2 heures au lieu de 1
```

### Ajouter un provider

Éditez `scanner.py` et `app.py`, section `PROVIDERS`.

Ajoutez :

```python
"nouveau_provider": {
    "headers": ["x-header-specifique"],
    "domains": [".example.com"],
    "name": "Nom du Provider",
    "icon": "🎨"
}
```

---

## 📝 Notes importantes

### Rate limiting

- Scanner : 50 threads parallèles, 3s timeout
- Scan batch : 100 IPs à la fois
- Pas de limite d'API externe utilisée

### Ranges d'IPs

Pour le MVP, le scanner utilise des ranges de test.

**Pour la prod**, intégrez une vraie source d'IPs :

- RIPE API : `https://stat.ripe.net/data/country-resource-list/data.json?resource=FR`
- ipinfo.io : API gratuite 50k req/mois
- MaxMind GeoLite2 : Database téléchargeable

### Coûts

- **Clever Cloud** : Gratuit (Nano instance + PostgreSQL free tier)
- **GitHub Actions** : Gratuit (2000 min/mois)
- **Total** : 0€/mois

---

## 🐛 Troubleshooting

### "Invalid API key"

Vérifiez que `API_KEY` est identique dans :
- Clever Cloud env vars
- GitHub Secrets

### Pas de résultats après 1h

1. Vérifiez les logs GitHub Actions
2. Vérifiez que l'API endpoint est accessible
3. Vérifiez les logs Clever Cloud : `clever logs`

### Base de données vide

Initialisez manuellement :

```bash
clever ssh
python3 -c "from app import init_db; init_db()"
exit
```

---

## 📧 Support

Créez une issue GitHub pour toute question ou bug.

---

## 📄 License

MIT
