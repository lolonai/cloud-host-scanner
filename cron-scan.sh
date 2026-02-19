#!/bin/bash
# Cron job - Lance le scanner toutes les heures

cd /home/bas/app_*/

# Liste des pays à scanner
COUNTRIES=("FR" "BE" "CH" "GB" "DE" "ES" "IT" "US" "CA")

# Scanner un pays aléatoire
COUNTRY=${COUNTRIES[$RANDOM % ${#COUNTRIES[@]}]}

echo "🌍 Scan automatique - Pays: $COUNTRY"

# Lancer le scanner
python3 scanner.py

echo "✅ Scan terminé"
