#!/bin/bash

# ========================================
# SCRIPT DE DÉMARRAGE - AUDIT LOGS MICROSERVICE
# ========================================

set -e

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="audit-logs-microservice"
COMPOSE_FILE="docker-compose.yml"

print_header() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "🔐 AUDIT LOGS MICROSERVICE"
    echo "   Démarrage automatique"
    echo "=========================================="
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Vérification des prérequis
check_requirements() {
    print_info "Vérification des prérequis..."

    if ! command -v docker &> /dev/null; then
        print_error "Docker n'est pas installé"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose n'est pas installé"
        exit 1
    fi

    print_success "Prérequis validés"
}

# Création des répertoires nécessaires
create_directories() {
    print_info "Création des répertoires..."

    directories=(
        "logs"
        "backups"
        "data/elasticsearch"
        "data/postgres"
        "data/redis"
        "nginx"
        "init-scripts"
    )

    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        echo "📁 Répertoire créé: $dir"
    done

    # Créer un script d'initialisation PostgreSQL basique
    cat > init-scripts/01-init.sql << 'EOF'
-- Script d'initialisation PostgreSQL
-- Création d'extensions utiles
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Configuration timezone
SET timezone = 'UTC';

-- Logs d'initialisation
SELECT 'Base de données audit_db initialisée avec succès' as message;
EOF

    print_success "Répertoires créés"
}

# Configuration des permissions
setup_permissions() {
    print_info "Configuration des permissions..."

    # Elasticsearch a besoin de permissions spéciales
    if [ -d "data/elasticsearch" ]; then
        sudo chown -R 1000:1000 data/elasticsearch 2>/dev/null || {
            print_warning "Impossible de changer les permissions Elasticsearch (sudo requis)"
        }
    fi

    # Logstash
    if [ -d "logstash" ]; then
        chmod -R 755 logstash/ 2>/dev/null || true
    fi

    print_success "Permissions configurées"
}

# Vérification des ports
check_ports() {
    print_info "Vérification des ports..."

    ports=(8080 5432 9200 5601 7001 6379 80)
    used_ports=()

    for port in "${ports[@]}"; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            used_ports+=($port)
        elif ss -tuln 2>/dev/null | grep -q ":$port "; then
            used_ports+=($port)
        fi
    done

    if [ ${#used_ports[@]} -gt 0 ]; then
        print_warning "Ports déjà utilisés: ${used_ports[*]}"
        read -p "Continuer malgré tout? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        print_success "Tous les ports sont disponibles"
    fi
}

# Démarrage des services
start_services() {
    print_info "Démarrage des services..."

    # Arrêter les services existants
    docker-compose down 2>/dev/null || true

    # Construire et démarrer
    echo "🔨 Construction des images..."
    docker-compose build --no-cache

    echo "🚀 Démarrage des services..."
    docker-compose up -d

    print_success "Services démarrés"
}

# Attendre que les services soient prêts
wait_for_services() {
    print_info "Attente de la disponibilité des services..."

    # PostgreSQL
    echo -n "⏳ PostgreSQL..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if docker-compose exec -T postgres pg_isready -U audit_user -d audit_db &>/dev/null; then
            echo " ✅"
            break
        fi
        sleep 2
        timeout=$((timeout-2))
        echo -n "."
    done

    # Elasticsearch
    echo -n "⏳ Elasticsearch..."
    timeout=120
    while [ $timeout -gt 0 ]; do
        if curl -s http://localhost:9200/_cluster/health &>/dev/null; then
            echo " ✅"
            break
        fi
        sleep 3
        timeout=$((timeout-3))
        echo -n "."
    done

    # Application
    echo -n "⏳ Application..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if curl -s http://localhost:8080/api/v1/audit/health &>/dev/null; then
            echo " ✅"
            break
        fi
        sleep 3
        timeout=$((timeout-3))
        echo -n "."
    done

    print_success "Tous les services sont prêts"
}

# Test de l'API
test_api() {
    print_info "Test de l'API..."

    response=$(curl -s -X POST http://localhost:8080/api/v1/audit/log \
        -H "Content-Type: application/json" \
        -d '{
            "eventType": "SYSTEM_STARTUP",
            "userEmail": "system@localhost",
            "details": "Microservice démarré avec succès",
            "ipAddress": "127.0.0.1"
        }' || echo "ERROR")

    if [[ "$response" == *"success"* ]]; then
        print_success "Test API réussi"
    else
        print_warning "Test API échoué, mais le service fonctionne"
    fi
}

# Affichage des informations finales
show_final_info() {
    echo -e "${GREEN}"
    echo "=========================================="
    echo "🎉 DÉMARRAGE TERMINÉ AVEC SUCCÈS!"
    echo "=========================================="
    echo -e "${NC}"

    echo "🌐 Services disponibles:"
    echo "   • API principale:     http://localhost:8080"
    echo "   • Documentation:      http://localhost:8080/swagger-ui.html"
    echo "   • Health check:       http://localhost:8080/api/v1/audit/health"
    echo "   • Dashboard Kibana:   http://localhost:5601"
    echo "   • Elasticsearch:      http://localhost:9200"
    echo "   • Interface H2:       http://localhost:8080/h2-console (dev)"
    echo ""

    echo "📊 Commandes utiles:"
    echo "   • make status         # Statut des services"
    echo "   • make logs           # Voir les logs"
    echo "   • make stop           # Arrêter les services"
    echo "   • make health         # Vérifier la santé"
    echo ""

    echo "📝 Exemple de test API:"
    echo 'curl -X POST http://localhost:8080/api/v1/audit/log \'
    echo '  -H "Content-Type: application/json" \'
    echo '  -d "{\"eventType\":\"TEST\",\"userEmail\":\"test@example.com\"}"'
    echo ""
}

# Fonction principale
main() {
    print_header

    # Mode automatique si --auto
    if [[ "$1" == "--auto" ]]; then
        AUTO_MODE=true
    else
        AUTO_MODE=false
    fi

    # Étapes d'installation
    check_requirements
    create_directories

    if [[ "$AUTO_MODE" == "false" ]]; then
        read -p "📋 Continuer avec l'installation? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    setup_permissions
    check_ports
    start_services
    wait_for_services

    # Test optionnel
    if [[ "$AUTO_MODE" == "false" ]]; then
        read -p "🧪 Effectuer un test de l'API? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            test_api
        fi
    else
        test_api
    fi

    show_final_info
}

# Gestion des signaux
trap 'print_error "Installation interrompue"; exit 1' INT TERM

# Point d'entrée
main "$@"