# ========================================
# MAKEFILE - AUDIT LOGS MICROSERVICE
# ========================================

.DEFAULT_GOAL := help
.PHONY: help install dev build start stop restart clean logs status

# Variables
COMPOSE_FILE = docker-compose.yml
PROJECT_NAME = audit-logs-microservice
BACKUP_DIR = backups
LOG_DIR = logs

help: ## Afficher cette aide
	@echo "🔐 Microservice Audit & Logs - Commandes disponibles:"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ========================================
# INSTALLATION & CONFIGURATION
# ========================================

install: create-dirs build start health ## Installation complète
	@echo "✅ Installation terminée!"
	@echo "🌐 API: http://localhost:8080"
	@echo "📊 Kibana: http://localhost:5601"
	@echo "🔍 Swagger: http://localhost:8080/swagger-ui.html"

dev: create-dirs ## Démarrage rapide pour développement
	@echo "🚀 Démarrage en mode développement..."
	docker-compose up -d postgres elasticsearch logstash
	@sleep 10
	@echo "✅ Services de base démarrés"

create-dirs: ## Créer les répertoires nécessaires
	@echo "📁 Création des répertoires..."
	@mkdir -p $(LOG_DIR) $(BACKUP_DIR) data/{elasticsearch,postgres,redis} nginx
	@echo "✅ Répertoires créés"

# ========================================
# BUILD & DÉMARRAGE
# ========================================

build: ## Construire les images Docker
	@echo "🔨 Construction des images..."
	docker-compose build --no-cache

start: ## Démarrer tous les services
	@echo "🚀 Démarrage des services..."
	docker-compose up -d

stop: ## Arrêter tous les services
	@echo "🛑 Arrêt des services..."
	docker-compose down

restart: stop start ## Redémarrer tous les services

# ========================================
# MONITORING & LOGS
# ========================================

logs: ## Afficher tous les logs
	docker-compose logs

logs-follow: ## Suivre les logs en temps réel
	docker-compose logs -f

logs-app: ## Logs de l'application seulement
	docker-compose logs -f audit-service

status: ## Statut des services
	@echo "📊 Statut des services:"
	@docker-compose ps

health: ## Vérifier la santé des services
	@echo "🏥 Vérification santé..."
	@curl -s http://localhost:8080/api/v1/audit/health | jq . || echo "❌ Service non disponible"

# ========================================
# MAINTENANCE & NETTOYAGE
# ========================================

clean: stop ## Nettoyage complet (ATTENTION: supprime les données)
	@echo "⚠️  Nettoyage complet..."
	docker-compose down -v
	docker system prune -f
	@echo "✅ Nettoyage terminé"

clean-logs: ## Nettoyer les anciens logs
	@echo "🧹 Nettoyage des logs..."
	find $(LOG_DIR) -name "*.log.*" -mtime +30 -delete 2>/dev/null || true
	@echo "✅ Logs nettoyés"

# ========================================
# BASE DE DONNÉES
# ========================================

db-connect: ## Se connecter à la base de données
	docker-compose exec postgres psql -U audit_user -d audit_db

db-backup: ## Sauvegarder la base de données
	@echo "💾 Sauvegarde base de données..."
	@mkdir -p $(BACKUP_DIR)
	docker-compose exec postgres pg_dump -U audit_user audit_db > $(BACKUP_DIR)/backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "✅ Sauvegarde créée dans $(BACKUP_DIR)/"

db-restore: ## Restaurer la base de données (BACKUP_FILE=chemin)
	@echo "📥 Restauration base de données..."
	@test -n "$(BACKUP_FILE)" || (echo "❌ Spécifiez BACKUP_FILE=chemin"; exit 1)
	docker-compose exec -T postgres psql -U audit_user -d audit_db < $(BACKUP_FILE)
	@echo "✅ Base de données restaurée"

db-reset: ## Réinitialiser la base de données (ATTENTION: perte de données)
	@echo "⚠️  Réinitialisation base de données..."
	docker-compose exec postgres psql -U audit_user -d audit_db -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	@echo "✅ Base de données réinitialisée"

# ========================================
# ELASTICSEARCH
# ========================================

es-status: ## Statut d'Elasticsearch
	@echo "🔍 Statut Elasticsearch:"
	@curl -s http://localhost:9200/_cluster/health | jq . || echo "❌ Elasticsearch non disponible"

es-indices: ## Lister les indices Elasticsearch
	@curl -s http://localhost:9200/_cat/indices?v

es-clean-old: ## Nettoyer les anciens indices (plus de 30 jours)
	@echo "🧹 Nettoyage anciens indices..."
	@curl -X DELETE "localhost:9200/*-$(shell date -d '30 days ago' +%Y.%m.%d)" 2>/dev/null || true
	@echo "✅ Anciens indices supprimés"

# ========================================
# TESTS & VALIDATION
# ========================================

test-api: ## Tester l'API
	@echo "🧪 Test de l'API..."
	@curl -X POST http://localhost:8080/api/v1/audit/log \
		-H "Content-Type: application/json" \
		-d '{"eventType":"TEST","userEmail":"test@example.com","details":"Test depuis Makefile"}' \
		| jq . || echo "❌ Test échoué"

validate: health test-api ## Validation complète du système

# ========================================
# MONITORING AVANCÉ
# ========================================

monitor: ## Monitoring continu
	@echo "📊 Monitoring en cours... (Ctrl+C pour arrêter)"
	@while true; do \
		clear; \
		echo "=== AUDIT LOGS MICROSERVICE - MONITORING ==="; \
		echo "Heure: $$(date)"; \
		echo ""; \
		echo "Services:"; \
		docker-compose ps; \
		echo ""; \
		echo "Mémoire Docker:"; \
		docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" | head -6; \
		echo ""; \
		echo "Espace disque:"; \
		df -h | grep -E '/$|docker'; \
		sleep 5; \
	done

metrics: ## Afficher les métriques détaillées
	@echo "📈 Métriques du service:"
	@curl -s http://localhost:8080/actuator/metrics | jq . || echo "❌ Métriques non disponibles"

# ========================================
# UTILITAIRES
# ========================================

ports-check: ## Vérifier les ports utilisés
	@echo "🔌 Ports en écoute:"
	@netstat -tlnp | grep -E ':8080|:5432|:9200|:5601|:7001|:6379' || echo "Aucun port trouvé"

info: ## Informations système
	@echo "ℹ️  Informations système:"
	@echo "Docker version: $$(docker --version)"
	@echo "Docker Compose version: $$(docker-compose --version)"
	@echo "Répertoire projet: $$(pwd)"
	@echo "Espace libre: $$(df -h . | tail -1 | awk '{print $$4}')"

# ========================================
# DÉVELOPPEMENT
# ========================================

shell-app: ## Shell dans le conteneur application
	docker-compose exec audit-service /bin/bash

shell-db: ## Shell dans le conteneur PostgreSQL
	docker-compose exec postgres /bin/bash

tail-app: ## Suivre les logs application
	docker-compose logs -f audit-service

# ========================================
# VÉRIFICATIONS SYSTÈME
# ========================================

check-requirements: ## Vérifier les prérequis
	@echo "✅ Vérification des prérequis:"
	@command -v docker >/dev/null 2>&1 || (echo "❌ Docker non installé"; exit 1)
	@command -v docker-compose >/dev/null 2>&1 || (echo "❌ Docker Compose non installé"; exit 1)
	@echo "✅ Docker: $$(docker --version)"
	@echo "✅ Docker Compose: $$(docker-compose --version)"
	@echo "✅ Tous les prérequis sont satisfaits"

# Maintenance programmée (à lancer via cron)
maintenance: clean-logs es-clean-old ## Maintenance automatique