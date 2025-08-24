# 🔐 Microservice Audit & Logs

Un microservice Spring Boot complet pour la gestion centralisée des audits et logs de sécurité, avec intégration ELK Stack et API REST.

## 📋 Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Architecture](#architecture)
- [Prérequis](#prérequis)
- [Installation rapide](#installation-rapide)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Monitoring](#monitoring)
- [Maintenance](#maintenance)
- [Dépannage](#dépannage)

## 🎯 Vue d'ensemble

Ce microservice fournit :

- **API REST** pour la collecte d'événements d'audit et de sécurité
- **Base de données PostgreSQL** pour le stockage persistant
- **Stack ELK** (Elasticsearch, Logstash, Kibana) pour l'analyse avancée
- **Dashboard Kibana** pour la visualisation des données
- **Alertes en temps réel** pour les événements critiques
- **API multilingue** - Compatible avec n'importe quel langage de programmation

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Applications  │───▶│  Audit Service   │───▶│   PostgreSQL    │
│  (Any Language) │    │  (Spring Boot)   │    │   (Storage)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│     Kibana      │◀───│     Logstash     │◀───│  Log Aggregation│
│  (Dashboard)    │    │  (Processing)    │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  Elasticsearch   │
                       │   (Indexing)     │
                       └──────────────────┘
```

## ✅ Prérequis

- **Docker** 20.10+
- **Docker Compose** 2.0+
- **8 GB RAM** minimum (16 GB recommandé)
- **Ports disponibles** : 8080, 5432, 9200, 5601, 7001, 6379, 80

### Vérification rapide
```bash
make check-requirements
```

## 🚀 Installation rapide

### Option 1: Make (Recommandé)
```bash
# Installation complète
make install

# Ou démarrage rapide pour développement
make dev
```

### Option 2: Docker Compose
```bash
# Cloner et configurer
git clone <repository>
cd audit-logs-microservice

# Création des répertoires
mkdir -p logs nginx data/{elasticsearch,postgres,redis}

# Démarrage
docker-compose up -d

# Vérification
make status
```

### Option 3: Script automatique
```bash
# Rendre exécutable et lancer
chmod +x start.sh
./start.sh --auto
```

## ⚙️ Configuration

### Variables d'environnement principales

```bash
# Application
SPRING_PROFILES_ACTIVE=docker
SERVER_PORT=8080

# Base de données
SPRING_DATASOURCE_URL=jdbc:postgresql://postgres:5432/audit_db
SPRING_DATASOURCE_USERNAME=audit_user
SPRING_DATASOURCE_PASSWORD=audit_password

# ELK Stack
ELK_ENABLED=true
ELK_LOGSTASH_URL=http://logstash:7001

# Sécurité (optionnel)
AUDIT_SECURITY_API_KEY=your-secret-api-key
AUDIT_SECURITY_ENABLE_CSRF=false
```

### Fichiers de configuration

- `application-docker.properties` - Configuration Docker
- `logback-spring.xml` - Configuration des logs
- `logstash/config/logstash.yml` - Configuration Logstash
- `nginx/nginx.conf` - Configuration reverse proxy

## 📚 API Documentation

### Endpoints principaux

#### 📝 Enregistrement d'événements

```bash
# Événement d'audit
POST /api/v1/audit/log
Content-Type: application/json

{
  "eventType": "USER_LOGIN_SUCCESS",
  "userEmail": "user@example.com",
  "details": "Connexion réussie depuis mobile app",
  "ipAddress": "192.168.1.100",
  "applicationName": "mobile-app"
}
```

```bash
# Événement de sécurité
POST /api/v1/audit/security
Content-Type: application/json

{
  "securityEvent": "SUSPICIOUS_LOGIN_ATTEMPT",
  "userEmail": "user@example.com",
  "threatLevel": "HIGH",
  "ipAddress": "192.168.1.100",
  "description": "Tentative de connexion depuis pays suspect"
}
```

#### 📊 Consultation et recherche

```bash
# Dashboard
GET /api/v1/audit/dashboard?hours=24

# Recherche
GET /api/v1/audit/search?query=login&eventType=USER_LOGIN_FAILED

# Export (Admin seulement)
GET /api/v1/audit/export?startDate=2024-01-01T00:00:00&endDate=2024-01-31T23:59:59
```

#### 🏥 Monitoring

```bash
# Health check
GET /api/v1/audit/health

# Métriques
GET /api/v1/audit/metrics

# Alertes actives
GET /api/v1/audit/alerts
```

### Swagger UI
Une fois démarré, accédez à la documentation interactive :
```
http://localhost:8080/swagger-ui.html
```

## 📊 Monitoring

### URLs d'accès

| Service | URL | Description |
|---------|-----|-------------|
| **Application** | http://localhost:8080 | API principale |
| **Health Check** | http://localhost:8080/actuator/health | État de santé |
| **Kibana** | http://localhost:5601 | Dashboard et analyse |
| **Elasticsearch** | http://localhost:9200 | Moteur de recherche |
| **Swagger UI** | http://localhost:8080/swagger-ui.html | Documentation API |

### Commandes de monitoring

```bash
# État des services
make status

# Logs en temps réel
make logs-follow

# Logs de l'application seulement
make logs-app

# Monitoring continu
make monitor

# Métriques détaillées
make metrics
```

### Dashboard Kibana

1. Accédez à http://localhost:5601
2. Créez un index pattern : `audit-logs-*` et `security-logs-*`
3. Explorez vos données dans "Discover"
4. Créez des visualisations dans "Visualize"

## 🔧 Maintenance

### Commandes utiles

```bash
# Maintenance complète
make maintenance

# Sauvegarde base de données
make db-backup

# Nettoyage indices anciens
make es-clean-old

# Rotation des logs
make logs-rotate
```

### Surveillance proactive

```bash
# Vérification quotidienne
make health-detailed
make es-status
make db-connect

# Alertes automatiques (à configurer dans un cron)
0 8 * * * /path/to/project && make maintenance
```

## 🐛 Dépannage

### Problèmes courants

#### Service ne démarre pas
```bash
# Vérifier les ports
make ports-check

# Vérifier les logs
make logs

# Redémarrage complet
make restart
```

#### Base de données inaccessible
```bash
# Vérifier PostgreSQL
make db-connect

# Réinitialiser (attention: perte de données)
make db-reset
```

#### Elasticsearch en erreur
```bash
# État du cluster
make es-status

# Vérifier l'espace disque
df -h

# Nettoyer les anciens indices
make es-clean-old
```

#### Problèmes de mémoire
```bash
# Vérifier l'utilisation
docker stats

# Ajuster dans docker-compose.yml
services:
  elasticsearch:
    environment:
      - ES_JAVA_OPTS=-Xms1g -Xmx1g  # Réduire si nécessaire
```

### Logs de debug

```bash
# Activer le debug pour l'application
docker-compose exec audit-service \
  curl -X POST http://localhost:8080/actuator/loggers/module.auditslogs \
  -H "Content-Type: application/json" \
  -d '{"configuredLevel":"DEBUG"}'
```

### Restauration rapide

```bash
# En cas de problème majeur
make clean
make install

# Ou avec sauvegarde
make db-backup BACKUP_FILE=backups/latest.sql
make clean
make install
make db-restore BACKUP_FILE=backups/latest.sql
```

## 🔒 Sécurité

### Configuration de production

1. **Changez les mots de passe par défaut**
2. **Activez HTTPS avec des certificats SSL**
3. **Configurez un API Key** :
   ```properties
   audit.security.api-key=your-strong-secret-key
   ```
4. **Limitez l'accès réseau** (firewall, VPN)
5. **Activez les sauvegardes automatiques**

### Authentification API Key

```bash
# Requête avec API Key
curl -X POST http://localhost:8080/api/v1/audit/log \
  -H "X-API-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"eventType":"TEST","userEmail":"test@example.com"}'
```

## 📞 Support

### Commandes d'aide
```bash
make help          # Aide générale
make info          # Informations du projet
make docs          # Documentation
```

### Ressources utiles

- **Logs applicatifs** : `./logs/`
- **Backups** : `./backups/`
- **Configuration** : `application-docker.properties`
- **Docker Compose** : `docker-compose.yml`

---

## 📝 Exemple d'utilisation complète

### 1. Installation
```bash
git clone <repository>
cd audit-logs-microservice
make install
```

### 2. Test de l'API
```bash
# Test simple
curl -X POST http://localhost:8080/api/v1/audit/log \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "USER_LOGIN_SUCCESS",
    "userEmail": "john.doe@example.com",
    "details": "Login from mobile app",
    "ipAddress": "192.168.1.100"
  }'
```

### 3. Vérification dans Kibana
1. Ouvrir http://localhost:5601
2. Créer l'index pattern `audit-logs-*`
3. Voir les données dans "Discover"

### 4. Intégration dans votre application

**Python :**
```python
import requests

def log_audit_event(event_type, user_email, details):
    response = requests.post('http://localhost:8080/api/v1/audit/log', json={
        'eventType': event_type,
        'userEmail': user_email,
        'details': details,
        'applicationName': 'my-python-app'
    })
    return response.status_code == 200
```

**Node.js :**
```javascript
const axios = require('axios');

async function logAuditEvent(eventType, userEmail, details) {
    try {
        await axios.post('http://localhost:8080/api/v1/audit/log', {
            eventType,
            userEmail,
            details,
            applicationName: 'my-node-app'
        });
        return true;
    } catch (error) {
        console.error('Audit log failed:', error);
        return false;
    }
}
```

**Java :**
```java
@Service
public class AuditService {
    private final RestTemplate restTemplate = new RestTemplate();
    
    public void logEvent(String eventType, String userEmail, String details) {
        Map<String, Object> event = Map.of(
            "eventType", eventType,
            "userEmail", userEmail,
            "details", details,
            "applicationName", "my-java-app"
        );
        
        restTemplate.postForObject(
            "http://localhost:8080/api/v1/audit/log", 
            event, 
            String.class
        );
    }
}
```

---

**🎉 Votre microservice Audit & Logs est maintenant opérationnel !**

Pour toute question ou problème, consultez la section [Dépannage](#dépannage) ou vérifiez les logs avec `make logs-follow`.