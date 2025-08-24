package module.auditslogs.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Value("${server.port:8080}")
    private String serverPort;

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .servers(List.of(
                        new Server().url("http://localhost:" + serverPort).description("Serveur local"),
                        new Server().url("http://audit-service:" + serverPort).description("Serveur Docker")
                ))
                .info(new Info()
                        .title("🔐 Audit & Logs Microservice API")
                        .version("1.0.0")
                        .description("""
                                ## Microservice centralisé pour la gestion des audits et logs de sécurité
                                
                                Cette API permet de :
                                - ✅ **Enregistrer** des événements d'audit et de sécurité
                                - 🔍 **Rechercher** dans les logs historiques  
                                - 📊 **Analyser** les données de sécurité
                                - 📈 **Monitorer** l'état du système
                                - 📤 **Exporter** des données pour compliance
                                
                                ### Fonctionnalités principales
                                - API REST multilingue (compatible avec tout langage)
                                - Intégration ELK Stack (Elasticsearch, Logstash, Kibana)
                                - Stockage PostgreSQL pour persistance
                                - Rate limiting intégré
                                - Alertes temps réel pour événements critiques
                                
                                ### Endpoints principaux
                                - `POST /api/v1/audit/log` - Enregistrer un événement d'audit
                                - `POST /api/v1/audit/security` - Enregistrer un événement de sécurité
                                - `GET /api/v1/audit/search` - Rechercher dans les logs
                                - `GET /api/v1/audit/dashboard` - Dashboard avec métriques
                                """)
                        .contact(new Contact()
                                .name("Équipe Sécurité")
                                .email("security@company.com")
                                .url("https://github.com/company/audit-logs-microservice"))
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT")));
    }
}