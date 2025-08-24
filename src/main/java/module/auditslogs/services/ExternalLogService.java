package module.auditslogs.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import module.auditslogs.constants.Utils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class ExternalLogService {

    private final RestTemplate restTemplate;
    private final boolean elkEnabled;
    private final String logstashUrl;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ExternalLogService(RestTemplate restTemplate, boolean elkEnabled, String logstashUrl) {
        this.restTemplate = restTemplate;
        this.elkEnabled = elkEnabled;
        this.logstashUrl = logstashUrl;
    }

    @Async
    public void sendToLogstash(String eventType, String userEmail, String details,
                               String ipAddress, String threatLevel) {
        if (!elkEnabled) {
            log.debug("ELK Stack désactivé, skip envoi Logstash");
            return;
        }

        if (Utils.isEmpty(logstashUrl)) {
            log.warn("⚠️ URL Logstash non configurée");
            return;
        }

        try {
            Map<String, Object> logData = buildLogData(eventType, userEmail, details, ipAddress, threatLevel);
            sendLogData(logData);

            log.debug("✅ Log envoyé vers Logstash: {}", eventType);

        } catch (Exception e) {
            log.error("❌ Erreur envoi Logstash: {}", Utils.sanitizeForLog(e.getMessage()));
            // Fallback vers log local
            logFallback(eventType, userEmail, details);
        }
    }

    @Async
    public void sendSecurityAlert(String securityEvent, String userEmail, String threatLevel,
                                  String description, String ipAddress) {

        // Envoi standard vers Logstash
        sendToLogstash(securityEvent, userEmail, description, ipAddress, threatLevel);

        // Traitement spécial pour les alertes critiques
        if ("CRITICAL".equals(threatLevel)) {
            sendCriticalAlert(securityEvent, userEmail, description, ipAddress);
        }
    }

    private Map<String, Object> buildLogData(String eventType, String userEmail, String details,
                                             String ipAddress, String threatLevel) {
        Map<String, Object> logData = new HashMap<>();

        logData.put("@timestamp", LocalDateTime.now().toString());
        logData.put("application", "security-api");
        logData.put("log_type", "audit");
        logData.put("eventType", Utils.defaultIfNull(eventType, "UNKNOWN"));
        logData.put("userEmail", Utils.sanitizeForLog(userEmail));
        logData.put("details", Utils.sanitizeForLog(details));
        logData.put("ipAddress", Utils.defaultIfNull(ipAddress, "unknown"));
        logData.put("threatLevel", Utils.defaultIfNull(threatLevel, "LOW"));
        logData.put("environment", getEnvironment());
        logData.put("server", getServerName());

        return logData;
    }

    private void sendLogData(Map<String, Object> logData) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("User-Agent", "audit-microservice/1.0");

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(logData, headers);

        // Timeout configuré dans RestTemplate
        restTemplate.postForEntity(logstashUrl, request, String.class);
    }

    private void sendCriticalAlert(String event, String userEmail, String description, String ipAddress) {
        try {
            Map<String, Object> alert = buildCriticalAlert(event, userEmail, description, ipAddress);

            log.error("🚨 ALERTE CRITIQUE: {} - {} - IP: {}",
                    event, Utils.sanitizeForLog(description), ipAddress);

            // Tentative d'envoi vers endpoint d'alerte si configuré
            sendAlertIfConfigured(alert);

        } catch (Exception e) {
            log.error("❌ Erreur alerte critique: {}", Utils.sanitizeForLog(e.getMessage()));
        }
    }

    private Map<String, Object> buildCriticalAlert(String event, String userEmail, String description, String ipAddress) {
        Map<String, Object> alert = new HashMap<>();
        alert.put("timestamp", LocalDateTime.now().toString());
        alert.put("severity", "CRITICAL");
        alert.put("event", event);
        alert.put("user", Utils.sanitizeForLog(userEmail));
        alert.put("description", Utils.sanitizeForLog(description));
        alert.put("source_ip", ipAddress);
        alert.put("application", "security-api");
        alert.put("requires_immediate_action", true);

        return alert;
    }

    private void sendAlertIfConfigured(Map<String, Object> alert) {
        // Placeholder pour système d'alerte externe
        // Peut être étendu pour envoyer vers Slack, email, webhook, etc.
        log.info("📧 Alerte critique prête pour notification externe");
    }

    private void logFallback(String eventType, String userEmail, String details) {
        log.warn("LOGSTASH_FALLBACK: {} - {} - {}",
                eventType,
                Utils.sanitizeForLog(userEmail),
                Utils.sanitizeForLog(details));
    }

    private String getEnvironment() {
        return Utils.defaultIfNull(System.getProperty("spring.profiles.active"), "unknown");
    }

    private String getServerName() {
        return Utils.defaultIfNull(System.getenv("HOSTNAME"), "localhost");
    }

    // ========================================
    // MÉTHODES PUBLIQUES UTILITAIRES
    // ========================================

    public boolean isElkEnabled() {
        return elkEnabled;
    }

    public String getLogstashUrl() {
        return logstashUrl;
    }

    public void testConnection() {
        if (!elkEnabled) {
            log.info("ℹ️ ELK Stack désactivé");
            return;
        }

        try {
            Map<String, Object> testData = new HashMap<>();
            testData.put("test", true);
            testData.put("timestamp", LocalDateTime.now().toString());

            sendLogData(testData);
            log.info("✅ Connexion Logstash OK");

        } catch (Exception e) {
            log.error("❌ Test connexion Logstash échoué: {}", Utils.sanitizeForLog(e.getMessage()));
        }
    }

    @Async
    public void sendBatchLogs(java.util.List<Map<String, Object>> logsBatch) {
        if (!elkEnabled || logsBatch == null || logsBatch.isEmpty()) {
            return;
        }

        try {
            // Limiter la taille du batch
            int maxBatchSize = Utils.Limits.MAX_EVENTS_PER_BATCH;
            if (logsBatch.size() > maxBatchSize) {
                log.warn("⚠️ Batch Logstash trop volumineux: {}, traitement des {} premiers",
                        logsBatch.size(), maxBatchSize);
                logsBatch = logsBatch.subList(0, maxBatchSize);
            }

            for (Map<String, Object> logData : logsBatch) {
                try {
                    sendLogData(logData);
                } catch (Exception e) {
                    log.warn("⚠️ Erreur envoi log batch: {}", Utils.sanitizeForLog(e.getMessage()));
                }
            }

            log.debug("✅ Batch envoyé vers Logstash: {} logs", logsBatch.size());

        } catch (Exception e) {
            log.error("❌ Erreur batch Logstash: {}", Utils.sanitizeForLog(e.getMessage()));
        }
    }
}