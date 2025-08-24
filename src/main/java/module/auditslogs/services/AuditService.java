package module.auditslogs.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import module.auditslogs.constants.ThreatLevel;
import module.auditslogs.dto.AuditEventRequest;
import module.auditslogs.dto.SearchRequest;
import module.auditslogs.entities.AuditLog;
import module.auditslogs.entities.SecurityLog;
import module.auditslogs.repositories.AuditLogRepository;
import module.auditslogs.repositories.SecurityLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Slf4j
public class AuditService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private SecurityLogRepository securityLogRepository;

    @Autowired
    private IpAddressService ipAddressService;

    @Autowired
    private ExternalLogService externalLogService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Async("auditTaskExecutor")
    @Transactional
    public void logAuditEvent(String eventType, String userEmail, String details,
                              HttpServletRequest request, Long executionTime) {
        try {
            IpAddressService.IpInfo ipInfo = ipAddressService.getDetailedIpInfo(request);
            String sessionId = extractSessionId(request);
            String threatLevel = determineThreatLevel(eventType, ipInfo);

            AuditLog auditLog = AuditLog.builder()
                    .timestamp(LocalDateTime.now())
                    .eventType(eventType)
                    .userEmail(userEmail)
                    .details(details)
                    .ipAddress(ipInfo.getIpAddress())
                    .userAgent(ipInfo.getUserAgent())
                    .requestUri(ipInfo.getRequestUri())
                    .httpMethod(ipInfo.getMethod())
                    .sessionId(sessionId)
                    .executionTime(executionTime)
                    .threatLevel(threatLevel)
                    .additionalData(createAdditionalData(ipInfo))
                    .build();

            auditLogRepository.save(auditLog);

            // Envoi vers ELK Stack de manière asynchrone
            externalLogService.sendToLogstash(eventType, userEmail, details,
                    ipInfo.getIpAddress(), threatLevel);

            log.info("AUDIT: {} - {} - {} | Session: {} | {}",
                    eventType, userEmail, details, sessionId, ipInfo.toString());

        } catch (Exception e) {
            log.error("Erreur sauvegarde audit DB, fallback vers fichier", e);
            log.warn("AUDIT_FALLBACK: {} - {} - {}", eventType, userEmail, details);
        }
    }

    @Async("auditTaskExecutor")
    @Transactional
    public void logSecurityEvent(String securityEvent, String userEmail, String threatLevel,
                                 String description, HttpServletRequest request) {
        try {
            IpAddressService.IpInfo ipInfo = ipAddressService.getDetailedIpInfo(request);

            SecurityLog securityLog = SecurityLog.builder()
                    .timestamp(LocalDateTime.now())
                    .securityEvent(securityEvent)
                    .userEmail(userEmail)
                    .threatLevel(threatLevel)
                    .ipAddress(ipInfo.getIpAddress())
                    .description(description + " | " + ipInfo.toString())
                    .blocked(shouldBlockBasedOnThreat(threatLevel))
                    .build();

            securityLogRepository.save(securityLog);

            // Envoi vers ELK Stack
            externalLogService.sendSecurityAlert(securityEvent, userEmail, threatLevel,
                    description, ipInfo.getIpAddress());

            log.warn("SECURITY: {} - {} - {} - {} | IP Info: {}",
                    securityEvent, userEmail, threatLevel, description, ipInfo.toString());

            if ("CRITICAL".equals(threatLevel)) {
                notifySecurityTeam(securityLog);
            }

        } catch (Exception e) {
            log.error("Erreur sauvegarde security DB, fallback vers fichier", e);
            log.error("SECURITY_FALLBACK: {} - {} - {} - {}", securityEvent, userEmail, threatLevel, description);
        }
    }

    /**
     * Enregistrer un événement d'audit depuis l'API REST
     */
    @Transactional
    public void logAuditEventFromApi(AuditEventRequest request) {
        try {
            String threatLevel = determineThreatLevelFromEvent(request.getEventType());

            AuditLog auditLog = AuditLog.builder()
                    .timestamp(request.getTimestamp() != null ? request.getTimestamp() : LocalDateTime.now())
                    .eventType(request.getEventType())
                    .userEmail(request.getUserEmail())
                    .details(request.getDetails())
                    .ipAddress(request.getIpAddress())
                    .userAgent(request.getUserAgent())
                    .requestUri(request.getRequestUri())
                    .httpMethod(request.getHttpMethod())
                    .sessionId(request.getSessionId())
                    .executionTime(request.getExecutionTime())
                    .threatLevel(threatLevel)
                    .additionalData(serializeAdditionalData(request.getAdditionalData()))
                    .build();

            auditLogRepository.save(auditLog);

            // Envoi vers ELK Stack
            externalLogService.sendToLogstash(
                    request.getEventType(),
                    request.getUserEmail(),
                    request.getDetails(),
                    request.getIpAddress(),
                    threatLevel
            );

            log.info("✅ Événement d'audit API enregistré: {} pour {}",
                    request.getEventType(), request.getUserEmail());

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'enregistrement de l'audit API", e);
            throw new RuntimeException("Erreur enregistrement audit", e);
        }
    }

    /**
     * Recherche dans les logs d'audit
     */
    public Map<String, Object> searchAuditLogs(SearchRequest searchRequest) {
        try {
            Pageable pageable = PageRequest.of(
                    searchRequest.getPage(),
                    searchRequest.getSize(),
                    Sort.Direction.fromString(searchRequest.getSortDirection()),
                    searchRequest.getSortBy()
            );

            Page<AuditLog> results;

            // Recherche selon les critères
            if (searchRequest.getUserEmail() != null && !searchRequest.getUserEmail().isEmpty()) {
                results = auditLogRepository.findByUserEmailContainingIgnoreCase(
                        searchRequest.getUserEmail(), pageable);
            } else if (searchRequest.getEventType() != null && !searchRequest.getEventType().isEmpty()) {
                results = auditLogRepository.findByEventType(searchRequest.getEventType(), pageable);
            } else if (searchRequest.getStartDate() != null && searchRequest.getEndDate() != null) {
                results = auditLogRepository.findByTimestampBetween(
                        searchRequest.getStartDate(), searchRequest.getEndDate(), pageable);
            } else {
                results = auditLogRepository.findAll(pageable);
            }

            Map<String, Object> response = new HashMap<>();
            response.put("content", results.getContent());
            response.put("totalElements", results.getTotalElements());
            response.put("totalPages", results.getTotalPages());
            response.put("currentPage", results.getNumber());
            response.put("size", results.getSize());

            return response;

        } catch (Exception e) {
            log.error("❌ Erreur lors de la recherche", e);
            throw new RuntimeException("Erreur recherche logs", e);
        }
    }

    /**
     * Export des logs pour compliance
     */
    public Map<String, Object> exportLogs(LocalDateTime startDate, LocalDateTime endDate, String logType) {
        try {
            Pageable limit = PageRequest.of(0, 10000, Sort.by("timestamp").ascending());

            Map<String, Object> exportData = new HashMap<>();

            if ("audit".equalsIgnoreCase(logType) || "all".equalsIgnoreCase(logType)) {
                Page<AuditLog> auditLogs = auditLogRepository.findByTimestampBetween(startDate, endDate, limit);
                exportData.put("auditLogs", auditLogs.getContent());
                exportData.put("auditCount", auditLogs.getTotalElements());
            }

            if ("security".equalsIgnoreCase(logType) || "all".equalsIgnoreCase(logType)) {
                Page<SecurityLog> securityLogs = securityLogRepository.findByTimestampBetween(startDate, endDate, limit);
                exportData.put("securityLogs", securityLogs.getContent());
                exportData.put("securityCount", securityLogs.getTotalElements());
            }

            exportData.put("exportDate", LocalDateTime.now());
            exportData.put("period", Map.of("start", startDate, "end", endDate));

            return exportData;

        } catch (Exception e) {
            log.error("❌ Erreur lors de l'export", e);
            throw new RuntimeException("Erreur export logs", e);
        }
    }

    /**
     * Traitement par batch des événements
     */
    @Transactional
    public int processBatchEvents(Map<String, Object> batchRequest) {
        try {
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> events = (List<Map<String, Object>>) batchRequest.get("events");

            if (events == null || events.isEmpty()) {
                return 0;
            }

            int processedCount = 0;
            for (Map<String, Object> eventData : events) {
                try {
                    AuditEventRequest auditEvent = convertToAuditEventRequest(eventData);
                    logAuditEventFromApi(auditEvent);
                    processedCount++;
                } catch (Exception e) {
                    log.warn("⚠️ Erreur traitement événement batch: {}", e.getMessage());
                }
            }

            log.info("✅ Batch traité: {}/{} événements", processedCount, events.size());
            return processedCount;

        } catch (Exception e) {
            log.error("❌ Erreur traitement batch", e);
            throw new RuntimeException("Erreur traitement batch", e);
        }
    }

    /**
     * Health check du service
     */
    public Map<String, Object> performHealthCheck() {
        Map<String, Object> health = new HashMap<>();

        try {
            // Test base de données
            long auditCount = auditLogRepository.count();
            health.put("database", "UP");
            health.put("auditLogsCount", auditCount);

            // Test ELK Stack (optionnel)
            health.put("elkStack", "UNKNOWN"); // À implémenter si besoin

            health.put("status", "UP");
            health.put("timestamp", LocalDateTime.now());
            health.put("version", "1.0.0");

        } catch (Exception e) {
            log.error("❌ Health check échoué", e);
            health.put("status", "DOWN");
            health.put("error", e.getMessage());
        }

        return health;
    }

    // ========================================
    // MÉTHODES PRIVÉES UTILITAIRES
    // ========================================

    private String determineThreatLevel(String eventType, IpAddressService.IpInfo ipInfo) {
        if (eventType.contains("LOGIN_FAILED") && !ipInfo.isLocalhost()) {
            return ThreatLevel.MEDIUM.name();
        }
        if (eventType.contains("SECURITY_BREACH") || eventType.contains("UNAUTHORIZED")) {
            return ThreatLevel.HIGH.name();
        }
        if (eventType.contains("ADMIN_ACTION") && !ipInfo.isPrivateNetwork()) {
            return ThreatLevel.MEDIUM.name();
        }
        return ThreatLevel.LOW.name();
    }

    private String determineThreatLevelFromEvent(String eventType) {
        if (eventType.contains("LOGIN_FAILED")) {
            return ThreatLevel.MEDIUM.name();
        }
        if (eventType.contains("SECURITY_") || eventType.contains("UNAUTHORIZED")) {
            return ThreatLevel.HIGH.name();
        }
        if (eventType.contains("ADMIN_")) {
            return ThreatLevel.MEDIUM.name();
        }
        return ThreatLevel.LOW.name();
    }

    private String createAdditionalData(IpAddressService.IpInfo ipInfo) {
        try {
            Map<String, Object> additionalData = new HashMap<>();
            additionalData.put("isLocalhost", ipInfo.isLocalhost());
            additionalData.put("isPrivateNetwork", ipInfo.isPrivateNetwork());
            additionalData.put("timestamp", LocalDateTime.now().toString());
            return objectMapper.writeValueAsString(additionalData);
        } catch (Exception e) {
            log.warn("⚠️ Erreur création données additionnelles: {}", e.getMessage());
            return "{}";
        }
    }

    private String serializeAdditionalData(Map<String, Object> additionalData) {
        if (additionalData == null) return "{}";
        try {
            return objectMapper.writeValueAsString(additionalData);
        } catch (Exception e) {
            log.warn("⚠️ Erreur sérialisation données additionnelles: {}", e.getMessage());
            return "{}";
        }
    }

    private boolean shouldBlockBasedOnThreat(String threatLevel) {
        return "CRITICAL".equals(threatLevel) || "HIGH".equals(threatLevel);
    }

    private void notifySecurityTeam(SecurityLog securityLog) {
        log.error("🚨 ALERTE CRITIQUE: {} - IP: {}",
                securityLog.getDescription(), securityLog.getIpAddress());
        // TODO: Implémenter notification (email, webhook, etc.)
    }

    private String extractSessionId(HttpServletRequest request) {
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                return session.getId();
            }
            return "temp-" + UUID.randomUUID().toString().substring(0, 8);
        } catch (Exception e) {
            log.debug("Impossible d'extraire l'ID de session: {}", e.getMessage());
            return "unknown-" + System.currentTimeMillis();
        }
    }

    private AuditEventRequest convertToAuditEventRequest(Map<String, Object> eventData) {
        // Conversion Map vers AuditEventRequest
        return AuditEventRequest.builder()
                .eventType((String) eventData.get("eventType"))
                .userEmail((String) eventData.get("userEmail"))
                .details((String) eventData.get("details"))
                .ipAddress((String) eventData.get("ipAddress"))
                .userAgent((String) eventData.get("userAgent"))
                .build();
    }

    /**
     * Méthodes publiques pour usage simple
     */
    public void logUserAction(String action, String userEmail, HttpServletRequest request) {
        logAuditEvent("USER_ACTION", userEmail, action, request, null);
    }

    public void logAuthenticationAttempt(String result, String userEmail, HttpServletRequest request) {
        String eventType = "USER_LOGIN_" + result.toUpperCase();
        String details = "Tentative de connexion: " + result;

        logAuditEvent(eventType, userEmail, details, request, null);

        if ("FAILED".equals(result.toUpperCase())) {
            logSecurityEvent("LOGIN_FAILURE", userEmail, ThreatLevel.MEDIUM.name(),
                    "Échec de connexion", request);
        }
    }
}