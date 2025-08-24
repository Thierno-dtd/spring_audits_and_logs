package module.auditslogs.controllers;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import module.auditslogs.constants.Utils;
import module.auditslogs.dto.ApiResponse;
import module.auditslogs.dto.AuditEventRequest;
import module.auditslogs.dto.SearchRequest;
import module.auditslogs.dto.SecurityEventRequest;
import module.auditslogs.services.AnalyticsService;
import module.auditslogs.services.AuditService;
import module.auditslogs.services.SecurityLogService;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping(Utils.AUDIT_API)
@RequiredArgsConstructor
@Slf4j
@Validated
public class AuditApiController {

    private final AuditService auditService;
    private final SecurityLogService securityLogService;
    private final AnalyticsService analyticsService;

    /**
     * Enregistrer un événement d'audit - Version améliorée
     */
    @PostMapping("/log")
    public ResponseEntity<ApiResponse<?>> logAuditEvent(
            @Valid @RequestBody AuditEventRequest request,
            HttpServletRequest httpRequest) {

        try {
            // Validation avec Utils
            if (Utils.isEmpty(request.getEventType())) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error(Utils.Messages.ERROR_VALIDATION));
            }

            // Enrichissement automatique des données manquantes
            enrichAuditRequest(request, httpRequest);

            // Sanitisation sécurisée
            String sanitizedDetails = Utils.sanitizeForLog(request.getDetails());
            String sanitizedEmail = Utils.sanitizeForLog(request.getUserEmail());

            log.info("📝 Audit: {} pour {}", request.getEventType(), sanitizedEmail);

            auditService.logAuditEventFromApi(request);
            return ResponseEntity.ok(ApiResponse.success(Utils.Messages.SUCCESS));

        } catch (Exception e) {
            log.error("❌ Erreur audit: {}", Utils.sanitizeForLog(e.getMessage()), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error(Utils.Messages.ERROR_INTERNAL));
        }
    }

    /**
     * Enregistrer un événement de sécurité - Version optimisée
     */
    @PostMapping("/security")
    public ResponseEntity<ApiResponse<?>> logSecurityEvent(
            @Valid @RequestBody SecurityEventRequest request,
            HttpServletRequest httpRequest) {

        try {
            // Enrichissement sécurité
            enrichSecurityRequest(request, httpRequest);

            // Log critique immédiat si nécessaire
            if ("CRITICAL".equals(request.getThreatLevel())) {
                log.error("🚨 CRITIQUE: {} - {}",
                        request.getSecurityEvent(),
                        Utils.sanitizeForLog(request.getUserEmail()));
            }

            securityLogService.logSecurityEventFromApi(request);
            return ResponseEntity.ok(ApiResponse.success(Utils.Messages.SUCCESS));

        } catch (Exception e) {
            log.error("❌ Erreur sécurité: {}", Utils.sanitizeForLog(e.getMessage()), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error(Utils.Messages.ERROR_INTERNAL));
        }
    }

    /**
     * Recherche optimisée avec pagination
     */
    @GetMapping("/search")
    public ResponseEntity<ApiResponse<?>> searchAuditLogs(@Valid SearchRequest searchRequest) {
        try {
            // Validation des limites avec constantes Utils
            if (searchRequest.getSize() > Utils.Limits.MAX_PAGE_SIZE) {
                searchRequest.setSize(Utils.Limits.MAX_PAGE_SIZE);
            }
            if (searchRequest.getSize() <= 0) {
                searchRequest.setSize(Utils.Limits.DEFAULT_PAGE_SIZE);
            }

            var results = auditService.searchAuditLogs(searchRequest);
            return ResponseEntity.ok(ApiResponse.success(results));

        } catch (Exception e) {
            log.error("❌ Erreur recherche: {}", Utils.sanitizeForLog(e.getMessage()), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error(Utils.Messages.ERROR_INTERNAL));
        }
    }

    /**
     * Dashboard avec validation de période
     */
    @GetMapping("/dashboard")
    public ResponseEntity<ApiResponse<?>> getDashboard(
            @RequestParam(defaultValue = "24") int hours) {
        try {
            // Limiter la période pour éviter surcharge
            if (hours > 168) hours = 168; // Max 7 jours
            if (hours < 1) hours = 1;

            var dashboard = analyticsService.generateDashboard(hours);
            return ResponseEntity.ok(ApiResponse.success(dashboard));

        } catch (Exception e) {
            log.error("❌ Erreur dashboard: {}", Utils.sanitizeForLog(e.getMessage()), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error(Utils.Messages.ERROR_INTERNAL));
        }
    }

    /**
     * Health check simplifié et efficace
     */
    @GetMapping("/health")
    public ResponseEntity<ApiResponse<?>> healthCheck() {
        try {
            var health = auditService.performHealthCheck();
            boolean isUp = "UP".equals(health.get("status"));

            if (isUp) {
                return ResponseEntity.ok(ApiResponse.success(health));
            } else {
                return ResponseEntity.status(503).body(ApiResponse.error("Service dégradé"));
            }

        } catch (Exception e) {
            log.error("❌ Health check: {}", Utils.sanitizeForLog(e.getMessage()), e);
            return ResponseEntity.status(503).body(ApiResponse.error("Service indisponible"));
        }
    }

    /**
     * Métriques système
     */
    @GetMapping("/metrics")
    public ResponseEntity<ApiResponse<?>> getMetrics() {
        try {
            var metrics = analyticsService.getServiceMetrics();
            return ResponseEntity.ok(ApiResponse.success(metrics));
        } catch (Exception e) {
            log.error("❌ Erreur métriques: {}", Utils.sanitizeForLog(e.getMessage()), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error(Utils.Messages.ERROR_INTERNAL));
        }
    }

    /**
     * Export de données avec validation
     */
    @GetMapping("/export")
    public ResponseEntity<ApiResponse<?>> exportLogs(
            @RequestParam LocalDateTime startDate,
            @RequestParam LocalDateTime endDate,
            @RequestParam(defaultValue = "all") String logType) {
        try {
            // Validation période
            if (startDate.isAfter(endDate)) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error("Date de début postérieure à la date de fin"));
            }

            var exportData = auditService.exportLogs(startDate, endDate, logType);
            return ResponseEntity.ok(ApiResponse.success(exportData));

        } catch (Exception e) {
            log.error("❌ Erreur export: {}", Utils.sanitizeForLog(e.getMessage()), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error(Utils.Messages.ERROR_INTERNAL));
        }
    }

    // ========================================
    // MÉTHODES PRIVÉES D'ENRICHISSEMENT
    // ========================================

    private void enrichAuditRequest(AuditEventRequest request, HttpServletRequest httpRequest) {
        // Application name par défaut
        if (Utils.isEmpty(request.getApplicationName())) {
            request.setApplicationName(Utils.defaultIfNull(
                    httpRequest.getHeader("X-Application-Name"), "unknown-app"));
        }

        // IP address extraction
        if (Utils.isEmpty(request.getIpAddress())) {
            request.setIpAddress(extractClientIp(httpRequest));
        }

        // User agent
        if (Utils.isEmpty(request.getUserAgent())) {
            request.setUserAgent(httpRequest.getHeader("User-Agent"));
        }

        // Timestamp si absent
        if (request.getTimestamp() == null) {
            request.setTimestamp(LocalDateTime.now());
        }
    }

    private void enrichSecurityRequest(SecurityEventRequest request, HttpServletRequest httpRequest) {
        if (Utils.isEmpty(request.getApplicationName())) {
            request.setApplicationName(Utils.defaultIfNull(
                    httpRequest.getHeader("X-Application-Name"), "unknown-app"));
        }

        if (Utils.isEmpty(request.getIpAddress())) {
            request.setIpAddress(extractClientIp(httpRequest));
        }

        if (request.getTimestamp() == null) {
            request.setTimestamp(LocalDateTime.now());
        }
    }

    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (Utils.isNotEmpty(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (Utils.isNotEmpty(xRealIp)) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}