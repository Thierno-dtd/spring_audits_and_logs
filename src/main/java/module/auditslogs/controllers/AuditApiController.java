package module.auditslogs.controllers;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import module.auditslogs.dto.ApiResponse;
import module.auditslogs.dto.AuditEventRequest;
import module.auditslogs.dto.SearchRequest;
import module.auditslogs.dto.SecurityEventRequest;
import module.auditslogs.services.AuditService;
import org.springframework.data.domain.PageRequest;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
@Slf4j
@Validated
public class AuditApiController {

    private final AuditService auditService;
    private final SecurityLogService securityLogService;
    private final AnalyticsService analyticsService;

    // ========================================
    // ENDPOINTS POUR ENREGISTREMENT DES ÉVÉNEMENTS
    // ========================================

    /**
     * Enregistrer un événement d'audit
     * POST /api/v1/audit/log
     */
    @PostMapping("/log")
    public ResponseEntity<ApiResponse<?>> logAuditEvent(@Valid @RequestBody AuditEventRequest request) {
        try {
            log.info("📝 Réception événement audit: {} pour {}", request.getEventType(), request.getUserEmail());

            auditService.logAuditEventFromApi(request);

            return ResponseEntity.ok(ApiResponse.success("Événement d'audit enregistré avec succès"));

        } catch (Exception e) {
            log.error("❌ Erreur enregistrement audit: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error("Erreur lors de l'enregistrement de l'audit"));
        }
    }

    /**
     * Enregistrer un événement de sécurité
     * POST /api/v1/audit/security
     */
    @PostMapping("/security")
    public ResponseEntity<ApiResponse<?>> logSecurityEvent(@Valid @RequestBody SecurityEventRequest request) {
        try {
            log.warn("🔐 Réception événement sécurité: {} - Niveau: {}",
                    request.getSecurityEvent(), request.getThreatLevel());

            securityLogService.logSecurityEventFromApi(request);

            return ResponseEntity.ok(ApiResponse.success("Événement de sécurité enregistré avec succès"));

        } catch (Exception e) {
            log.error("❌ Erreur enregistrement sécurité: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error("Erreur lors de l'enregistrement de l'événement de sécurité"));
        }
    }

    /**
     * Enregistrement batch (pour performance)
     * POST /api/v1/audit/batch
     */
    @PostMapping("/batch")
    public ResponseEntity<ApiResponse<?>> logBatchEvents(@Valid @RequestBody Map<String, Object> batchRequest) {
        try {
            int processedEvents = auditService.processBatchEvents(batchRequest);

            return ResponseEntity.ok(ApiResponse.success(
                    String.format("%d événements traités avec succès", processedEvents)
            ));

        } catch (Exception e) {
            log.error("❌ Erreur traitement batch: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error("Erreur lors du traitement batch"));
        }
    }

    // ========================================
    // ENDPOINTS DE RECHERCHE ET CONSULTATION
    // ========================================

    /**
     * Recherche dans les logs d'audit
     * GET /api/v1/audit/search
     */
    @GetMapping("/search")
    public ResponseEntity<ApiResponse<?>> searchAuditLogs(@Valid SearchRequest searchRequest) {
        try {
            var results = auditService.searchAuditLogs(searchRequest);
            return ResponseEntity.ok(ApiResponse.success(results));

        } catch (Exception e) {
            log.error("❌ Erreur recherche: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error("Erreur lors de la recherche"));
        }
    }

    /**
     * Dashboard principal avec métriques
     * GET /api/v1/audit/dashboard
     */
    @GetMapping("/dashboard")
    public ResponseEntity<ApiResponse<?>> getDashboard(
            @RequestParam(defaultValue = "24") int hours) {
        try {
            var dashboardData = analyticsService.generateDashboard(hours);
            return ResponseEntity.ok(ApiResponse.success(dashboardData));

        } catch (Exception e) {
            log.error("❌ Erreur génération dashboard: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error("Erreur lors de la génération du dashboard"));
        }
    }

    /**
     * Analyse de sécurité en temps réel
     * GET /api/v1/audit/security/analysis
     */
    @GetMapping("/security/analysis")
    public ResponseEntity<ApiResponse<?>> getSecurityAnalysis(
            @RequestParam(defaultValue = "1") int hours) {
        try {
            var analysis = analyticsService.performSecurityAnalysis(hours);
            return ResponseEntity.ok(ApiResponse.success(analysis));

        } catch (Exception e) {
            log.error("❌ Erreur analyse sécurité: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error("Erreur lors de l'analyse de sécurité"));
        }
    }

    /**
     * Export des logs pour compliance
     * GET /api/v1/audit/export
     */
    @GetMapping("/export")
    public ResponseEntity<ApiResponse<?>> exportLogs(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate,
            @RequestParam(defaultValue = "audit") String logType) {
        try {
            var exportData = auditService.exportLogs(startDate, endDate, logType);
            return ResponseEntity.ok(ApiResponse.success(exportData));

        } catch (Exception e) {
            log.error("❌ Erreur export: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error("Erreur lors de l'export"));
        }
    }

    // ========================================
    // ENDPOINTS DE MONITORING
    // ========================================

    /**
     * Health check détaillé
     * GET /api/v1/audit/health
     */
    @GetMapping("/health")
    public ResponseEntity<ApiResponse<?>> healthCheck() {
        try {
            var healthStatus = auditService.performHealthCheck();
            return ResponseEntity.ok(ApiResponse.success(healthStatus));

        } catch (Exception e) {
            log.error("❌ Erreur health check: {}", e.getMessage(), e);
            return ResponseEntity.status(503)
                    .body(ApiResponse.error("Service dégradé"));
        }
    }

    /**
     * Métriques du service
     * GET /api/v1/audit/metrics
     */
    @GetMapping("/metrics")
    public ResponseEntity<ApiResponse<?>> getMetrics() {
        try {
            var metrics = analyticsService.getServiceMetrics();
            return ResponseEntity.ok(ApiResponse.success(metrics));

        } catch (Exception e) {
            log.error("❌ Erreur métriques: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error("Erreur lors de la récupération des métriques"));
        }
    }

    /**
     * Alertes actives
     * GET /api/v1/audit/alerts
     */
    @GetMapping("/alerts")
    public ResponseEntity<ApiResponse<?>> getActiveAlerts() {
        try {
            var alerts = analyticsService.getActiveAlerts();
            return ResponseEntity.ok(ApiResponse.success(alerts));

        } catch (Exception e) {
            log.error("❌ Erreur alertes: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error("Erreur lors de la récupération des alertes"));
        }
    }
}






