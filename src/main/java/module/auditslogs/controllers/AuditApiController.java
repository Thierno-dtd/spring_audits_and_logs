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


@RestController
@RequestMapping(Utils.AUDIT_API) // 🎯 Utilisation de la constante
@RequiredArgsConstructor
@Slf4j
@Validated
public class AuditApiController {

    private final AuditService auditService;
    private final SecurityLogService securityLogService;
    private final AnalyticsService analyticsService;

    /**
     * Enregistrer un événement d'audit
     */
    @PostMapping("/log") // Ou utiliser Utils.AUDIT_LOG_ENDPOINT sans le préfixe
    public ResponseEntity<ApiResponse<?>> logAuditEvent(
            @Valid @RequestBody AuditEventRequest request,
            HttpServletRequest httpRequest) {

        try {
            // 🔍 Validation avec Utils
            if (Utils.isEmpty(request.getEventType())) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error(Utils.Messages.ERROR_VALIDATION));
            }

            // 🧹 Sanitisation pour les logs
            String sanitizedDetails = Utils.sanitizeForLog(request.getDetails());
            String sanitizedEmail = Utils.sanitizeForLog(request.getUserEmail());

            log.info("📝 Réception événement audit: {} pour {}",
                    request.getEventType(), sanitizedEmail);

            // 🔧 Enrichissement avec des valeurs par défaut
            if (Utils.isEmpty(request.getApplicationName())) {
                request.setApplicationName("unknown-app");
            }

            auditService.logAuditEventFromApi(request);

            return ResponseEntity.ok(ApiResponse.success(Utils.Messages.SUCCESS));

        } catch (Exception e) {
            log.error("❌ Erreur enregistrement audit: {}", Utils.sanitizeForLog(e.getMessage()), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error(Utils.Messages.ERROR_INTERNAL));
        }
    }

    /**
     * Enregistrer un événement de sécurité
     */
    @PostMapping("/security")
    public ResponseEntity<ApiResponse<?>> logSecurityEvent(
            @Valid @RequestBody SecurityEventRequest request,
            HttpServletRequest httpRequest) {

        try {
            // 🚨 Log spécial pour événements critiques
            if ("CRITICAL".equals(request.getThreatLevel())) {
                log.error("🚨 ÉVÉNEMENT CRITIQUE: {} - {} - IP: {}",
                        request.getSecurityEvent(),
                        Utils.sanitizeForLog(request.getUserEmail()),
                        request.getIpAddress());
            }

            securityLogService.logSecurityEventFromApi(request);

            return ResponseEntity.ok(ApiResponse.success(Utils.Messages.SUCCESS));

        } catch (Exception e) {
            log.error("❌ Erreur événement sécurité: {}", Utils.sanitizeForLog(e.getMessage()), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error(Utils.Messages.ERROR_INTERNAL));
        }
    }

    /**
     * Recherche avec validation des paramètres
     */
    @GetMapping("/search")
    public ResponseEntity<ApiResponse<?>> searchAuditLogs(@Valid SearchRequest searchRequest) {
        try {
            // 🔍 Validation des limites
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
     * Health check avec messages standardisés
     */
    @GetMapping("/health")
    public ResponseEntity<ApiResponse<?>> healthCheck() {
        try {
            var healthStatus = auditService.performHealthCheck();

            // 🏥 Vérification du statut
            boolean isHealthy = "UP".equals(healthStatus.get("status"));

            if (isHealthy) {
                return ResponseEntity.ok(ApiResponse.success(healthStatus));
            } else {
                return ResponseEntity.status(503)
                        .body(ApiResponse.error("Service dégradé"));
            }

        } catch (Exception e) {
            log.error("❌ Health check échoué: {}", Utils.sanitizeForLog(e.getMessage()), e);
            return ResponseEntity.status(503)
                    .body(ApiResponse.error("Service indisponible"));
        }
    }

    /**
     * Validation d'API Key personnalisée
     */
    private boolean isValidApiKey(HttpServletRequest request) {
        String apiKey = request.getHeader(Utils.Headers.API_KEY);
        return Utils.isNotEmpty(apiKey) && !"default-key".equals(apiKey);
    }
}