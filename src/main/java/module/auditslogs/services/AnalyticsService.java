package module.auditslogs.services;

import module.auditslogs.repositories.AuditLogRepository;
import module.auditslogs.repositories.SecurityLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
public class AnalyticsService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private SecurityLogRepository securityLogRepository;

    public Map<String, Object> generateDashboard(int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        Map<String, Object> dashboard = new HashMap<>();

        dashboard.put("period", hours + " heures");
        dashboard.put("totalAuditEvents", auditLogRepository.count());
        dashboard.put("totalSecurityEvents", securityLogRepository.count());
        dashboard.put("criticalEvents", securityLogRepository.countHighThreatsSince(since));
        dashboard.put("generatedAt", LocalDateTime.now());

        return dashboard;
    }

    public Map<String, Object> performSecurityAnalysis(int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        Map<String, Object> analysis = new HashMap<>();

        analysis.put("timeframe", hours + " heures");
        analysis.put("highThreatEvents", securityLogRepository.countHighThreatsSince(since));
        analysis.put("suspiciousIPs", auditLogRepository.getTopFailedLoginIPs(since));
        analysis.put("analysisTime", LocalDateTime.now());

        return analysis;
    }

    public Map<String, Object> getServiceMetrics() {
        Map<String, Object> metrics = new HashMap<>();

        metrics.put("totalAuditLogs", auditLogRepository.count());
        metrics.put("totalSecurityLogs", securityLogRepository.count());
        metrics.put("timestamp", LocalDateTime.now());

        return metrics;
    }

    public Map<String, Object> getActiveAlerts() {
        LocalDateTime lastHour = LocalDateTime.now().minusHours(1);
        Map<String, Object> alerts = new HashMap<>();

        Long criticalThreats = securityLogRepository.countHighThreatsSince(lastHour);
        alerts.put("criticalAlertsLastHour", criticalThreats);
        alerts.put("alertLevel", criticalThreats > 5 ? "HIGH" : "LOW");
        alerts.put("timestamp", LocalDateTime.now());

        return alerts;
    }
}