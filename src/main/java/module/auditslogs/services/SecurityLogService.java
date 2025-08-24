package module.auditslogs.services;

import lombok.extern.slf4j.Slf4j;
import module.auditslogs.dto.SecurityEventRequest;
import module.auditslogs.entities.SecurityLog;
import module.auditslogs.repositories.SecurityLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@Slf4j
public class SecurityLogService {

    @Autowired
    private SecurityLogRepository securityLogRepository;

    @Async
    public void logSecurityEventFromApi(SecurityEventRequest request) {
        try {
            SecurityLog securityLog = SecurityLog.builder()
                    .timestamp(request.getTimestamp() != null ? request.getTimestamp() : LocalDateTime.now())
                    .securityEvent(request.getSecurityEvent())
                    .userEmail(request.getUserEmail())
                    .threatLevel(request.getThreatLevel())
                    .ipAddress(request.getIpAddress())
                    .description(request.getDescription())
                    .blocked(request.getBlocked() != null ? request.getBlocked() : false)
                    .countermeasure(request.getCountermeasure())
                    .build();

            securityLogRepository.save(securityLog);
            log.info("Événement de sécurité enregistré: {}", request.getSecurityEvent());

        } catch (Exception e) {
            log.error("Erreur lors de l'enregistrement de l'événement de sécurité", e);
            throw new RuntimeException("Erreur enregistrement événement sécurité", e);
        }
    }
}
