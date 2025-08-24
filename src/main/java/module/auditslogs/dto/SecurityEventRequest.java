package module.auditslogs.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEventRequest {

    @NotBlank(message = "L'événement de sécurité est obligatoire")
    @Size(max = 100, message = "L'événement de sécurité ne peut pas dépasser 100 caractères")
    private String securityEvent;

    private String userEmail;

    @NotBlank(message = "Le niveau de menace est obligatoire")
    private String threatLevel; // LOW, MEDIUM, HIGH, CRITICAL

    private String ipAddress;
    private String description;
    private Boolean blocked;
    private String countermeasure;
    private String applicationName;
    private String environment;
    private Map<String, Object> additionalData;
    private LocalDateTime timestamp;
}
