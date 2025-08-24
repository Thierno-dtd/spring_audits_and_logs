package module.auditslogs.dto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditEventRequest {

    @NotBlank(message = "Le type d'événement est obligatoire")
    @Size(max = 100, message = "Le type d'événement ne peut pas dépasser 100 caractères")
    private String eventType;

    @Size(max = 255, message = "L'email utilisateur ne peut pas dépasser 255 caractères")
    private String userEmail;

    private String details;

    @Size(max = 45, message = "L'adresse IP ne peut pas dépasser 45 caractères")
    private String ipAddress;

    private String userAgent;
    private String requestUri;
    private String httpMethod;
    private String sessionId;
    private Long executionTime;
    private String applicationName;
    private String environment;
    private String server;

    // Métadonnées supplémentaires
    private Map<String, Object> additionalData;

    // Timestamp optionnel (si non fourni, utilise le timestamp actuel)
    private LocalDateTime timestamp;
}