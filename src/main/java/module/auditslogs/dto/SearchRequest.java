package module.auditslogs.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SearchRequest {
    private String query;
    private String eventType;
    private String userEmail;
    private String threatLevel;
    private LocalDateTime startDate;
    private LocalDateTime endDate;
    private String applicationName;
    private int page = 0;
    private int size = 20;
    private String sortBy = "timestamp";
    private String sortDirection = "desc";
}