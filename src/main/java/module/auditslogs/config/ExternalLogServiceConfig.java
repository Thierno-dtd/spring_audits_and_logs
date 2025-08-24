package module.auditslogs.config;

import module.auditslogs.services.ExternalLogService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class ExternalLogServiceConfig {

    @Value("${audit.elk.enabled:false}")
    private boolean elkEnabled;

    @Value("${audit.elk.logstash.url:http://localhost:7001}")
    private String logstashUrl;

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public ExternalLogService externalLogService(RestTemplate restTemplate) {
        return new ExternalLogService(restTemplate, elkEnabled, logstashUrl);
    }
}