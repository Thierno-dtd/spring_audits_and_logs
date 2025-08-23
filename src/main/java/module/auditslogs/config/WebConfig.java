package module.auditslogs.config;

import lombok.RequiredArgsConstructor;
import module.auditslogs.AuditInterceptor;
import module.auditslogs.constants.utils;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static module.auditslogs.constants.utils.APP_ROOT;

@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {

    private final AuditInterceptor auditInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(auditInterceptor)
                .addPathPatterns(APP_ROOT+"/auth/**", APP_ROOT+"/admin/**")
                .excludePathPatterns(APP_ROOT+"/auth/health", "/swagger-ui/**", "/h2-console/**");
    }
}