package module.auditslogs.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    private final ConcurrentHashMap<String, RateLimitInfo> rateLimitMap = new ConcurrentHashMap<>();
    private final int MAX_REQUESTS_PER_MINUTE = 60;
    private final long WINDOW_SIZE_MS = 60000; // 1 minute

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String clientId = getClientId(request);
        String uri = request.getRequestURI();

        // Appliquer le rate limiting seulement sur les endpoints d'audit
        if (uri.startsWith("/api/v1/audit/log") || uri.startsWith("/api/v1/audit/security")) {
            if (!isAllowed(clientId)) {
                log.warn("Rate limit dépassé pour: {} depuis IP: {}", uri, clientId);

                // Correction du bug : Utiliser le code numérique 429
                response.setStatus(429); // Too Many Requests
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");

                response.getWriter().write("{\"error\":\"Rate limit exceeded\",\"message\":\"Trop de requêtes, veuillez patienter\"}");
                response.getWriter().flush();
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String getClientId(HttpServletRequest request) {
        // Vérifier les en-têtes de proxy
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    private boolean isAllowed(String clientId) {
        long currentTime = System.currentTimeMillis();

        // Nettoyer les entrées expirées périodiquement
        if (rateLimitMap.size() > 1000) {
            cleanExpiredEntries(currentTime);
        }

        rateLimitMap.compute(clientId, (key, rateLimitInfo) -> {
            if (rateLimitInfo == null || (currentTime - rateLimitInfo.windowStart) > WINDOW_SIZE_MS) {
                return new RateLimitInfo(currentTime, new AtomicInteger(1));
            } else {
                rateLimitInfo.requestCount.incrementAndGet();
                return rateLimitInfo;
            }
        });

        RateLimitInfo info = rateLimitMap.get(clientId);
        return info.requestCount.get() <= MAX_REQUESTS_PER_MINUTE;
    }

    private void cleanExpiredEntries(long currentTime) {
        rateLimitMap.entrySet().removeIf(entry ->
                (currentTime - entry.getValue().windowStart) > WINDOW_SIZE_MS
        );
        log.debug("Cache rate limiting nettoyé, {} entrées restantes", rateLimitMap.size());
    }

    private static class RateLimitInfo {
        final long windowStart;
        final AtomicInteger requestCount;

        RateLimitInfo(long windowStart, AtomicInteger requestCount) {
            this.windowStart = windowStart;
            this.requestCount = requestCount;
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/actuator/") ||
                path.startsWith("/swagger-ui/") ||
                path.startsWith("/v3/api-docs/") ||
                path.equals("/api/v1/audit/health") ||
                path.startsWith("/h2-console/");
    }
}