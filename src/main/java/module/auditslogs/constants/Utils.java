package module.auditslogs.constants;

/**
 * Classe utilitaire contenant les constantes de l'application
 */
public final class Utils {

    // Empêcher l'instanciation
    private Utils() {
        throw new UnsupportedOperationException("Cette classe ne peut pas être instanciée");
    }

    // ========================================
    // ROUTES API
    // ========================================
    public static final String API_ROOT = "/api/v1";
    public static final String AUDIT_API = API_ROOT + "/audit";

    // Routes spécifiques
    public static final String AUDIT_LOG_ENDPOINT = AUDIT_API + "/log";
    public static final String SECURITY_LOG_ENDPOINT = AUDIT_API + "/security";
    public static final String SEARCH_ENDPOINT = AUDIT_API + "/search";
    public static final String DASHBOARD_ENDPOINT = AUDIT_API + "/dashboard";
    public static final String HEALTH_ENDPOINT = AUDIT_API + "/health";
    public static final String METRICS_ENDPOINT = AUDIT_API + "/metrics";
    public static final String EXPORT_ENDPOINT = AUDIT_API + "/export";

    // ========================================
    // TYPES D'ÉVÉNEMENTS
    // ========================================
    public static final class EventTypes {
        // Authentification
        public static final String USER_LOGIN_SUCCESS = "USER_LOGIN_SUCCESS";
        public static final String USER_LOGIN_FAILED = "USER_LOGIN_FAILED";
        public static final String USER_LOGOUT = "USER_LOGOUT";

        // Actions utilisateur
        public static final String USER_ACTION = "USER_ACTION";
        public static final String USER_REGISTRATION = "USER_REGISTRATION";
        public static final String USER_UPDATE = "USER_UPDATE";
        public static final String USER_DELETE = "USER_DELETE";

        // Actions administrateur
        public static final String ADMIN_ACTION = "ADMIN_ACTION";
        public static final String ADMIN_LOGIN = "ADMIN_LOGIN";
        public static final String ADMIN_CONFIG_CHANGE = "ADMIN_CONFIG_CHANGE";

        // Sécurité
        public static final String SECURITY_BREACH = "SECURITY_BREACH";
        public static final String UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS";
        public static final String SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY";

        // Système
        public static final String SYSTEM_STARTUP = "SYSTEM_STARTUP";
        public static final String SYSTEM_SHUTDOWN = "SYSTEM_SHUTDOWN";
        public static final String API_CALL = "API_CALL";
    }

    // ========================================
    // ÉVÉNEMENTS DE SÉCURITÉ
    // ========================================
    public static final class SecurityEvents {
        public static final String BRUTE_FORCE_ATTEMPT = "BRUTE_FORCE_ATTEMPT";
        public static final String SQL_INJECTION_ATTEMPT = "SQL_INJECTION_ATTEMPT";
        public static final String XSS_ATTEMPT = "XSS_ATTEMPT";
        public static final String DDOS_ATTEMPT = "DDOS_ATTEMPT";
        public static final String MALWARE_DETECTED = "MALWARE_DETECTED";
        public static final String PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION";
        public static final String DATA_EXFILTRATION = "DATA_EXFILTRATION";
        public static final String ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER";
    }

    // ========================================
    // HEADERS HTTP
    // ========================================
    public static final class Headers {
        public static final String API_KEY = "X-API-Key";
        public static final String REQUEST_ID = "X-Request-ID";
        public static final String CORRELATION_ID = "X-Correlation-ID";
        public static final String FORWARDED_FOR = "X-Forwarded-For";
        public static final String REAL_IP = "X-Real-IP";
        public static final String USER_AGENT = "User-Agent";
    }

    // ========================================
    // FORMATS ET PATTERNS
    // ========================================
    public static final class Formats {
        public static final String DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
        public static final String DATE_FORMAT = "yyyy-MM-dd";
        public static final String IP_PATTERN = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
        public static final String EMAIL_PATTERN = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
    }

    // ========================================
    // LIMITES ET SEUILS
    // ========================================
    public static final class Limits {
        public static final int MAX_EVENTS_PER_BATCH = 100;
        public static final int MAX_SEARCH_RESULTS = 1000;
        public static final int DEFAULT_PAGE_SIZE = 20;
        public static final int MAX_PAGE_SIZE = 100;
        public static final int RATE_LIMIT_PER_MINUTE = 60;
        public static final int MAX_FAILED_LOGIN_ATTEMPTS = 5;
        public static final long SESSION_TIMEOUT_MINUTES = 30;
    }

    // ========================================
    // MESSAGES
    // ========================================
    public static final class Messages {
        public static final String SUCCESS = "Opération réussie";
        public static final String ERROR_GENERIC = "Une erreur s'est produite";
        public static final String ERROR_VALIDATION = "Erreur de validation des données";
        public static final String ERROR_UNAUTHORIZED = "Accès non autorisé";
        public static final String ERROR_NOT_FOUND = "Ressource non trouvée";
        public static final String ERROR_RATE_LIMIT = "Limite de requêtes dépassée";
        public static final String ERROR_INTERNAL = "Erreur interne du serveur";
    }

    // ========================================
    // CONFIGURATION ELK STACK
    // ========================================
    public static final class ELK {
        public static final String AUDIT_INDEX_PREFIX = "audit-logs";
        public static final String SECURITY_INDEX_PREFIX = "security-logs";
        public static final String APPLICATION_INDEX_PREFIX = "application-logs";
        public static final String INDEX_DATE_PATTERN = "yyyy.MM.dd";
    }

    // ========================================
    // MÉTHODES UTILITAIRES
    // ========================================

    /**
     * Vérifie si une chaîne est vide ou null
     */
    public static boolean isEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }

    /**
     * Vérifie si une chaîne n'est pas vide
     */
    public static boolean isNotEmpty(String str) {
        return !isEmpty(str);
    }

    /**
     * Retourne une valeur par défaut si la valeur est null
     */
    public static <T> T defaultIfNull(T value, T defaultValue) {
        return value != null ? value : defaultValue;
    }

    /**
     * Sanitise une chaîne pour les logs (évite l'injection de logs)
     */
    public static String sanitizeForLog(String input) {
        if (isEmpty(input)) {
            return "";
        }
        return input.replaceAll("[\r\n\t]", "_");
    }
}