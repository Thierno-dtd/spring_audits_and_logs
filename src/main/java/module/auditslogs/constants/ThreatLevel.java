package module.auditslogs.constants;

/**
 * Énumération des niveaux de menace pour les événements de sécurité
 */
public enum ThreatLevel {
    LOW("Faible", "Événement normal sans risque particulier"),
    MEDIUM("Moyen", "Événement suspect nécessitant une surveillance"),
    HIGH("Élevé", "Événement critique nécessitant une action immédiate"),
    CRITICAL("Critique", "Menace imminente nécessitant une intervention d'urgence");

    private final String displayName;
    private final String description;

    ThreatLevel(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Détermine le niveau de menace basé sur un score numérique
     */
    public static ThreatLevel fromScore(int score) {
        if (score >= 90) return CRITICAL;
        if (score >= 70) return HIGH;
        if (score >= 40) return MEDIUM;
        return LOW;
    }

    /**
     * Convertit une chaîne en ThreatLevel (insensible à la casse)
     */
    public static ThreatLevel fromString(String level) {
        if (level == null) return LOW;

        try {
            return ThreatLevel.valueOf(level.toUpperCase());
        } catch (IllegalArgumentException e) {
            return LOW;
        }
    }
}