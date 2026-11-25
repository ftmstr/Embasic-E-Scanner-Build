package com.embasic.escanner.android

/**
 * Non-destructive, platform-parity 90-degree rotation recipe.
 * The original JPEG/PNG asset bytes and SHA-256 NEVER change.
 * Values are clockwise screen/PDF degrees; no arbitrary angle or crop yet.
 */
internal object PageRotationRecipe {
    private val allowed = setOf(0, 90, 180, 270)

    fun isValid(clockwiseDegrees: Int): Boolean = clockwiseDegrees in allowed

    fun clockwise(current: Int): Int {
        require(isValid(current)) { "Invalid stored rotation" }
        return (current + 90) % 360
    }

    fun reset(): Int = 0

    /**
     * Existing two-column manifests have no angle and migrate to zero.
     * Malformed/non-right-angle entries are rejected, never normalized.
     */
    fun parsePersisted(field: String?): Int? {
        if (field == null) return 0
        // Canonical decimal spellings only: reject +90, 090, whitespace,
        // negatives and accidental migration of malformed edits.
        if (field !in setOf("0", "90", "180", "270")) return null
        return field.toInt()
    }
}
