package com.embasic.escanner.android

/**
 * Small, framework-independent Android contract seed.
 * Not connected to capture, pairing, or production data transfer.
 * These canonical checks must also be exercised against Windows golden fixtures.
 */
object ScanContract {
    const val PROTOCOL_VERSION: Int = 1

    fun isSupportedVersion(version: Int): Boolean = version == PROTOCOL_VERSION

    fun isValidPageOrder(order: Int): Boolean = order >= 0

    /** Exactly 32 bytes encoded as *lowercase* hexadecimal SHA-256, no padding. */
    fun isCanonicalSha256Hex(value: String): Boolean =
        value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }
}
