package com.embasic.escanner.android

import java.security.MessageDigest

/**
 * Untrusted page-transfer envelope preflight, independent of Android UI and network.
 *
 * This verifies canonical metadata and complete SHA-256/byte-count agreement only.
 * It does NOT parse raw wire JSON, authenticate an HTTPS session, validate image
 * decodability, or authorize a transition into ScanSession/READY.
 */
object PageTransferIntegrity {
    private const val NIL_UUID = "00000000-0000-0000-0000-000000000000"

    fun isCanonicalUuid(value: String?): Boolean {
        if (value == null || value.length != 36 || value == NIL_UUID) return false
        for (i in value.indices) {
            val ch = value[i]
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (ch != '-') return false
            } else if (ch !in '0'..'9' && ch !in 'a'..'f') {
                return false
            }
        }
        return true
    }

    fun isCanonicalSha256(value: String?): Boolean =
        value != null && value.length == 64 &&
            value.all { it in '0'..'9' || it in 'a'..'f' }

    fun isConsistentMetadata(
        sessionId: String?, pageId: String?, order: Int, declaredBytes: Long,
        mime: String?, sha256: String?, maxBytes: Long
    ): Boolean =
        isCanonicalUuid(sessionId) && isCanonicalUuid(pageId) &&
            sessionId != pageId && order >= 0 && maxBytes > 0 &&
            declaredBytes > 0 && declaredBytes <= maxBytes &&
            (mime == "image/jpeg" || mime == "image/png") && isCanonicalSha256(sha256)

    /** Bytes are checked with a fixed-time digest comparison, not image decoding. */
    fun verifyCompleteBytes(
        sessionId: String?, pageId: String?, order: Int, declaredBytes: Long,
        mime: String?, sha256: String?, maxBytes: Long, bytes: ByteArray?
    ): Boolean {
        if (!isConsistentMetadata(sessionId, pageId, order, declaredBytes, mime, sha256, maxBytes) ||
            bytes == null || bytes.size.toLong() != declaredBytes) return false
        val expected = ByteArray(32) { i ->
            ((nibble(sha256!![i * 2]) shl 4) or nibble(sha256[i * 2 + 1])).toByte()
        }
        val actual = MessageDigest.getInstance("SHA-256").digest(bytes)
        return MessageDigest.isEqual(actual, expected)
    }

    private fun nibble(c: Char): Int = if (c in '0'..'9') c - '0' else c - 'a' + 10
}
