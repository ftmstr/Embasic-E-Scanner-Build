package com.embasic.escanner.android

import java.security.MessageDigest

/**
 * In-memory acceptance guard, NOT a TLS/QR implementation and NOT a durable file store.
 * A trusted composition root owns session ID, token SHA-256, clock and limits.
 * All mutations are serialized; untrusted wire bytes never choose phase or session.
 */
class ReceiveGateV1 private constructor(
    private val sessionId: String,
    private val tokenHash: ByteArray,
    private val issuedAtMillis: Long,
    private val expiresAtMillis: Long,
    private val maxPageBytes: Long,
    private val maxPages: Int
) {
    enum class Phase { PENDING, AUTHORIZED, STAGED, CLOSED }
    enum class Decision { ACCEPTED, REJECTED }

    private var phaseValue = Phase.PENDING
    private var lastClock = issuedAtMillis
    private val pageIds = HashSet<String>()
    private var nextOrder = 0
    private var pending: CanonicalPageWireV1? = null

    val phase: Phase @Synchronized get() = phaseValue
    val confirmedPages: Int @Synchronized get() = nextOrder

    /**
     * The QR token is a 256-bit random value represented by 64 lowercase hex chars.
     * Only its SHA-256 digest is retained in this object. TLS peer authentication
     * and restart-safe token consumption remain separate, mandatory gates.
     */
    @Synchronized
    fun authenticate(presentedToken: String?, nowMillis: Long): Decision {
        if (!timeAllowed(nowMillis) || phaseValue != Phase.PENDING ||
            !PageTransferIntegrity.isCanonicalSha256(presentedToken)) return Decision.REJECTED
        val calculated = MessageDigest.getInstance("SHA-256")
            .digest(presentedToken!!.toByteArray(Charsets.US_ASCII))
        if (!MessageDigest.isEqual(calculated, tokenHash)) return Decision.REJECTED
        phaseValue = Phase.AUTHORIZED  // one-shot: no second successful authenticate
        return Decision.ACCEPTED
    }

    /**
     * Stage proposal: checks raw wire + complete bytes; no I/O is performed here.
     * Must NOT be interpreted as a disk write or a ScanSession RECEIVED transition.
     */
    @Synchronized
    fun propose(rawJson: ByteArray?, completeBytes: ByteArray?, nowMillis: Long): Decision {
        if (!timeAllowed(nowMillis) || phaseValue != Phase.AUTHORIZED ||
            nextOrder >= maxPages) return Decision.REJECTED
        val envelope = PageWireV1.parse(rawJson, sessionId, maxPageBytes) ?: return Decision.REJECTED
        if (envelope.order != nextOrder || envelope.pageId in pageIds ||
            !PageWireV1.verifyBody(envelope, maxPageBytes, completeBytes)) return Decision.REJECTED
        pending = envelope
        phaseValue = Phase.STAGED
        return Decision.ACCEPTED
    }

    /**
     * Requires independent bytes re-read from a caller-controlled staging source.
     * No durability, atomic rename, image decoding or file identity is established
     * by this in-memory guard. Caller must implement and test those separate gates.
     */
    @Synchronized
    fun confirmReread(stagedReread: ByteArray?, nowMillis: Long): Decision {
        if (!timeAllowed(nowMillis) || phaseValue != Phase.STAGED) return Decision.REJECTED
        val item = pending ?: return Decision.REJECTED
        if (!PageWireV1.verifyBody(item, maxPageBytes, stagedReread)) return Decision.REJECTED
        if (item.pageId in pageIds || item.order != nextOrder || nextOrder >= maxPages)
            return Decision.REJECTED
        pageIds.add(item.pageId)
        nextOrder++
        pending = null
        phaseValue = Phase.AUTHORIZED
        return Decision.ACCEPTED
    }

    @Synchronized
    fun close(): Decision {
        if (phaseValue == Phase.CLOSED) return Decision.REJECTED
        phaseValue = Phase.CLOSED
        pending = null
        return Decision.ACCEPTED
    }

    private fun timeAllowed(nowMillis: Long): Boolean {
        if (phaseValue == Phase.CLOSED || nowMillis < issuedAtMillis ||
            nowMillis < lastClock) return false
        lastClock = nowMillis
        if (nowMillis >= expiresAtMillis) {
            phaseValue = Phase.CLOSED
            pending = null
            return false
        }
        return true
    }

    companion object {
        const val MAX_TTL_MILLIS = 300_000L
        const val MAX_PAGES = 1000

        /** Never creates a partially initialized or unbounded session. */
        fun open(
            expectedSessionId: String?, expectedTokenSha256: String?,
            issuedAtMillis: Long, expiresAtMillis: Long,
            maxPageBytes: Long, maxPages: Int
        ): ReceiveGateV1? {
            if (!PageTransferIntegrity.isCanonicalUuid(expectedSessionId) ||
                !PageTransferIntegrity.isCanonicalSha256(expectedTokenSha256) ||
                issuedAtMillis < 0 || expiresAtMillis <= issuedAtMillis ||
                expiresAtMillis - issuedAtMillis > MAX_TTL_MILLIS ||
                maxPageBytes <= 0 || maxPages !in 1..MAX_PAGES) return null
            val hex = expectedTokenSha256!!
            val digest = ByteArray(32) { index ->
                fun nibble(c: Char) = if (c <= '9') c - '0' else c - 'a' + 10
                ((nibble(hex[index * 2]) shl 4) or nibble(hex[index * 2 + 1])).toByte()
            }
            return ReceiveGateV1(expectedSessionId!!, digest,
                issuedAtMillis, expiresAtMillis, maxPageBytes, maxPages)
        }
    }
}
