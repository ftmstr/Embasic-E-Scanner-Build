package com.embasic.escanner.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic, platform-parity envelope vectors; no real documents or network. */
class PageTransferIntegrityTest {
    private val session = "01234567-89ab-4cde-8f01-23456789abcd"
    private val page = "11234567-89ab-4cde-8f01-23456789abcd"
    private val hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    private val abc = "abc".toByteArray(Charsets.US_ASCII)

    private fun verified(
        sessionId: String? = session, pageId: String? = page, order: Int = 0,
        length: Long = 3L, mime: String? = "image/jpeg", sha: String? = hash,
        limit: Long = 1024L, bytes: ByteArray? = abc
    ) = PageTransferIntegrity.verifyCompleteBytes(
        sessionId, pageId, order, length, mime, sha, limit, bytes
    )

    @Test fun canonicalIdentifiersAndDigestsOnly() {
        assertTrue(PageTransferIntegrity.isCanonicalUuid(session))
        assertTrue(PageTransferIntegrity.isCanonicalUuid(page))
        assertTrue(PageTransferIntegrity.isCanonicalSha256(hash))
        listOf<String?>(null, "", "00000000-0000-0000-0000-000000000000",
            session.uppercase(), session.replace("-", ""), session.replace('a', 'g'),
            session + " ", "🤖" + session.drop(2)).forEach {
            assertFalse(PageTransferIntegrity.isCanonicalUuid(it))
        }
        listOf<String?>(null, "", hash.uppercase(), hash.dropLast(1),
            hash + "0", hash.replace('a', 'g')).forEach {
            assertFalse(PageTransferIntegrity.isCanonicalSha256(it))
        }
    }

    @Test fun sameSyntheticVectorMatchesBothPlatforms() {
        assertTrue(verified())
        assertTrue(verified(order = Int.MAX_VALUE))
        assertTrue(verified(mime = "image/png")) // Not a decoder or image type sniffer.
        assertTrue(PageTransferIntegrity.isConsistentMetadata(
            session, page, 0, 3, "image/jpeg", hash, 3
        ))
    }

    @Test fun incompleteOrRewrittenPayloadFailsClosed() {
        assertFalse(verified(bytes = null))
        assertFalse(verified(bytes = byteArrayOf()))
        assertFalse(verified(bytes = abc.copyOfRange(0, 2)))
        assertFalse(verified(bytes = abc + byteArrayOf(0)))
        assertFalse(verified(bytes = "abd".toByteArray(Charsets.US_ASCII)))
        assertFalse(verified(sha = "0".repeat(64)))
        assertFalse(verified(sha = hash.uppercase()))
        assertFalse(verified(length = 2))
        assertFalse(verified(length = 4))
        assertFalse(verified(length = Long.MAX_VALUE, limit = Long.MAX_VALUE))
    }

    @Test fun malformedMetadataNeverPassesHashCheck() {
        assertFalse(verified(sessionId = null))
        assertFalse(verified(sessionId = session.uppercase()))
        assertFalse(verified(pageId = page.uppercase()))
        assertFalse(verified(pageId = session))
        assertFalse(verified(order = -1))
        assertFalse(verified(order = Int.MIN_VALUE))
        assertFalse(verified(length = 0))
        assertFalse(verified(length = -1))
        assertFalse(verified(limit = 0))
        assertFalse(verified(limit = -1))
        assertFalse(verified(limit = 2))
        assertFalse(verified(mime = "IMAGE/JPEG"))
        assertFalse(verified(mime = "image/svg+xml"))
        assertFalse(verified(mime = "image/jpeg; charset=utf-8"))
        assertFalse(verified(mime = null))
        assertFalse(verified(sha = null))
    }
}
