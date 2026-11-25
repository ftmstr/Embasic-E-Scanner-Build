package com.embasic.escanner.android

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Shared byte-exact golden fixture matrix. No Android device, TLS or real document. */
class PageWireV1Test {
    private val session = "01234567-89ab-4cde-8f01-23456789abcd"
    private val canonical = "{\"protocolVersion\":1,\"sessionId\":\"$session\"," +
        "\"pageId\":\"11234567-89ab-4cde-8f01-23456789abcd\"," +
        "\"order\":0,\"byteSize\":3,\"mime\":\"image/jpeg\"," +
        "\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}"

    private fun golden(): File {
        var current: File? = File(System.getProperty("user.dir"))
        repeat(8) {
            val f = File(current, "tests/golden/page-wire-v1.hex.tsv")
            if (f.isFile) return f
            current = current?.parentFile
        }
        error("Shared PUBLIC golden fixture is mandatory: tests/golden/page-wire-v1.hex.tsv")
    }

    @Test fun sharedGoldenBytesPassOrFailIdentically() {
        val lines = golden().readLines(Charsets.US_ASCII).filter { it.isNotBlank() && !it.startsWith('#') }
        assertEquals(63, lines.size)
        var good = 0
        var rejected = 0
        val names = HashSet<String>()
        for (line in lines) {
            val parts = line.split('\t')
            assertEquals("fixture columns", 3, parts.size)
            assertTrue("duplicated case: " + parts[0], names.add(parts[0]))
            val bytes = decodeLowerHex(parts[2])
            val parsed = PageWireV1.parse(bytes, session, 1024)
            when (parts[1]) {
                "PASS" -> {
                    good++
                    assertNotNull(parts[0], parsed)
                    val envelope = parsed!!
                    assertEquals(1, envelope.protocolVersion)
                    assertEquals(session, envelope.sessionId)
                    assertEquals(3L, envelope.byteSize)
                    assertTrue(PageWireV1.verifyBody(envelope, 1024, "abc".toByteArray(Charsets.US_ASCII)))
                    assertFalse(PageWireV1.verifyBody(envelope, 1024, "abd".toByteArray(Charsets.US_ASCII)))
                    assertFalse(PageWireV1.verifyBody(envelope, 1024, null))
                    assertEquals(envelope.canonicalJson,
                        PageWireV1.parse(envelope.canonicalJson.toByteArray(Charsets.US_ASCII), session, 1024)?.canonicalJson)
                    if (parts[0] in setOf("valid_canonical", "valid_reordered", "valid_whitespace"))
                        assertEquals(canonical, envelope.canonicalJson)
                }
                "REJECT" -> { rejected++; assertNull(parts[0], parsed) }
                else -> error("unknown fixture disposition")
            }
        }
        assertEquals(5, good)
        assertEquals(58, rejected)
    }

    @Test fun trustedSessionAndSizePoliciesCannotBeSuppliedByWire() {
        val raw = canonical.toByteArray(Charsets.US_ASCII)
        assertNotNull(PageWireV1.parse(raw, session, 3))
        assertNull(PageWireV1.parse(raw, session, 2))
        assertNull(PageWireV1.parse(raw, session, 0))
        assertNull(PageWireV1.parse(raw, session, -1))
        assertNull(PageWireV1.parse(raw, "21234567-89ab-4cde-8f01-23456789abcd", 1024))
        assertNull(PageWireV1.parse(raw, session.uppercase(), 1024))
        assertNull(PageWireV1.parse(raw, null, 1024))
        assertNull(PageWireV1.parse(null, session, 1024))
    }

    private fun decodeLowerHex(value: String): ByteArray {
        require(value.length % 2 == 0 && value.all { it in '0'..'9' || it in 'a'..'f' })
        return ByteArray(value.length / 2) { i ->
            fun nibble(ch: Char) = if (ch in '0'..'9') ch - '0' else ch - 'a' + 10
            ((nibble(value[i * 2]) shl 4) or nibble(value[i * 2 + 1])).toByte()
        }
    }
}
