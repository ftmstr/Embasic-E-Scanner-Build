package com.embasic.escanner.android

/**
 * Canonical wire metadata only, never an authenticated ScanSession/domain object.
 * Input is a bounded ASCII-only subset of JSON; no JSON escapes or Unicode aliases.
 */
data class CanonicalPageWireV1(
    val protocolVersion: Int,
    val sessionId: String,
    val pageId: String,
    val order: Int,
    val byteSize: Long,
    val mime: String,
    val sha256: String,
    val canonicalJson: String
)

object PageWireV1 {
    const val MAX_WIRE_BYTES = 4096
    private val allowed = setOf(
        "protocolVersion", "sessionId", "pageId", "order", "byteSize", "mime", "sha256"
    )
    private val numbers = setOf("protocolVersion", "order", "byteSize")

    /** Trusted caller binds session and maximum size; untrusted JSON never sets state. */
    fun parse(raw: ByteArray?, expectedSessionId: String?, maxBytes: Long): CanonicalPageWireV1? {
        if (!PageTransferIntegrity.isCanonicalUuid(expectedSessionId) || maxBytes <= 0L ||
            raw == null || raw.isEmpty() || raw.size > MAX_WIRE_BYTES ||
            raw.any { b ->
                val n = b.toInt() and 0xff
                n !in 0x20..0x7e && n != 9 && n != 10 && n != 13
            }) return null

        return try {
            val input = String(raw, Charsets.US_ASCII)
            val fields = Reader(input).readObject()
            if (fields.keys != allowed) return null
            fun string(key: String): String {
                val field = fields.getValue(key)
                require(field.isString)
                return field.text
            }
            fun number(key: String): String {
                val field = fields.getValue(key)
                require(!field.isString)
                return field.text
            }
            val version = number("protocolVersion").toIntOrNull() ?: return null
            val order = number("order").toIntOrNull() ?: return null
            val size = number("byteSize").toLongOrNull() ?: return null
            val session = string("sessionId")
            val page = string("pageId")
            val mime = string("mime")
            val digest = string("sha256")
            if (version != ScanContract.PROTOCOL_VERSION || session != expectedSessionId ||
                !PageTransferIntegrity.isConsistentMetadata(
                    session, page, order, size, mime, digest, maxBytes
                )) return null
            val canonical = "{\"protocolVersion\":1,\"sessionId\":\"$session\",\"pageId\":\"$page\"," +
                "\"order\":$order,\"byteSize\":$size,\"mime\":\"$mime\",\"sha256\":\"$digest\"}"
            CanonicalPageWireV1(version, session, page, order, size, mime, digest, canonical)
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /** Parsing is not sufficient for RECEIVED; caller must check a complete staged payload. */
    fun verifyBody(envelope: CanonicalPageWireV1, maxBytes: Long, bytes: ByteArray?): Boolean =
        PageTransferIntegrity.verifyCompleteBytes(
            envelope.sessionId, envelope.pageId, envelope.order, envelope.byteSize,
            envelope.mime, envelope.sha256, maxBytes, bytes
        )

    private data class Field(val text: String, val isString: Boolean)

    private class Reader(private val text: String) {
        private var pos = 0
        private fun skipSpace() {
            while (pos < text.length && text[pos] in " \t\n\r") pos++
        }
        private fun peek(): Char? = text.getOrNull(pos)
        private fun expect(ch: Char) {
            skipSpace()
            if (peek() != ch) throw IllegalArgumentException("wire token")
            pos++
        }
        private fun readString(): String {
            if (peek() != '"') throw IllegalArgumentException("string expected")
            pos++
            val start = pos
            while (pos < text.length) {
                val ch = text[pos++]
                if (ch == '"') return text.substring(start, pos - 1)
                if (ch == '\\' || ch.code < 32 || ch.code > 126)
                    throw IllegalArgumentException("escapes and controls forbidden")
            }
            throw IllegalArgumentException("unterminated string")
        }
        private fun readNumber(): String {
            val start = pos
            if (peek() !in '0'..'9') throw IllegalArgumentException("noncanonical number")
            while (peek() in '0'..'9') pos++
            val result = text.substring(start, pos)
            if (result.length > 1 && result[0] == '0')
                throw IllegalArgumentException("leading zero")
            return result
        }
        fun readObject(): Map<String, Field> {
            val fields = LinkedHashMap<String, Field>()
            expect('{')
            skipSpace()
            if (peek() == '}') throw IllegalArgumentException("missing members")
            while (true) {
                skipSpace()
                val key = readString()
                if (key !in allowed || key in fields || fields.size >= allowed.size)
                    throw IllegalArgumentException("unknown or repeated field")
                expect(':')
                skipSpace()
                val isString = key !in numbers
                val value = if (isString) readString() else readNumber()
                fields[key] = Field(value, isString)
                skipSpace()
                when (peek()) {
                    ',' -> { pos++; continue }
                    '}' -> { pos++; break }
                    else -> throw IllegalArgumentException("unexpected object token")
                }
            }
            skipSpace()
            if (pos != text.length) throw IllegalArgumentException("trailing bytes")
            return fields
        }
    }
}
