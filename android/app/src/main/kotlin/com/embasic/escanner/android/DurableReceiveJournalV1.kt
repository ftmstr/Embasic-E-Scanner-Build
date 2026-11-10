package com.embasic.escanner.android

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest

/**
 * Restricted on-disk receipt adapter for a PRE-EXISTING app-private single-session dir.
 * Token claim uses CREATE_NEW + force and is never deleted; restarting opens READ-ONLY
 * inspect, never reauthorizes an existing consumed token. Orphans poison recovery.
 *
 * No TLS, image decode, domain transition, directory fsync / full power-cut guarantee
 * or defense against a second untrusted writer with access to the root directory.
 */
class DurableReceiveJournalV1 private constructor(
    private val root: Path, private val rootKey: Any,
    private val session: String, private val tokenSha: String,
    private val issuedAt: Long, private val expiresAt: Long,
    private val maxBytes: Long, private val maxPages: Int,
    private val gate: ReceiveGateV1
) {
    enum class RecoveryStatus { FRESH, TOKEN_CONSUMED, POISONED }
    data class Recovery(val status: RecoveryStatus, val confirmedPages: Int)

    private var claimed = false
    private var stopped = false

    @Synchronized
    fun claimToken(token: String?, nowMillis: Long): Boolean {
        if (stopped || claimed || !stableRoot(root, rootKey) ||
            !PageTransferIntegrity.isCanonicalSha256(token) ||
            nowMillis < issuedAt || nowMillis >= expiresAt) return false
        // A suspicious pre-existing entry is evidence of an older interrupted
        // or tampered session. Do not grant another token on that directory.
        if (!unusedRoot()) {
            stopped = true
            return false
        }
        val actual = MessageDigest.getInstance("SHA-256")
            .digest(token!!.toByteArray(Charsets.US_ASCII))
        if (!MessageDigest.isEqual(actual, decodeHex(tokenSha))) return false
        val claim = "v1|$session|$tokenSha|$issuedAt|$expiresAt\n"
        // First make the replay tombstone durable as far as file fsync allows.
        // Even a partial marker means no future token acceptance.
        if (!createAndForce(root.resolve(CLAIM), claim.toByteArray(Charsets.US_ASCII))) {
            stopped = true
            return false
        }
        if (!stableRoot(root, rootKey) ||
            gate.authenticate(token, nowMillis) != ReceiveGateV1.Decision.ACCEPTED) {
            stopped = true
            return false
        }
        claimed = true
        return true
    }

    /** Stages, rereads, atomically renames and records, but never admits to ScanSession. */
    @Synchronized
    fun commit(rawJson: ByteArray?, bytes: ByteArray?, nowMillis: Long): Boolean {
        if (!claimed || stopped || !stableRoot(root, rootKey)) return false
        // Re-audit every previous receipt and blob BEFORE accepting new bytes.
        // Crash remnants, torn token claim or a modified earlier page permanently
        // poison this instance. This is not a hostile-writer race guarantee.
        val before = inspect(root, session, tokenSha, issuedAt, expiresAt,
            maxBytes, maxPages)
        if (before.status != RecoveryStatus.TOKEN_CONSUMED ||
            before.confirmedPages != gate.confirmedPages) return poison()
        val envelope = PageWireV1.parse(rawJson, session, maxBytes) ?: return false
        if (bytes == null || !PageWireV1.verifyBody(envelope, maxBytes, bytes) ||
            gate.propose(rawJson, bytes, nowMillis) != ReceiveGateV1.Decision.ACCEPTED) return false
        val number = envelope.order.toString().padStart(4, '0')
        val temporary = root.resolve("stage-$number.tmp")
        val blob = root.resolve("page-$number.blob")
        val receipt = root.resolve("page-$number.rec")
        try {
            if (Files.exists(temporary, LinkOption.NOFOLLOW_LINKS) ||
                Files.exists(blob, LinkOption.NOFOLLOW_LINKS) ||
                Files.exists(receipt, LinkOption.NOFOLLOW_LINKS)) return poison()
            if (!createAndForce(temporary, bytes)) return poison()
            val stageKey = safeKey(temporary) ?: return poison()
            val staged = readBounded(temporary, maxBytes) ?: return poison()
            if (!MessageDigest.isEqual(staged, bytes)) return poison()
            // Never fall back to a non-atomic copy. Concurrent hostile directory
            // replacement and directory power-loss persistence remain unproved.
            Files.move(temporary, blob, StandardCopyOption.ATOMIC_MOVE)
            if (safeKey(blob) != stageKey) return poison()
            val reread = readBounded(blob, maxBytes) ?: return poison()
            if (!PageWireV1.verifyBody(envelope, maxBytes, reread)) return poison()
            val record = "v1|" + envelope.order + "|" + envelope.pageId +
                "|" + envelope.byteSize + "|" + envelope.mime + "|" + envelope.sha256 + "\n"
            if (!createAndForce(receipt, record.toByteArray(Charsets.US_ASCII))) return poison()
            if (!stableRoot(root, rootKey) ||
                gate.confirmReread(reread, nowMillis) != ReceiveGateV1.Decision.ACCEPTED)
                return poison()
            // Check the complete new receipt chain, not merely the last page.
            val after = inspect(root, session, tokenSha, issuedAt, expiresAt,
                maxBytes, maxPages)
            if (after.status != RecoveryStatus.TOKEN_CONSUMED ||
                after.confirmedPages != gate.confirmedPages) return poison()
            return true
        } catch (_: Exception) { return poison() }
    }

    private fun unusedRoot(): Boolean =
        try {
            stableRoot(root, rootKey) &&
                Files.newDirectoryStream(root).use { !it.iterator().hasNext() } &&
                stableRoot(root, rootKey)
        } catch (_: Exception) { false }

    private fun poison(): Boolean { stopped = true; return false }

    companion object {
        const val MAX_STAGE_BYTES = 32 * 1024 * 1024
        private const val CLAIM = "token.claim"
        private const val MAX_RECORD_BYTES = 256
        private val noLinks = arrayOf(LinkOption.NOFOLLOW_LINKS)

        /** No directory creation: the caller is responsible for a private app-owned root. */
        fun open(root: Path?, session: String?, tokenSha: String?,
                 issuedAt: Long, expiresAt: Long, maxBytes: Long,
                 maxPages: Int): DurableReceiveJournalV1? {
            val gate = ReceiveGateV1.open(session, tokenSha, issuedAt, expiresAt,
                maxBytes, maxPages) ?: return null
            if (root == null || maxBytes > MAX_STAGE_BYTES) return null
            val key = rootIdentity(root) ?: return null
            return DurableReceiveJournalV1(root, key, session!!, tokenSha!!,
                issuedAt, expiresAt, maxBytes, maxPages, gate)
        }

        /** READ ONLY. Recovery never provides authority to resume transmission. */
        fun inspect(root: Path?, session: String?, tokenSha: String?,
                    issuedAt: Long, expiresAt: Long, maxBytes: Long,
                    maxPages: Int): Recovery {
            val bad = Recovery(RecoveryStatus.POISONED, 0)
            if (root == null || open(root, session, tokenSha, issuedAt,
                    expiresAt, maxBytes, maxPages) == null) return bad
            val rootKey = rootIdentity(root) ?: return bad
            return try {
                val names = Files.newDirectoryStream(root).use { stream ->
                    stream.map { it.fileName.toString() }.toSet()
                }
                if (!stableRoot(root, rootKey)) return bad
                if (names.isEmpty()) return Recovery(RecoveryStatus.FRESH, 0)
                if (CLAIM !in names) return bad
                val claim = readBounded(root.resolve(CLAIM), MAX_RECORD_BYTES.toLong())
                    ?: return bad
                val expected = "v1|$session|$tokenSha|$issuedAt|$expiresAt\n"
                if (!MessageDigest.isEqual(claim, expected.toByteArray(Charsets.US_ASCII)))
                    return bad
                val accounted = mutableSetOf(CLAIM)
                val pages = HashSet<String>()
                var index = 0
                while (index < maxPages) {
                    val number = index.toString().padStart(4, '0')
                    val recName = "page-$number.rec"
                    val blobName = "page-$number.blob"
                    if (recName !in names && blobName !in names) break
                    if (recName !in names || blobName !in names) return bad
                    val rec = readBounded(root.resolve(recName), MAX_RECORD_BYTES.toLong())
                        ?: return bad
                    val line = String(rec, Charsets.US_ASCII)
                    val parts = line.removeSuffix("\n").split('|')
                    if (!line.endsWith("\n") || parts.size != 6 || parts[0] != "v1" ||
                        parts[1] != index.toString() ||
                        !PageTransferIntegrity.isCanonicalUuid(parts[2]) ||
                        parts[2] == session || !pages.add(parts[2])) return bad
                    val length = parts[3].toLongOrNull() ?: return bad
                    if (length.toString() != parts[3] ||
                        !PageTransferIntegrity.isConsistentMetadata(session, parts[2],
                            index, length, parts[4], parts[5], maxBytes)) return bad
                    val body = readBounded(root.resolve(blobName), maxBytes) ?: return bad
                    if (!PageTransferIntegrity.verifyCompleteBytes(session, parts[2],
                            index, length, parts[4], parts[5], maxBytes, body)) return bad
                    accounted.add(recName)
                    accounted.add(blobName)
                    index++
                }
                if (accounted != names || !stableRoot(root, rootKey)) return bad
                Recovery(RecoveryStatus.TOKEN_CONSUMED, index)
            } catch (_: Exception) { bad }
        }

        private fun rootIdentity(path: Path): Any? {
            return try {
                // NOFOLLOW on the leaf alone is insufficient: /trusted/alias/session
                // resolves through an untrusted symbolic-link ancestor. Check every
                // lexical parent as well. A concurrent writer is NOT handled here.
                var current: Path? = path.toAbsolutePath().normalize()
                while (current != null) {
                    val attrs = Files.readAttributes(current,
                        BasicFileAttributes::class.java, *noLinks)
                    if (!attrs.isDirectory || attrs.isSymbolicLink) return null
                    current = current.parent
                }
                val rootAttrs = Files.readAttributes(path,
                    BasicFileAttributes::class.java, *noLinks)
                rootAttrs.fileKey()
            } catch (_: Exception) { null }
        }

        private fun stableRoot(path: Path, key: Any): Boolean = rootIdentity(path) == key

        private fun safeKey(path: Path): Any? =
            try {
                val a = Files.readAttributes(path, BasicFileAttributes::class.java, *noLinks)
                // Linux/Unix file providers expose hardlink count; reject an
                // externally aliased token or receipt before reading it. If an
                // Android provider lacks this view, fail closed (NOT device tested).
                val nlink = Files.getAttribute(path, "unix:nlink", *noLinks) as? Number
                if (!a.isRegularFile || a.isSymbolicLink ||
                    nlink?.toLong() != 1L) null else a.fileKey()
            } catch (_: Exception) { null }

        private fun createAndForce(path: Path, content: ByteArray): Boolean =
            try {
                FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS).use { out ->
                    val b = ByteBuffer.wrap(content)
                    while (b.hasRemaining()) out.write(b)
                    out.force(true)
                }
                true
            } catch (_: Exception) { false }

        private fun readBounded(path: Path, limit: Long): ByteArray? {
            if (limit < 0 || limit > MAX_STAGE_BYTES) return null
            val before = safeKey(path) ?: return null
            return try {
                FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input ->
                    val len = input.size()
                    if (len < 0 || len > limit) return null
                    val output = ByteArray(len.toInt())
                    val buffer = ByteBuffer.wrap(output)
                    while (buffer.hasRemaining()) if (input.read(buffer) < 0) return null
                    if (input.read(ByteBuffer.allocate(1)) != -1) return null
                    if (safeKey(path) != before) return null
                    output
                }
            } catch (_: Exception) { null }
        }

        private fun decodeHex(value: String): ByteArray = ByteArray(value.length / 2) { i ->
            fun nibble(c: Char): Int = if (c <= '9') c - '0' else c - 'a' + 10
            ((nibble(value[2 * i]) shl 4) or nibble(value[2 * i + 1])).toByte()
        }
    }
}
