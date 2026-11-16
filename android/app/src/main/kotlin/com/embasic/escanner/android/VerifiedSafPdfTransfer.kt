package com.embasic.escanner.android

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest

/**
 * Bounded, provider-neutral SAF transfer contract. Success requires:
 * (1) staged bytes complete; (2) closed provider output; (3) target reopened;
 * (4) target size + SHA-256 EXACT match. The Android caller also reopens with
 * PdfRenderer and validates page count. No SAF provider is assumed atomic.
 *
 * All streams close even if a provider throws. This does not restore a
 * preexisting destination or guarantee a power-loss-durable provider commit.
 */
internal object VerifiedSafPdfTransfer {
    private const val MAX_BYTES = 512L * 1024L * 1024L
    private const val BUFFER = 64 * 1024
    // InputStream.read(byte[],...) is required to make progress or return EOF.
    // Nonconforming cloud/document providers can return zero forever. Bound
    // consecutive zero reads so a worker cannot spin indefinitely without IO.
    private const val MAX_ZERO_READS = 16
    data class Receipt(val bytes: Long, val sha256: String)

    fun copyAndVerify(
        staged: File,
        openTarget: () -> OutputStream?,
        reopenTarget: () -> InputStream?
    ): Receipt {
        if (!staged.isFile || staged.length() !in 1..MAX_BYTES)
            throw IOException("Geçersiz SAF PDF staging boyutu")

        // Reopen the staged file before any provider mutation; source must stay
        // exactly the same while streaming, not merely have matching length.
        val expected = staged.inputStream().use { digest(it, MAX_BYTES) }
        if (expected.bytes != staged.length())
            throw IOException("PDF staging değişti")
        val output = openTarget() ?: throw IOException("SAF yazma akışı yok")
        var copied = 0L
        val copiedDigest = MessageDigest.getInstance("SHA-256")
        output.use { stream ->
            staged.inputStream().use { input ->
                val bytes = ByteArray(BUFFER)
                var zeroReads = 0
                while (true) {
                    val n = input.read(bytes)
                    if (n == -1) break
                    if (n == 0) {
                        if (++zeroReads >= MAX_ZERO_READS)
                            throw IOException("PDF staging akışı ilerlemiyor")
                        continue
                    }
                    zeroReads = 0
                    copied += n
                    if (copied > expected.bytes) throw IOException("PDF staging büyüdü")
                    copiedDigest.update(bytes, 0, n)
                    stream.write(bytes, 0, n)
                }
            }
            stream.flush()
        }
        if (copied != expected.bytes ||
            copiedDigest.digest().toHex() != expected.sha256)
            throw IOException("PDF staging kopyalama sırasında değişti")

        // Only now reopen the provider resource. Treat unreadable/cloud-stale
        // target as NOT VERIFIED, never emit "PDF kaydedildi".
        val verified = (reopenTarget() ?: throw IOException("SAF yeniden açılamıyor"))
            .use { digest(it, expected.bytes) }
        if (verified != expected)
            throw IOException("SAF hedefi eksik/bozuk veya SHA-256 uyuşmuyor")
        return verified
    }

    private fun digest(input: InputStream, limit: Long): Receipt {
        val md = MessageDigest.getInstance("SHA-256")
        val bytes = ByteArray(BUFFER)
        var total = 0L
        var zeroReads = 0
        while (true) {
            val n = input.read(bytes)
            if (n == -1) break
            if (n == 0) {
                if (++zeroReads >= MAX_ZERO_READS)
                    throw IOException("SAF/PDF okuma akışı ilerlemiyor")
                continue
            }
            zeroReads = 0
            total += n
            if (total > limit) throw IOException("PDF bayt sınırı aşıldı")
            md.update(bytes, 0, n)
        }
        return Receipt(total, md.digest().toHex())
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
