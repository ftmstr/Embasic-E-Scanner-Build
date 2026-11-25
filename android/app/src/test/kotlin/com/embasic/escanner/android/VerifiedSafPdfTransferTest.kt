package com.embasic.escanner.android

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.nio.file.Files
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VerifiedSafPdfTransferTest {
    // Synthetic PDF-like data. The Android platform PdfRenderer validates
    // real PDF structure; these JVM tests intentionally test BYTE transfer.
    private val source = ("%PDF-1.4\\n".repeat(9000) + "\\n%%EOF").toByteArray()

    private fun staged(): java.io.File =
        Files.createTempFile("saf-verified-golden-", ".pdf").toFile()
            .apply { writeBytes(source); deleteOnExit() }

    @Test fun exactSafRoundTripReturnsSizeAndSha256OnlyAfterReadback() {
        val file = staged()
        val output = ByteArrayOutputStream()
        var reads = 0
        val receipt = VerifiedSafPdfTransfer.copyAndVerify(file,
            openTarget = { output },
            reopenTarget = { reads++; ByteArrayInputStream(output.toByteArray()) })
        assertEquals(source.size.toLong(), receipt.bytes)
        assertEquals(64, receipt.sha256.length)
        assertArrayEquals(source, output.toByteArray())
        assertEquals(1, reads)
    }

    @Test fun truncatedDestinationFailsWithoutReportingSuccess() {
        val file = staged()
        val output = ByteArrayOutputStream()
        try {
            VerifiedSafPdfTransfer.copyAndVerify(file, { output }) {
                ByteArrayInputStream(output.toByteArray().copyOf(output.size() - 1))
            }
            throw AssertionError("Truncated SAF destination falsely accepted")
        } catch (expected: IOException) {
            assertTrue(expected.message!!.contains("SAF hedefi"))
        }
    }

    @Test fun sameLengthCorruptionFailsSha256Verification() {
        val file = staged()
        val output = ByteArrayOutputStream()
        try {
            VerifiedSafPdfTransfer.copyAndVerify(file, { output }) {
                val altered = output.toByteArray().also { it[it.lastIndex / 2] =
                    (it[it.lastIndex / 2].toInt() xor 0x40).toByte() }
                ByteArrayInputStream(altered)
            }
            throw AssertionError("Same length corrupted destination accepted")
        } catch (expected: IOException) {
            assertTrue(expected.message!!.contains("SHA-256"))
        }
    }

    @Test fun interruptedTargetWriteFailsAndNeverReadsBack() {
        val file = staged()
        var readCalls = 0
        var closed = false
        try {
            VerifiedSafPdfTransfer.copyAndVerify(file,
                openTarget = {
                    object : OutputStream() {
                        var written = 0
                        override fun write(value: Int) {
                            if (written++ >= 12) throw IOException("simulated storage full")
                        }
                        override fun write(b: ByteArray, off: Int, len: Int) {
                            write(b[off].toInt())
                            throw IOException("simulated interrupted provider")
                        }
                        override fun close() { closed = true }
                    }
                },
                reopenTarget = { readCalls++; ByteArrayInputStream(source) })
            throw AssertionError("Partial write accepted")
        } catch (expected: IOException) {
            assertEquals("simulated interrupted provider", expected.message)
        }
        assertTrue(closed)
        assertEquals(0, readCalls)
    }

    @Test fun providerUnavailableToReopenFailsClosed() {
        val file = staged()
        try {
            VerifiedSafPdfTransfer.copyAndVerify(file, { ByteArrayOutputStream() }, { null })
            throw AssertionError("Unreadable SAF provider accepted")
        } catch (expected: IOException) {
            assertTrue(expected.message!!.contains("yeniden açılamıyor"))
        }
    }

    @Test fun invalidOrEmptyStagingRejectedBeforeTouchingTarget() {
        val file = Files.createTempFile("saf-empty-", ".pdf").toFile()
        file.deleteOnExit()
        var touched = false
        try {
            VerifiedSafPdfTransfer.copyAndVerify(file,
                openTarget = { touched = true; ByteArrayOutputStream() },
                reopenTarget = { ByteArrayInputStream(source) })
            throw AssertionError("Empty staging accepted")
        } catch (expected: IOException) {
            assertTrue(expected.message!!.contains("staging boyutu"))
        }
        assertTrue(!touched)
    }

    /**
     * Provider simulators, NOT a real Android DocumentsProvider integration.
     * They assert no false success for a cloud-stale, append-only, interrupted
     * or nonconforming InputStream. Real native SAF acceptance remains open.
     */
    @Test fun appendOnlyProviderRetainingOldBytesFailsClosed() {
        val file = staged()
        val data = ByteArrayOutputStream().apply { write("PREVIOUS_USER_CONTENT".toByteArray()) }
        // Readback exceeds the staged length, so the bounded digest rejects
        // the extra bytes BEFORE the final hash-compare branch can run.
        VerifiedSafPdfTransferTest.assertIOException("PDF bayt sınırı") {
            VerifiedSafPdfTransfer.copyAndVerify(file, { data },
                { ByteArrayInputStream(data.toByteArray()) })
        }
    }

    @Test fun cloudProviderReturnsStaleSnapshotAfterSuccessfulClose() {
        val file = staged()
        val stale = ByteArray(64) { 0x23 }
        val data = ByteArrayOutputStream()
        VerifiedSafPdfTransferTest.assertIOException("SAF hedefi") {
            VerifiedSafPdfTransfer.copyAndVerify(file, { data },
                { ByteArrayInputStream(stale) })
        }
        assertArrayEquals(source, data.toByteArray())
    }

    @Test fun providerCloseThrowsAndReadbackIsNeverAttempted() {
        val file = staged()
        var readback = 0
        var closed = 0
        VerifiedSafPdfTransferTest.assertIOException("provider close failed") {
            VerifiedSafPdfTransfer.copyAndVerify(file, openTarget = {
                object : ByteArrayOutputStream() {
                    override fun close() {
                        closed++
                        throw IOException("provider close failed")
                    }
                }
            }, reopenTarget = { readback++; ByteArrayInputStream(source) })
        }
        assertEquals(1, closed)
        assertEquals(0, readback)
    }

    @Test fun targetReadbackThrowsMidstreamAndNeverSucceeds() {
        val file = staged()
        val data = ByteArrayOutputStream()
        VerifiedSafPdfTransferTest.assertIOException("provider disconnected") {
            VerifiedSafPdfTransfer.copyAndVerify(file, { data }, {
                object : ByteArrayInputStream(data.toByteArray()) {
                    var consumed = 0
                    override fun read(b: ByteArray, off: Int, len: Int): Int {
                        if (consumed > 0) throw IOException("provider disconnected")
                        return super.read(b, off, minOf(len, 9)).also {
                            if (it > 0) consumed += it
                        }
                    }
                }
            })
        }
    }

    @Test fun permanentlyZeroReadbackIsRejectedWithoutInfiniteLoop() {
        val file = staged()
        var calls = 0
        var closed = false
        VerifiedSafPdfTransferTest.assertIOException("ilerlemiyor") {
            VerifiedSafPdfTransfer.copyAndVerify(file, { ByteArrayOutputStream() }, {
                object : java.io.InputStream() {
                    override fun read(): Int = 0
                    override fun read(b: ByteArray, off: Int, len: Int): Int {
                        calls++
                        return 0
                    }
                    override fun close() { closed = true }
                }
            })
        }
        assertEquals(16, calls)
        assertTrue(closed)
    }

    @Test fun intermittentZeroReadbackCanRecoverWithoutFalseRejection() {
        val file = staged()
        val data = ByteArrayOutputStream()
        var zeroReads = 0
        val receipt = VerifiedSafPdfTransfer.copyAndVerify(file, { data }, {
            object : ByteArrayInputStream(data.toByteArray()) {
                override fun read(b: ByteArray, off: Int, len: Int): Int {
                    if (zeroReads < 3) {
                        zeroReads++
                        return 0
                    }
                    return super.read(b, off, len)
                }
            }
        })
        assertEquals(3, zeroReads)
        assertEquals(source.size.toLong(), receipt.bytes)
    }

    @Test fun mutationOfStagingBetweenDigestAndStreamIsDetected() {
        val file = staged()
        var readback = 0
        val data = ByteArrayOutputStream()
        VerifiedSafPdfTransferTest.assertIOException("staging kopyalama") {
            VerifiedSafPdfTransfer.copyAndVerify(file,
                openTarget = {
                    val changed = file.readBytes()
                    changed[changed.size / 2] = (changed[changed.size / 2].toInt() xor 1).toByte()
                    file.writeBytes(changed)
                    data
                },
                reopenTarget = { readback++; ByteArrayInputStream(data.toByteArray()) })
        }
        assertEquals(0, readback)
    }

    @Test fun syntheticOneTwentyHundredPageByteBatchesRoundTrip() {
        for (pageCount in listOf(1, 20, 100)) {
            // Byte-only fixture; this is deliberately not a PdfRenderer test.
            val synthetic = buildString {
                append("%PDF-1.4\\n")
                repeat(pageCount) { i ->
                    append("synthetic-page-").append(i).append(':')
                    append("XYZ1234".repeat(512)).append(10.toChar())
                }
                append("%%EOF")
            }.toByteArray()
            val file = Files.createTempFile("saf-batch-", ".pdf").toFile()
            try {
                file.writeBytes(synthetic)
                val output = ByteArrayOutputStream()
                val receipt = VerifiedSafPdfTransfer.copyAndVerify(file,
                    { output }, { ByteArrayInputStream(output.toByteArray()) })
                assertEquals("pages=$pageCount", synthetic.size.toLong(), receipt.bytes)
                assertArrayEquals("pages=$pageCount", synthetic, output.toByteArray())
            } finally {
                file.delete()
            }
        }
    }

    companion object {
        private fun assertIOException(messageFragment: String, block: () -> Unit) {
            try {
                block()
                throw AssertionError("Expected IOException containing $messageFragment")
            } catch (expected: IOException) {
                assertTrue(
                    "Expected $messageFragment, got ${expected.message}",
                    expected.message?.contains(messageFragment) == true
                )
            }
        }
    }
}
