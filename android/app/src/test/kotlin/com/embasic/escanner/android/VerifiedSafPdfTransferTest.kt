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
}
