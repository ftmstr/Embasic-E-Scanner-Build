package com.embasic.escanner.android

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivatePdfStageCacheTest {
    private fun withCache(block: (File) -> Unit) {
        val parent = Files.createTempDirectory("escanner-stage-test-").toFile()
        try { block(parent) }
        finally {
            parent.walkBottomUp().forEach { it.delete() }
        }
    }

    @Test fun recoveryRemovesOnlyKnownOrphanPdfStages() = withCache { cache ->
        val old = File(cache, "escanner-pdf-12345678.tmp").apply { writeText("legacy stage") }
        val crash = File(cache,
            "escanner-pdf-01234567-89ab-4cde-8f01-0123456789ab.tmp").apply {
            writeText("orphan new stage")
        }
        val original = File(cache, "private-original.jpg").apply { writeText("original") }
        val import = File(cache, "in-12345678.pending").apply { writeText("private import") }
        val other = File(cache, "escanner-pdf-unexpected.tmp").apply { writeText("other") }
        val recovery = PrivatePdfStageCache.recover(cache)
        assertEquals(2, recovery.removed)
        assertEquals(0, recovery.failed)
        assertFalse(old.exists())
        assertFalse(crash.exists())
        assertTrue(original.exists())
        assertTrue(import.exists())
        assertTrue(other.exists())
    }

    @Test fun activeExportStageSurvivesRecreatedActivityRecovery() = withCache { cache ->
        val active = PrivatePdfStageCache.create(cache)
        active.writeText("unfinished but active")
        val sweep = PrivatePdfStageCache.recover(cache)
        assertEquals(0, sweep.removed)
        assertEquals(1, sweep.activeSkipped)
        assertTrue(active.exists())
        assertTrue(PrivatePdfStageCache.finish(cache, active))
        assertFalse(active.exists())
        val retry = PrivatePdfStageCache.recover(cache)
        assertEquals(0, retry.removed)
        assertEquals(0, retry.failed)
    }

    @Test fun unknownStageCannotBeReleasedOrDeleted() = withCache { cache ->
        val unregistered = File(cache, "escanner-pdf-12345678.tmp").apply {
            writeText("unregistered")
        }
        try {
            PrivatePdfStageCache.finish(cache, unregistered)
            throw AssertionError("Unregistered stage deleted")
        } catch (expected: IOException) {
            assertTrue(expected.message!!.contains("aktif değil"))
        }
        assertTrue(unregistered.exists())
    }

    @Test fun matchingDirectoryIsNotRecursedOrDeleted() = withCache { cache ->
        val folder = File(cache, "escanner-pdf-23456789.tmp").apply { mkdir() }
        val inside = File(folder, "keep.pdf").apply { writeText("keep") }
        val result = PrivatePdfStageCache.recover(cache)
        assertEquals(0, result.removed)
        assertEquals(1, result.unsafeSkipped)
        assertEquals("keep", inside.readText())
    }

    @Test fun matchingSymlinkCannotDeleteExternalTarget() = withCache { cache ->
        val outside = Files.createTempFile("escanner-outside-", ".pdf")
        val link = File(cache, "escanner-pdf-34567890.tmp").toPath()
        try {
            Files.writeString(outside, "protected content")
            Files.createSymbolicLink(link, outside)
            val result = PrivatePdfStageCache.recover(cache)
            assertEquals(0, result.removed)
            assertEquals(1, result.unsafeSkipped)
            assertEquals("protected content", Files.readString(outside))
            assertTrue(Files.isSymbolicLink(link))
        } finally {
            Files.deleteIfExists(link)
            Files.deleteIfExists(outside)
        }
    }

    @Test fun refusingNonDirectoryAndSymlinkedCacheFailsClosed() = withCache { cache ->
        val notDirectory = File(cache, "not-a-folder").apply { writeText("keep") }
        try {
            PrivatePdfStageCache.recover(notDirectory)
            throw AssertionError("Unsafe cache path accepted")
        } catch (expected: IOException) {
            assertTrue(expected.message!!.contains("cache klasörü"))
        }
        val linkDir = File(cache, "redirect").toPath()
        try {
            Files.createSymbolicLink(linkDir, cache.toPath())
            try {
                PrivatePdfStageCache.create(linkDir.toFile())
                throw AssertionError("Symlinked cache accepted")
            } catch (expected: IOException) {
                assertTrue(expected.message!!.contains("cache klasörü"))
            }
        } finally { Files.deleteIfExists(linkDir) }
    }

    @Test fun multipleCurrentExportsRemainProtectedUntilFinish() = withCache { cache ->
        val first = PrivatePdfStageCache.create(cache)
        val second = PrivatePdfStageCache.create(cache)
        val recovery = PrivatePdfStageCache.recover(cache)
        assertEquals(2, recovery.activeSkipped)
        assertEquals(0, recovery.removed)
        assertTrue(PrivatePdfStageCache.finish(cache, first))
        assertTrue(second.exists())
        assertTrue(PrivatePdfStageCache.finish(cache, second))
    }

    @Test fun boundedSweepingReportsRemainingOrphansInsteadOfFalseSuccess() =
        withCache { cache ->
            repeat(131) { i ->
                File(cache, "escanner-pdf-${(10000000 + i)}.tmp").writeText("orphan")
            }
            val first = PrivatePdfStageCache.recover(cache)
            assertEquals(128, first.removed)
            assertEquals(3, first.failed)
            val second = PrivatePdfStageCache.recover(cache)
            assertEquals(3, second.removed)
            assertEquals(0, second.failed)
        }
}
