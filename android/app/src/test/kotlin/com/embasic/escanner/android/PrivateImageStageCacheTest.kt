package com.embasic.escanner.android

import java.io.File
import java.io.IOException
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivateImageStageCacheTest {
    private fun withCache(f: (File) -> Unit) {
        val folder = Files.createTempDirectory("escanner-img-cache-").toFile()
        try { f(folder) }
        finally { folder.walkBottomUp().forEach { it.delete() } }
    }

    @Test fun orphanRecoveredButOriginalUnrelatedFileUntouched() = withCache { cache ->
        val stage = PrivateImageStageCache.create(cache)
        assertTrue(PrivateImageStageCache.finish(cache, stage))
        val orphan = File.createTempFile("escanner-image-", ".tmp",
            File(cache, "escanner-image-stages"))
        // The orphan filename above is not UUID; strict policy must NOT
        // delete unknown stage naming even after crash.
        val other = File(cache, "original.jpg").apply { writeText("private") }
        val result = PrivateImageStageCache.recover(cache)
        assertEquals(0, result.removed)
        assertTrue(orphan.exists())
        assertTrue(other.exists())
    }

    @Test fun exactUuidOrphanDeletedWhileActiveStageProtected() = withCache { cache ->
        val orphan = PrivateImageStageCache.create(cache)
        assertTrue(PrivateImageStageCache.finish(cache, orphan))
        orphan.writeText("crashed private export")
        val live = PrivateImageStageCache.create(cache)
        val result = PrivateImageStageCache.recover(cache)
        assertEquals(1, result.removed)
        assertEquals(1, result.protectedSkipped)
        assertFalse(orphan.exists())
        assertTrue(live.exists())
        assertTrue(PrivateImageStageCache.finish(cache, live))
    }

    @Test fun unregisteredStageCannotBeDeletedThroughFinish() = withCache { cache ->
        val stage = PrivateImageStageCache.create(cache)
        assertTrue(PrivateImageStageCache.finish(cache, stage))
        stage.writeText("other")
        try {
            PrivateImageStageCache.finish(cache, stage)
            throw AssertionError("Released stage accepted")
        } catch (expected: IOException) {
            assertTrue(expected.message?.contains("aktif değil") == true)
        }
        assertTrue(stage.exists())
    }

    @Test fun symlinkToOutsideIsNeverDeleted() = withCache { cache ->
        val stage = PrivateImageStageCache.create(cache)
        val path = stage.toPath()
        val external = Files.createTempFile("escanner-outside-", ".jpg")
        try {
            assertTrue(PrivateImageStageCache.finish(cache, stage))
            Files.write(external, "keep".toByteArray())
            Files.createSymbolicLink(path, external)
            val recovery = PrivateImageStageCache.recover(cache)
            assertEquals(0, recovery.removed)
            assertEquals(1, recovery.protectedSkipped)
            assertTrue(Files.isSymbolicLink(path))
            assertEquals("keep", String(Files.readAllBytes(external)))
        } finally {
            Files.deleteIfExists(path)
            Files.deleteIfExists(external)
        }
    }
}
