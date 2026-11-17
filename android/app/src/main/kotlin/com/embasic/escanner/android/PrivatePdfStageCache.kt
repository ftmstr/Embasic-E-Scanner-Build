package com.embasic.escanner.android

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.UUID

/**
 * Private cache-only PDF stage lifecycle for the SINGLE-PROCESS Android app.
 *
 * Crash/restart recovery never touches SAF URI targets, private originals,
 * thumbnail assets, subdirectories or arbitrary cache files. A process-wide
 * registry protects exports still active during Activity recreation.
 * A future multiprocess exporter MUST add a cross-process lease before using
 * this same recovery policy; the registry alone is process-local.
 */
internal object PrivatePdfStageCache {
    private const val MAX_SWEEP_CANDIDATES = 128

    // New UUID names, plus old File.createTempFile() decimal names.
    // Deliberately do not match other .tmp, in-*.pending, or documents.
    private val stageName = Regex(
        """escanner-pdf-(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9]{6,24})\.tmp"""
    )
    private val active = HashSet<Path>()

    internal data class Recovery(
        val removed: Int,
        val activeSkipped: Int,
        val unsafeSkipped: Int,
        val failed: Int
    )

    fun create(cacheDir: File): File = synchronized(this) {
        checkDirectory(cacheDir)
        val file = File(cacheDir, "escanner-pdf-${UUID.randomUUID()}.tmp")
        // CREATE_NEW/NO REPLACE: never reuse existing cache or SAF content.
        Files.createFile(file.toPath())
        val path = file.toPath().toAbsolutePath().normalize()
        active.add(path)
        file
    }

    /**
     * Only an export registered by create() may be finished. Do not delete
     * anything that has been swapped to a symlink/directory or moved outside
     * the configured private cache.
     */
    fun finish(cacheDir: File, file: File): Boolean = synchronized(this) {
        val path = file.toPath().toAbsolutePath().normalize()
        if (!active.contains(path))
            throw IOException("PDF staging bu süreçte aktif değil")
        try {
            checkDirectory(cacheDir)
            if (!eligible(cacheDir, file))
                throw IOException("PDF staging güvenli konumda değil")
            Files.deleteIfExists(path)
        } finally {
            active.remove(path)
        }
    }

    /**
     * Called on Activity startup before its workspace restore. Synchronized
     * with create/finish so a re-created Activity never deletes another live
     * export's stage within this Android application process.
     *
     * Only direct child files with strict known names are deleted. No symlink
     * following, no recursion and at most 128 candidate deletions per startup.
     */
    fun recover(cacheDir: File): Recovery = synchronized(this) {
        checkDirectory(cacheDir)
        val entries = cacheDir.listFiles()
            ?: throw IOException("PDF cache listelenemedi")
        var removed = 0
        var activeSkipped = 0
        var unsafeSkipped = 0
        var failed = 0
        var candidates = 0
        for (entry in entries) {
            if (!stageName.matches(entry.name)) continue
            val path = entry.toPath().toAbsolutePath().normalize()
            if (active.contains(path)) {
                activeSkipped++
                continue
            }
            if (++candidates > MAX_SWEEP_CANDIDATES) {
                failed++ // bounded pass; another launch can remove remainder
                continue
            }
            if (!eligible(cacheDir, entry)) {
                unsafeSkipped++ // never follow symlink or recurse into folder
                continue
            }
            try {
                if (Files.deleteIfExists(path)) removed++
            } catch (_: IOException) {
                failed++
            } catch (_: SecurityException) {
                failed++
            }
        }
        Recovery(removed, activeSkipped, unsafeSkipped, failed)
    }

    private fun checkDirectory(dir: File) {
        val path = dir.toPath()
        if (Files.isSymbolicLink(path) ||
            !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS))
            throw IOException("Özel PDF cache klasörü güvenli değil")
    }

    private fun eligible(cacheDir: File, file: File): Boolean {
        val path = file.toPath()
        return stageName.matches(file.name) &&
            file.parentFile?.canonicalFile == cacheDir.canonicalFile &&
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(path)
    }
}
