package com.embasic.escanner.android

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.UUID

/**
 * Dedicated single-process private image-export stage directory. Does not
 * touch PrivatePdfStageCache, SAF documents, original assets or other caches.
 * Re-created Activities share active leases inside the same process.
 * Multiprocess exporters would require a cross-process lock.
 */
internal object PrivateImageStageCache {
    private val active = HashSet<Path>()
    private val name = Regex(
        """escanner-image-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp"""
    )
    data class Recovery(val removed: Int, val protectedSkipped: Int, val failed: Int)

    private fun directory(cache: File, create: Boolean): File {
        val root = cache.toPath()
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS))
            throw IOException("Özel cache kökü güvenli değil")
        val folder = File(cache, "escanner-image-stages")
        if (create && !folder.exists() && !folder.mkdir())
            throw IOException("Görsel staging klasörü oluşturulamadı")
        if (folder.exists() &&
            !Files.isDirectory(folder.toPath(), LinkOption.NOFOLLOW_LINKS))
            throw IOException("Görsel staging klasörü güvenli değil")
        return folder
    }

    fun create(cache: File): File = synchronized(this) {
        val dir = directory(cache, true)
        val file = File(dir, "escanner-image-${UUID.randomUUID()}.tmp")
        Files.createFile(file.toPath()) // exclusive; never overwrite prior content
        active.add(file.toPath().toAbsolutePath().normalize())
        file
    }

    fun finish(cache: File, file: File): Boolean = synchronized(this) {
        val path = file.toPath().toAbsolutePath().normalize()
        if (!active.contains(path)) throw IOException("Görsel stage aktif değil")
        try {
            val dir = directory(cache, false)
            if (file.parentFile?.canonicalFile != dir.canonicalFile ||
                !name.matches(file.name) ||
                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
                throw IOException("Görsel stage güvenli konumda değil")
            Files.deleteIfExists(path)
        } finally { active.remove(path) }
    }

    /** Strict child-only recovery; bounded to 128 deletions per startup. */
    fun recover(cache: File): Recovery = synchronized(this) {
        val dir = directory(cache, false)
        if (!dir.exists()) return@synchronized Recovery(0, 0, 0)
        val files = dir.listFiles() ?: throw IOException("Görsel stage listelenemiyor")
        var removed = 0
        var protectedSkipped = 0
        var failed = 0
        var attempts = 0
        for (file in files) {
            if (!name.matches(file.name)) continue
            val path = file.toPath().toAbsolutePath().normalize()
            if (active.contains(path)) { protectedSkipped++; continue }
            if (++attempts > 128) { failed++; continue }
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                protectedSkipped++
                continue
            }
            try {
                if (Files.deleteIfExists(path)) removed++
            } catch (_: IOException) { failed++ }
              catch (_: SecurityException) { failed++ }
        }
        Recovery(removed, protectedSkipped, failed)
    }
}
