package com.embasic.escanner.android

import java.io.IOException
import java.security.MessageDigest

/**
 * Pure Kotlin, Android-independent raster validation contract. Native bitmap
 * rendering is in PdfRasterGate; these checks and ARGB digest run under JUnit.
 * This is a deterministic LOW-RES raster acceptance, not full-resolution
 * golden-image parity or a physical-device acceptance claim.
 */
internal object PdfRasterPlan {
    const val A4_WIDTH = 595
    const val A4_HEIGHT = 842
    const val PREVIEW_WIDTH = 192
    const val PREVIEW_HEIGHT = 272
    private const val MAX_PAGES = 100

    fun requireDocument(actualPages: Int, expectedPages: Int) {
        if (expectedPages !in 1..MAX_PAGES || actualPages != expectedPages)
            throw IOException("PDF sayfa sayısı kabul edilmedi")
    }

    fun requireA4(pageWidth: Int, pageHeight: Int) {
        if (pageWidth != A4_WIDTH || pageHeight != A4_HEIGHT)
            throw IOException("PDF A4 sayfa geometrisi uyuşmuyor")
    }

    internal class Digest {
        private val md = MessageDigest.getInstance("SHA-256")
        private val bytes = ByteArray(PREVIEW_WIDTH * PREVIEW_HEIGHT * 4)
        private var nextPage = 0

        fun addPage(argb: IntArray, index: Int) {
            if (index != nextPage || argb.size != PREVIEW_WIDTH * PREVIEW_HEIGHT)
                throw IOException("PDF raster sayfa sırası/boyutu geçersiz")
            var offset = 0
            for (pixel in argb) {
                bytes[offset++] = (pixel ushr 24).toByte()
                bytes[offset++] = (pixel ushr 16).toByte()
                bytes[offset++] = (pixel ushr 8).toByte()
                bytes[offset++] = pixel.toByte()
            }
            // Fixed-size buffers plus explicit 4-byte page index give an
            // unambiguous ordered digest across 1..100 rendered pages.
            md.update(byteArrayOf(
                (index ushr 24).toByte(), (index ushr 16).toByte(),
                (index ushr 8).toByte(), index.toByte()
            ))
            md.update(bytes)
            nextPage++
        }

        fun finish(expectedPages: Int): String {
            if (nextPage != expectedPages || expectedPages !in 1..MAX_PAGES)
                throw IOException("PDF raster sayfa sayısı eksik")
            return md.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
        }
    }
}
