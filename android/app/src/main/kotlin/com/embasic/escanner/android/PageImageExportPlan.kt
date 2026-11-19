package com.embasic.escanner.android

import java.io.IOException

/** Pure policy for a single-page, local-first JPEG/PNG export. */
internal object PageImageExportPlan {
    enum class Format(val mime: String, val extension: String) {
        JPEG("image/jpeg", "jpg"),
        PNG("image/png", "png")
    }

    data class Size(val width: Int, val height: Int)
    private const val MAX_PIXELS = 24_000_000L
    private const val MAX_EDGE = 8000

    fun outputSize(width: Int, height: Int, clockwise: Int): Size {
        if (!PageRotationRecipe.isValid(clockwise))
            throw IOException("Görsel döndürme tarifi geçersiz")
        if (width <= 0 || height <= 0 || width > MAX_EDGE || height > MAX_EDGE ||
            width.toLong() * height > MAX_PIXELS)
            throw IOException("Görsel çıktı geometrisi reddedildi")
        return if (clockwise == 90 || clockwise == 270)
            Size(height, width) else Size(width, height)
    }

    fun requireEncoded(format: Format, expected: Size, mime: String?,
                       width: Int, height: Int) {
        if (mime != format.mime || expected.width != width || expected.height != height)
            throw IOException("Görsel MIME veya boyut doğrulaması başarısız")
    }
}
