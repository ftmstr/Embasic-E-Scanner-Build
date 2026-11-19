package com.embasic.escanner.android

/**
 * EXIF tag 0x0112, in immutable SOURCE raster pixel coordinates.
 * Only 1..8 are defined; do not guess a transform for invalid metadata.
 * Windows BitmapDecoder uses ExifOrientationMode.RespectExifOrientation.
 * This JVM-safe geometry contract is shared with the Windows headless tests.
 */
internal class ExifOrientationRecipe private constructor(val tag: Int) {
    val swapsAxes: Boolean get() = tag in 5..8

    fun outputSize(width: Int, height: Int): Pair<Int, Int> {
        require(width > 0 && height > 0 && width.toLong() * height <= 100_000_000L)
        return if (swapsAxes) height to width else width to height
    }

    fun mapPixel(width: Int, height: Int, x: Int, y: Int): Pair<Int, Int> {
        outputSize(width, height)
        require(x in 0 until width && y in 0 until height)
        return when (tag) {
            1 -> x to y
            2 -> width - 1 - x to y
            3 -> width - 1 - x to height - 1 - y
            4 -> x to height - 1 - y
            5 -> y to x
            6 -> height - 1 - y to x
            7 -> height - 1 - y to width - 1 - x
            8 -> y to width - 1 - x
            else -> error("Invalid EXIF tag")
        }
    }

    companion object {
        val NORMAL = ExifOrientationRecipe(1)
        fun fromTag(tag: Int): ExifOrientationRecipe? =
            if (tag in 1..8) ExifOrientationRecipe(tag) else null
    }
}
