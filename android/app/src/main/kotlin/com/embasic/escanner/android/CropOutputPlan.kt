package com.embasic.escanner.android

import kotlin.math.floor
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sqrt

/**
 * Cross-platform export geometry: original-image-space quad -> safe raster size.
 * Under the pixel/edge limits, export uses source pixel resolution (no 2400px
 * preview downscale). Larger inputs are downsampled; this is NOT tile streaming.
 */
internal data class CropOutputSize(val width: Int, val height: Int)
internal object CropOutputPlan {
    const val MAX_EDGE = 6000
    const val MAX_PIXELS = 12_000_000L
    const val MAX_INPUT_GEOMETRY = 100_000_000L

    fun measure(width: Int, height: Int, quad: PageQuadRecipe): CropOutputSize {
        if (width <= 0 || height <= 0 ||
            width.toLong() * height > MAX_INPUT_GEOMETRY)
            throw IllegalArgumentException("Invalid input geometry")
        val w = width.toDouble()
        val h = height.toDouble()
        fun distance(i: Int, j: Int) = hypot(
            (quad.x(j) - quad.x(i)).toDouble() * w,
            (quad.y(j) - quad.y(i)).toDouble() * h)
        val targetW = max(distance(0, 1), distance(3, 2))
        val targetH = max(distance(0, 3), distance(1, 2))
        if (!targetW.isFinite() || !targetH.isFinite() || targetW <= 0 || targetH <= 0)
            throw IllegalArgumentException("Degenerate perspective dimensions")
        val factor = min(1.0, min(MAX_EDGE / max(targetW, targetH),
            sqrt(MAX_PIXELS.toDouble() / (targetW * targetH))))
        // Explicit half-up rounding is the parity contract (not banker rounding).
        val outW = max(32, floor(targetW * factor + 0.5).toInt())
        val outH = max(32, floor(targetH * factor + 0.5).toInt())
        if (outW > MAX_EDGE || outH > MAX_EDGE ||
            outW.toLong() * outH > MAX_PIXELS)
            throw IllegalArgumentException("Output geometry exceeds safety limit")
        return CropOutputSize(outW, outH)
    }
}
