package com.embasic.escanner.android

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.Paint
import java.io.IOException
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/**
 * Renders a normalized four-point crop from decoded immutable image pixels
 * into a new bounded bitmap. Android Skia's projective matrix maps the source
 * quadrilateral to a rectangle. The source asset and original bitmap stay intact.
 * Output is bounded to <= 2400px per edge; no full-resolution claim.
 */
internal object PagePerspective {
    fun warp(source: Bitmap, quad: PageQuadRecipe): Bitmap {
        require(!quad.isFullFrame)
        val w = source.width.toFloat()
        val h = source.height.toFloat()
        fun edge(i: Int, j: Int) = hypot(
            (quad.x(j) - quad.x(i)) * w, (quad.y(j) - quad.y(i)) * h)
        val estimatedWidth = max(edge(0, 1), edge(3, 2))
        val estimatedHeight = max(edge(0, 3), edge(1, 2))
        val limit = min(1f, 2400f / max(estimatedWidth, estimatedHeight))
        val outW = max(32, (estimatedWidth * limit).roundToInt())
        val outH = max(32, (estimatedHeight * limit).roundToInt())
        if (outW.toLong() * outH > 6_000_000L)
            throw IOException("Kırpma çıktısı sınırı")
        val from = FloatArray(8) { i ->
            if (i % 2 == 0) quad.x(i / 2) * (w - 1f)
            else quad.y(i / 2) * (h - 1f)
        }
        val to = floatArrayOf(0f, 0f, outW.toFloat(), 0f,
            outW.toFloat(), outH.toFloat(), 0f, outH.toFloat())
        val matrix = Matrix()
        if (!matrix.setPolyToPoly(from, 0, to, 0, 4))
            throw IOException("Perspektif matrisi oluşturulamadı")
        val out = Bitmap.createBitmap(outW, outH, Bitmap.Config.ARGB_8888)
        try {
            val canvas = Canvas(out)
            canvas.drawColor(Color.WHITE)
            canvas.drawBitmap(source, matrix, Paint(Paint.ANTI_ALIAS_FLAG or
                Paint.FILTER_BITMAP_FLAG or Paint.DITHER_FLAG))
            return out
        } catch (e: Exception) {
            out.recycle()
            throw e
        }
    }
}
