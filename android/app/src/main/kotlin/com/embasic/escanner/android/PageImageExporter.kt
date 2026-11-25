package com.embasic.escanner.android

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/**
 * Encodes a single decoded / EXIF-normalized / quad-warped immutable-source
 * page using the Android platform encoder. Runs off the UI thread. JPEG
 * deliberately flattens transparency onto white; PNG retains source alpha.
 * A rotation allocates another raster only after an explicit heap preflight.
 */
internal object PageImageExporter {
    fun encode(
        stage: File, source: Bitmap, clockwise: Int, format: PageImageExportPlan.Format
    ): PageImageExportPlan.Size {
        val expected = PageImageExportPlan.outputSize(
            source.width, source.height, clockwise
        )
        val needsCanvas = clockwise != 0 || format == PageImageExportPlan.Format.JPEG
        val target = if (needsCanvas) {
            val required = expected.width.toLong() * expected.height * 4 +
                16L * 1024L * 1024L
            val runtime = Runtime.getRuntime()
            val free = runtime.maxMemory() -
                (runtime.totalMemory() - runtime.freeMemory())
            if (required > free) throw IOException("Görsel dışa aktarma belleği yetersiz")
            Bitmap.createBitmap(expected.width, expected.height, Bitmap.Config.ARGB_8888)
                .also { rendered ->
                    try {
                        val canvas = Canvas(rendered)
                        if (format == PageImageExportPlan.Format.JPEG)
                            canvas.drawColor(Color.WHITE)
                        when (clockwise) {
                            90 -> { canvas.translate(expected.width.toFloat(), 0f); canvas.rotate(90f) }
                            180 -> { canvas.translate(expected.width.toFloat(),
                                expected.height.toFloat()); canvas.rotate(180f) }
                            270 -> { canvas.translate(0f, expected.height.toFloat()); canvas.rotate(270f) }
                        }
                        canvas.drawBitmap(source, 0f, 0f,
                            Paint(Paint.FILTER_BITMAP_FLAG or Paint.ANTI_ALIAS_FLAG))
                    } catch (error: Exception) {
                        rendered.recycle()
                        throw error
                    }
                }
        } else source
        try {
            FileOutputStream(stage).use { output ->
                val encoded = target.compress(
                    if (format == PageImageExportPlan.Format.JPEG)
                        Bitmap.CompressFormat.JPEG else Bitmap.CompressFormat.PNG,
                    if (format == PageImageExportPlan.Format.JPEG) 92 else 100,
                    output
                )
                if (!encoded) throw IOException("Görsel kodlanamadı")
                output.fd.sync()
            }
        } finally {
            if (target !== source) target.recycle()
        }

        // Source and target sanity check without an extra full-resolution
        // bitmap decode. A native decoder's bounds probe is not pixel QA.
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(stage.absolutePath, bounds)
        PageImageExportPlan.requireEncoded(
            format, expected, bounds.outMimeType, bounds.outWidth, bounds.outHeight
        )
        return expected
    }
}
