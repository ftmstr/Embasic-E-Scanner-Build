package com.embasic.escanner.android

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Matrix
import android.graphics.Paint
import android.media.ExifInterface
import java.io.File
import java.io.IOException

/**
 * Platform-only adapter for the shared integer EXIF coordinate recipe.
 * Android BitmapFactory does not apply JPEG EXIF orientation. Normalize the
 * private working bitmap BEFORE both the manual crop dialog and PDF export.
 * Never modify or rewrite the imported original file or its SHA-256.
 *
 * PNG eXIf chunks are not read by this adapter (Android API26 decoder
 * portability not verified). A PNG with eXIf must not be treated as parity-
 * verified against Windows; add a source gate before claiming PNG EXIF parity.
 */
internal object ExifBitmapNormalizer {
    fun read(file: File): ExifOrientationRecipe {
        if (!file.extension.equals("jpg", ignoreCase = true))
            return ExifOrientationRecipe.NORMAL
        val tag = ExifInterface(file.absolutePath).getAttributeInt(
            ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)
        return ExifOrientationRecipe.fromTag(tag)
            ?: throw IOException("Geçersiz JPEG EXIF yönü: $tag")
    }

    fun apply(raw: Bitmap, recipe: ExifOrientationRecipe): Bitmap {
        if (recipe.tag == 1) return raw
        val (outW, outH) = recipe.outputSize(raw.width, raw.height)
        val width = raw.width.toFloat()
        val height = raw.height.toFloat()
        // Affine transform in continuous pixel-EDGE coordinates. The integer
        // origin/upper bound equals width/height (not width-1/height-1):
        // Android draws bitmap pixel centers at x+.5 / y+.5. This places
        // every one of the 8 EXIF transforms on integral pixel centers.
        val coeffs = when (recipe.tag) {
            2 -> floatArrayOf(-1f, 0f, width, 0f, 1f, 0f, 0f, 0f, 1f)
            3 -> floatArrayOf(-1f, 0f, width, 0f, -1f, height, 0f, 0f, 1f)
            4 -> floatArrayOf(1f, 0f, 0f, 0f, -1f, height, 0f, 0f, 1f)
            5 -> floatArrayOf(0f, 1f, 0f, 1f, 0f, 0f, 0f, 0f, 1f)
            6 -> floatArrayOf(0f, -1f, height, 1f, 0f, 0f, 0f, 0f, 1f)
            7 -> floatArrayOf(0f, -1f, height, -1f, 0f, width, 0f, 0f, 1f)
            8 -> floatArrayOf(0f, 1f, 0f, -1f, 0f, width, 0f, 0f, 1f)
            else -> throw IOException("Geçersiz EXIF dönüştürmesi")
        }
        val result = Bitmap.createBitmap(outW, outH, Bitmap.Config.ARGB_8888)
        try {
            val matrix = Matrix().apply { setValues(coeffs) }
            // No filtering/interpolation for these exact right-angle/mirror maps.
            Canvas(result).drawBitmap(raw, matrix, Paint(0))
            return result
        } catch (error: Exception) {
            result.recycle()
            throw error
        }
    }
}
