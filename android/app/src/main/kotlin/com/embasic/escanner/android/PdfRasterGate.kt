package com.embasic.escanner.android

import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor

/**
 * Native Android PdfRenderer acceptance for the actual staged and SAF target
 * PDFs. Always on the export IO executor; renders each A4 page to a bounded
 * 192x272 ARGB surface, hashes raster pixels in page order, closes EVERY page,
 * bitmap, renderer and descriptor. No user document is exported by this gate.
 *
 * Device-backed execution and rendered-pixel visual golden QA NOT VERIFIED.
 */
internal object PdfRasterGate {
    data class Receipt(val pageCount: Int, val rasterSha256: String)

    fun verify(descriptor: ParcelFileDescriptor, expectedPages: Int): Receipt =
        descriptor.use { fd ->
            PdfRenderer(fd).use { pdf ->
                PdfRasterPlan.requireDocument(pdf.pageCount, expectedPages)
                val digest = PdfRasterPlan.Digest()
                val bitmap = Bitmap.createBitmap(
                    PdfRasterPlan.PREVIEW_WIDTH,
                    PdfRasterPlan.PREVIEW_HEIGHT,
                    Bitmap.Config.ARGB_8888
                )
                val pixels = IntArray(PdfRasterPlan.PREVIEW_WIDTH * PdfRasterPlan.PREVIEW_HEIGHT)
                try {
                    for (index in 0 until pdf.pageCount) {
                        pdf.openPage(index).use { page ->
                            PdfRasterPlan.requireA4(page.width, page.height)
                            bitmap.eraseColor(Color.WHITE)
                            page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                            bitmap.getPixels(pixels, 0, bitmap.width,
                                0, 0, bitmap.width, bitmap.height)
                            digest.addPage(pixels, index)
                        }
                    }
                    Receipt(pdf.pageCount, digest.finish(expectedPages))
                } finally {
                    bitmap.recycle()
                }
            }
        }
}
