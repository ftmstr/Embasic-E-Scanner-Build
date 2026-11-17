package com.embasic.escanner.android

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PdfRasterPlanTest {
    private fun pixels(value: Int = -1) =
        IntArray(PdfRasterPlan.PREVIEW_WIDTH * PdfRasterPlan.PREVIEW_HEIGHT) { value }

    private fun rejected(text: String, block: () -> Unit) {
        try {
            block()
            throw AssertionError("Accepted invalid raster: $text")
        } catch (expected: IOException) {
            assertTrue(expected.message?.contains(text) == true)
        }
    }

    @Test fun exactA4AndPageCountsForOneTwentyHundredAreAccepted() {
        for (count in listOf(1, 20, 100)) {
            PdfRasterPlan.requireDocument(count, count)
            PdfRasterPlan.requireA4(595, 842)
        }
        assertEquals(192, PdfRasterPlan.PREVIEW_WIDTH)
        assertEquals(272, PdfRasterPlan.PREVIEW_HEIGHT)
    }

    @Test fun rejectsPageCountOverflowMissingAndMismatch() {
        for ((actual, expected) in listOf(0 to 1, 1 to 0, 1 to 101, 20 to 100))
            rejected("sayfa sayısı") { PdfRasterPlan.requireDocument(actual, expected) }
    }

    @Test fun rejectsRotatedOrWrongA4Geometry() {
        for ((w, h) in listOf(842 to 595, 594 to 842, 595 to 841, 0 to 842))
            rejected("geometrisi") { PdfRasterPlan.requireA4(w, h) }
    }

    @Test fun orderedRasterPixelHashChangesWhenRealPixelChanges() {
        val initial = pixels(0xffffffff.toInt())
        val d1 = PdfRasterPlan.Digest()
        d1.addPage(initial, 0)
        val a = d1.finish(1)
        val edited = initial.clone()
        edited[edited.size / 2] = 0xff000000.toInt()
        val d2 = PdfRasterPlan.Digest()
        d2.addPage(edited, 0)
        val b = d2.finish(1)
        assertEquals(64, a.length)
        assertNotEquals(a, b)
    }

    @Test fun samePagesDifferentOrderChangesRasterDigest() {
        val first = pixels(0xff123456.toInt())
        val second = pixels(0xfffedcba.toInt())
        val a = PdfRasterPlan.Digest().apply {
            addPage(first, 0); addPage(second, 1)
        }.finish(2)
        val b = PdfRasterPlan.Digest().apply {
            addPage(second, 0); addPage(first, 1)
        }.finish(2)
        assertNotEquals(a, b)
    }

    @Test fun rejectsMissingDuplicatedOrWrongSizeRasterPage() {
        rejected("sırası/boyutu") {
            PdfRasterPlan.Digest().addPage(pixels(), 1)
        }
        rejected("sırası/boyutu") {
            val d = PdfRasterPlan.Digest()
            d.addPage(pixels(), 0)
            d.addPage(pixels(), 0)
        }
        rejected("sırası/boyutu") {
            PdfRasterPlan.Digest().addPage(IntArray(10), 0)
        }
        rejected("sayfa sayısı eksik") {
            PdfRasterPlan.Digest().apply { addPage(pixels(), 0) }.finish(2)
        }
    }
}
