package com.embasic.escanner.android

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PageImageExportPlanTest {
    private fun rejects(part: String, block: () -> Unit) {
        try { block(); throw AssertionError("Rejected input accepted") }
        catch (expected: IOException) {
            assertTrue("wrong error: ${expected.message}",
                expected.message?.contains(part) == true)
        }
    }

    @Test fun formatsMapToExactMimeAndExtension() {
        assertEquals("image/jpeg", PageImageExportPlan.Format.JPEG.mime)
        assertEquals("jpg", PageImageExportPlan.Format.JPEG.extension)
        assertEquals("image/png", PageImageExportPlan.Format.PNG.mime)
        assertEquals("png", PageImageExportPlan.Format.PNG.extension)
    }

    @Test fun clockwiseRotationSwapsDimensionsOnlyForQuarterTurns() {
        val p = PageImageExportPlan
        assertEquals(p.Size(1600, 1200), p.outputSize(1600, 1200, 0))
        assertEquals(p.Size(1200, 1600), p.outputSize(1600, 1200, 90))
        assertEquals(p.Size(1600, 1200), p.outputSize(1600, 1200, 180))
        assertEquals(p.Size(1200, 1600), p.outputSize(1600, 1200, 270))
    }

    @Test fun outOfBoundsOrUnsupportedRotationRejectedBeforeEncode() {
        rejects("döndürme") { PageImageExportPlan.outputSize(2, 2, 45) }
        rejects("geometrisi") { PageImageExportPlan.outputSize(0, 100, 90) }
        rejects("geometrisi") { PageImageExportPlan.outputSize(8001, 5, 0) }
        rejects("geometrisi") { PageImageExportPlan.outputSize(6000, 5000, 0) }
    }

    @Test fun maximum24MegaPixelsWithBoundedEdgesAccepted() {
        assertEquals(PageImageExportPlan.Size(6000, 4000),
            PageImageExportPlan.outputSize(6000, 4000, 0))
        assertEquals(PageImageExportPlan.Size(4000, 6000),
            PageImageExportPlan.outputSize(6000, 4000, 90))
    }

    @Test fun actualEncodedMimeAndDimensionsMustMatchRequestedFormat() {
        val p = PageImageExportPlan
        val size = p.Size(842, 595)
        p.requireEncoded(p.Format.JPEG, size, "image/jpeg", 842, 595)
        p.requireEncoded(p.Format.PNG, size, "image/png", 842, 595)
        rejects("MIME") { p.requireEncoded(p.Format.JPEG, size, "image/png", 842, 595) }
        rejects("MIME") { p.requireEncoded(p.Format.PNG, size, "image/png", 595, 842) }
        rejects("MIME") { p.requireEncoded(p.Format.PNG, size, null, 842, 595) }
    }
}
