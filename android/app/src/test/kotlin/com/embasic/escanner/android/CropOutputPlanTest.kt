package com.embasic.escanner.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CropOutputPlanTest {
    @Test fun sharedGoldenOriginalScaleAndBoundedDownscale() {
        val input = javaClass.classLoader!!.getResourceAsStream("perspective-output-v1.tsv")
            ?: error("Missing canonical shared crop sizing golden fixture")
        input.bufferedReader().useLines { lines ->
            var cases = 0
            for (line in lines.filter { it.isNotBlank() && !it.startsWith("#") }) {
                val p = line.split('\t')
                assertEquals("Golden fixture fields: $line", 6, p.size)
                val quad = PageQuadRecipe.parse(p[3]) ?: error("Invalid fixture $line")
                val actual = CropOutputPlan.measure(p[1].toInt(), p[2].toInt(), quad)
                assertEquals(p[0], p[4].toInt(), actual.width)
                assertEquals(p[0], p[5].toInt(), actual.height)
                assertTrue(actual.width <= CropOutputPlan.MAX_EDGE)
                assertTrue(actual.width.toLong() * actual.height <= CropOutputPlan.MAX_PIXELS)
                cases++
            }
            assertEquals("Shared golden fixture count", 5, cases)
        }
    }

    @Test fun invalidGeometryFailsBeforeBitmapDecode() {
        for ((w, h) in listOf(0 to 100, -1 to 200, 100 to 0, 20000 to 20000)) {
            try {
                CropOutputPlan.measure(w, h, PageQuadRecipe.INSET)
                error("Invalid geometry accepted: $w x $h")
            } catch (_: IllegalArgumentException) { /* expected */ }
        }
    }
}
