package com.embasic.escanner.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ExifOrientationRecipeTest {
    @Test fun sharedExifGoldenAllEightTagsAndBothOppositeCorners() {
        val input = javaClass.classLoader!!.getResourceAsStream("exif-orientation-v1.tsv")
            ?: error("Missing canonical shared EXIF fixture")
        input.bufferedReader().useLines { lines ->
            var cases = 0
            val seen = mutableSetOf<Int>()
            for (line in lines.filter { it.isNotBlank() && !it.startsWith("#") }) {
                val a = line.split('\t').map(String::toInt)
                assertEquals("EXIF golden field count", 9, a.size)
                val exif = ExifOrientationRecipe.fromTag(a[0])
                    ?: error("Unexpected golden EXIF tag")
                assertEquals(a[0].toString(), a[5] to a[6], exif.outputSize(a[1], a[2]))
                assertEquals(a[0].toString(), a[7] to a[8],
                    exif.mapPixel(a[1], a[2], a[3], a[4]))
                cases++
                seen += a[0]
            }
            assertEquals("Expected all EXIF transforms", (1..8).toSet(), seen)
            assertEquals("Expected two corners per transform", 16, cases)
        }
    }

    @Test fun malformedTagsAndGeometryMustFailClosed() {
        for (tag in listOf(-1, 0, 9, 255)) assertNull(ExifOrientationRecipe.fromTag(tag))
        val normal = ExifOrientationRecipe.NORMAL
        for ((w, h) in listOf(0 to 3, 3 to 0, -1 to 3, 20000 to 20000)) {
            try {
                normal.outputSize(w, h)
                error("Invalid EXIF image geometry admitted")
            } catch (_: IllegalArgumentException) { }
        }
        for ((x, y) in listOf(-1 to 0, 0 to -1, 3 to 1, 0 to 2)) {
            try {
                normal.mapPixel(3, 2, x, y)
                error("Out-of-range EXIF pixel admitted")
            } catch (_: IllegalArgumentException) { }
        }
    }
}
