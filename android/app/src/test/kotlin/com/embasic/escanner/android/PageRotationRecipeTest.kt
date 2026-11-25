package com.embasic.escanner.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PageRotationRecipeTest {
    @Test fun clockwiseCyclePreservesOriginalRotationState() {
        var degrees = 0
        for (next in listOf(90, 180, 270, 0)) {
            degrees = PageRotationRecipe.clockwise(degrees)
            assertEquals(next, degrees)
        }
        assertEquals(0, PageRotationRecipe.reset())
    }

    @Test fun legacyManifestDefaultsToZeroAndRightAnglesRoundTrip() {
        assertEquals(0, PageRotationRecipe.parsePersisted(null))
        for (degrees in listOf(0, 90, 180, 270))
            assertEquals(degrees, PageRotationRecipe.parsePersisted(degrees.toString()))
    }

    @Test fun corruptManifestAnglesFailClosedRatherThanMutatingOriginal() {
        for (invalid in listOf("", "45", "-90", "360", "090", "abc", "1.5", " 90"))
            assertNull("Invalid persisted angle: $invalid",
                PageRotationRecipe.parsePersisted(invalid))
        assertFalse(PageRotationRecipe.isValid(45))
        assertTrue(PageRotationRecipe.isValid(270))
    }

    @Test(expected = IllegalArgumentException::class)
    fun invalidInMemoryAngleCannotAdvance() {
        PageRotationRecipe.clockwise(12)
    }
}
