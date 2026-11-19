package com.embasic.escanner.android

import org.junit.Assert.*
import org.junit.Test

class PageQuadRecipeTest {
    @Test fun legacyIdentityAndCanonicalCrossPlatformContract() {
        assertEquals(PageQuadRecipe.FULL, PageQuadRecipe.parse(null))
        assertEquals("0,0;1000,0;1000,1000;0,1000", PageQuadRecipe.FULL.encode())
        assertEquals(PageQuadRecipe.INSET, PageQuadRecipe.parse(PageQuadRecipe.INSET.encode()))
        assertTrue(PageQuadRecipe.FULL.isFullFrame)
    }
    @Test fun editableQuadAndRestartRoundTripWithoutTouchingAsset() {
        var quad = PageQuadRecipe.FULL
        val next = quad.moved(0, 120, 150)
        assertNotNull(next)
        quad = next!!
        assertEquals(quad, PageQuadRecipe.parse(quad.encode()))
        assertEquals(PageQuadRecipe.FULL, PageQuadRecipe.parse(null))
    }
    @Test fun foldedTinyAndInvalidCoordinatesFailClosed() {
        listOf(
            "", "0,0;1000,0;1000,1000",
            "0,0;1000,1000;1000,0;0,1000",
            "0,0;20,0;20,20;0,20",
            "-1,0;1000,0;1000,1000;0,1000",
            "000,0;1000,0;1000,1000;0,1000",
            "0,0;1001,0;1000,1000;0,1000",
            "0,0;1000,0;1000,1000;0,1000 ",
            "0.0,0;1000,0;1000,1000;0,1000"
        ).forEach { assertNull("Must reject $it", PageQuadRecipe.parse(it)) }
        assertNull(PageQuadRecipe.FULL.moved(0, 1000, 1000))
        assertNull(PageQuadRecipe.FULL.moved(-1, 0, 0))
    }
}
