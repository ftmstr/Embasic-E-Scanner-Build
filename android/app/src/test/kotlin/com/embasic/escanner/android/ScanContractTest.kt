package com.embasic.escanner.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Real local JVM JUnit tests, no Android device or private fixtures required. */
class ScanContractTest {
    @Test fun supportedProtocolVersionIsOne() {
        assertTrue(ScanContract.isSupportedVersion(1))
    }

    @Test fun unsupportedProtocolVersionsFailClosed() {
        listOf(0, 2, -1, Int.MIN_VALUE, Int.MAX_VALUE).forEach {
            assertFalse(ScanContract.isSupportedVersion(it))
        }
    }

    @Test fun validPageOrdersIncludeZeroAndLargestInt() {
        assertTrue(ScanContract.isValidPageOrder(0))
        assertTrue(ScanContract.isValidPageOrder(1))
        assertTrue(ScanContract.isValidPageOrder(Int.MAX_VALUE))
    }

    @Test fun negativePageOrdersAreRejected() {
        assertFalse(ScanContract.isValidPageOrder(-1))
        assertFalse(ScanContract.isValidPageOrder(Int.MIN_VALUE))
    }

    @Test fun canonicalLowercaseSha256IsAccepted() {
        assertTrue(ScanContract.isCanonicalSha256Hex("0123456789abcdef".repeat(4)))
        assertTrue(ScanContract.isCanonicalSha256Hex("a".repeat(64)))
    }

    @Test fun malformedOrNonCanonicalHashesAreRejected() {
        listOf("", "a".repeat(63), "a".repeat(65), "A".repeat(64),
               "g".repeat(64), " ".repeat(64), "á".repeat(64),
               "\u0000".repeat(64)).forEach {
            assertFalse(ScanContract.isCanonicalSha256Hex(it))
        }
    }
}
