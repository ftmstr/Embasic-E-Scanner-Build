package com.embasic.escanner.android

import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Both platforms execute identical synthetic traces, never real pairing secrets. */
class ReceiveGateV1Test {
    private val session = "01234567-89ab-4cde-8f01-23456789abcd"
    private val page0 = "11234567-89ab-4cde-8f01-23456789abcd"
    private val page1 = "21234567-89ab-4cde-8f01-23456789abcd"
    private val token = "a".repeat(64) // synthetic ONLY
    private val tokenDigest = "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
    private val abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    private val body = "abc".toByteArray(Charsets.US_ASCII)

    private fun gate() = ReceiveGateV1.open(session, tokenDigest, 1000, 2000, 1024, 2)!!

    private fun wire(page: String, order: Int, sid: String = session, hash: String = abcHash) =
        ("{\"protocolVersion\":1,\"sessionId\":\"$sid\",\"pageId\":\"$page\"," +
         "\"order\":$order,\"byteSize\":3,\"mime\":\"image/jpeg\",\"sha256\":\"$hash\"}")
            .toByteArray(Charsets.US_ASCII)

    private fun fixture(): File {
        var path: File? = File(System.getProperty("user.dir"))
        repeat(8) {
            val f = File(path, "tests/golden/receive-gate-v1.tsv")
            if (f.isFile) return f
            path = path?.parentFile
        }
        error("Missing mandatory shared golden receive-gate-v1.tsv")
    }

    private fun action(g: ReceiveGateV1, name: String, now: Long): ReceiveGateV1.Decision {
        return when (name) {
            "AUTH_GOOD" -> g.authenticate(token, now)
            "AUTH_BAD" -> g.authenticate("b".repeat(64), now)
            "AUTH_UPPER" -> g.authenticate(token.uppercase(), now)
            "AUTH_EMPTY" -> g.authenticate("", now)
            "AUTH_NULL" -> g.authenticate(null, now)
            "STAGE0" -> g.propose(wire(page0, 0), body, now)
            "STAGE0_BAD_BYTES" -> g.propose(wire(page0, 0), "abd".toByteArray(Charsets.US_ASCII), now)
            "STAGE0_PARTIAL" -> g.propose(wire(page0, 0), "ab".toByteArray(Charsets.US_ASCII), now)
            "STAGE0_NULL" -> g.propose(wire(page0, 0), null, now)
            "STAGE0_BAD_HASH" -> g.propose(wire(page0, 0, hash = "0".repeat(64)), body, now)
            "STAGE0_WRONG_SESSION" -> g.propose(
                wire(page0, 0, sid = "31234567-89ab-4cde-8f01-23456789abcd"), body, now)
            "STAGE1" -> g.propose(wire(page1, 1), body, now)
            "STAGE1_DUPID" -> g.propose(wire(page0, 1), body, now)
            "STAGE2" -> g.propose(wire(page1, 2), body, now)
            "CONFIRM_GOOD" -> g.confirmReread(body, now)
            "CONFIRM_BAD" -> g.confirmReread("abd".toByteArray(Charsets.US_ASCII), now)
            "CONFIRM_NULL" -> g.confirmReread(null, now)
            "CLOSE" -> g.close()
            else -> error("Unknown golden action: $name")
        }
    }

    @Test fun sharedThirtyEightScenarioTraces() {
        val lines = fixture().readLines(Charsets.US_ASCII).filter {
            it.isNotBlank() && !it.startsWith("#")
        }
        assertEquals(38, lines.size)
        val seen = HashSet<String>()
        var totalSteps = 0
        for (line in lines) {
            val columns = line.split('\t')
            assertEquals("fixture columns", 5, columns.size)
            assertTrue("duplicate case: " + columns[0], seen.add(columns[0]))
            val commands = columns[1].split(',')
            val decisions = columns[2].split(',')
            assertEquals(columns[0], commands.size, decisions.size)
            val g = gate()
            commands.forEachIndexed { index, command ->
                val pair = command.split('@')
                assertEquals(columns[0], 2, pair.size)
                val actual = action(g, pair[0], pair[1].toLong())
                assertEquals(columns[0] + " step $index", decisions[index],
                    if (actual == ReceiveGateV1.Decision.ACCEPTED) "A" else "R")
                totalSteps++
            }
            assertEquals(columns[0] + " phase", columns[3], g.phase.name)
            assertEquals(columns[0] + " count", columns[4].toInt(), g.confirmedPages)
        }
        assertEquals(95, totalSteps)
    }

    @Test fun invalidTrustedInputsCannotCreateGate() {
        assertNull(ReceiveGateV1.open(null, tokenDigest, 1000, 2000, 1024, 2))
        assertNull(ReceiveGateV1.open(session.uppercase(), tokenDigest, 1000, 2000, 1024, 2))
        assertNull(ReceiveGateV1.open(session, null, 1000, 2000, 1024, 2))
        assertNull(ReceiveGateV1.open(session, tokenDigest.uppercase(), 1000, 2000, 1024, 2))
        assertNull(ReceiveGateV1.open(session, tokenDigest, -1, 2000, 1024, 2))
        assertNull(ReceiveGateV1.open(session, tokenDigest, 1000, 1000, 1024, 2))
        assertNull(ReceiveGateV1.open(session, tokenDigest, 1000, 301001, 1024, 2))
        assertNull(ReceiveGateV1.open(session, tokenDigest, 1000, 2000, 0, 2))
        assertNull(ReceiveGateV1.open(session, tokenDigest, 1000, 2000, 1024, 0))
        assertNull(ReceiveGateV1.open(session, tokenDigest, 1000, 2000, 1024, 1001))
        assertNotNull(gate())
    }

    @Test fun concurrentTokenCanBeConsumedOnlyOnce() {
        val g = gate()
        val executor = Executors.newFixedThreadPool(8)
        val ready = CountDownLatch(1)
        try {
            val futures = (1..24).map {
                executor.submit<ReceiveGateV1.Decision> {
                    ready.await()
                    g.authenticate(token, 1000)
                }
            }
            ready.countDown()
            assertEquals(1, futures.count {
                it.get(10, TimeUnit.SECONDS) == ReceiveGateV1.Decision.ACCEPTED
            })
            assertEquals(ReceiveGateV1.Phase.AUTHORIZED, g.phase)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test fun concurrentStagingAllowsOnePendingPage() {
        val g = gate()
        assertEquals(ReceiveGateV1.Decision.ACCEPTED, g.authenticate(token, 1000))
        val executor = Executors.newFixedThreadPool(8)
        val ready = CountDownLatch(1)
        try {
            val futures = (1..20).map {
                executor.submit<ReceiveGateV1.Decision> {
                    ready.await()
                    g.propose(wire(page0, 0), body, 1001)
                }
            }
            ready.countDown()
            assertEquals(1, futures.count {
                it.get(10, TimeUnit.SECONDS) == ReceiveGateV1.Decision.ACCEPTED
            })
            assertEquals(ReceiveGateV1.Decision.ACCEPTED, g.confirmReread(body, 1002))
            assertEquals(1, g.confirmedPages)
        } finally {
            executor.shutdownNow()
        }
    }
}
