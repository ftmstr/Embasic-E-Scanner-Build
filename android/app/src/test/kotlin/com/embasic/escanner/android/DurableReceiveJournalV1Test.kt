package com.embasic.escanner.android

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.Comparator
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Actual sandbox file I/O, but NOT signed APK/device, NTFS or guaranteed power-cut. */
class DurableReceiveJournalV1Test {
    private val session = "01234567-89ab-4cde-8f01-23456789abcd"
    private val page0 = "11234567-89ab-4cde-8f01-23456789abcd"
    private val page1 = "21234567-89ab-4cde-8f01-23456789abcd"
    private val token = "a".repeat(64) // fixed synthetic, never production secret
    private val digest = "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
    private val hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    private val body = "abc".toByteArray(Charsets.US_ASCII)

    private fun open(root: Path) =
        DurableReceiveJournalV1.open(root, session, digest, 1000, 2000, 1024, 2)!!

    private fun recover(root: Path) =
        DurableReceiveJournalV1.inspect(root, session, digest, 1000, 2000, 1024, 2)

    private fun wire(page: String, order: Int, sid: String = session, sha: String = hash) =
        ("{\"protocolVersion\":1,\"sessionId\":\"$sid\",\"pageId\":\"$page\"," +
         "\"order\":$order,\"byteSize\":3,\"mime\":\"image/jpeg\",\"sha256\":\"$sha\"}")
            .toByteArray(Charsets.US_ASCII)

    private fun fixture(): Path {
        var cwd: Path? = Path.of(System.getProperty("user.dir"))
        repeat(8) {
            val candidate = cwd!!.resolve("tests/golden/durable-receipt-v1.tsv")
            if (Files.isRegularFile(candidate)) return candidate
            cwd = cwd?.parent
        }
        error("Shared durable-receipt-v1.tsv is mandatory")
    }

    private fun execute(root: Path, g: DurableReceiveJournalV1, action: String): Boolean =
        when (action) {
            "INSPECT_FRESH" -> recover(root).status == DurableReceiveJournalV1.RecoveryStatus.FRESH
            "CLAIM_GOOD" -> g.claimToken(token, 1001)
            "CLAIM_BAD" -> g.claimToken("b".repeat(64), 1001)
            "CLAIM_EXPIRED" -> g.claimToken(token, 2000)
            "RESTART_CLAIM" -> open(root).claimToken(token, 1002)
            "COMMIT0" -> g.commit(wire(page0, 0), body, 1002)
            "COMMIT1" -> g.commit(wire(page1, 1), body, 1003)
            "COMMIT2" -> g.commit(wire(page1, 2), body, 1004)
            "COMMIT0_EXPIRED" -> g.commit(wire(page0, 0), body, 2000)
            "COMMIT0_BAD_BYTES" -> g.commit(wire(page0, 0), "abd".toByteArray(Charsets.US_ASCII), 1002)
            "COMMIT0_PARTIAL" -> g.commit(wire(page0, 0), "ab".toByteArray(Charsets.US_ASCII), 1002)
            "COMMIT0_BAD_HASH" -> g.commit(wire(page0, 0, sha = "0".repeat(64)), body, 1002)
            "COMMIT0_FOREIGN" -> g.commit(wire(page0, 0,
                sid = "31234567-89ab-4cde-8f01-23456789abcd"), body, 1002)
            "COMMIT1_DUPID" -> g.commit(wire(page0, 1), body, 1003)
            "COMMIT1_BAD_BYTES" -> g.commit(wire(page1, 1), "abd".toByteArray(Charsets.US_ASCII), 1003)
            "TAMPER_BLOB" -> mutate(root.resolve("page-0000.blob"), "abd")
            "TAMPER_RECEIPT" -> mutate(root.resolve("page-0000.rec"), "torn")
            "TAMPER_CLAIM" -> mutate(root.resolve("token.claim"), "torn")
            "ORPHAN_TEMP" -> create(root.resolve("stage-0000.tmp"))
            "ORPHAN_BLOB" -> create(root.resolve("page-0000.blob"))
            "ORPHAN_RECEIPT" -> create(root.resolve("page-0000.rec"))
            "UNKNOWN_FILE" -> create(root.resolve("unknown.file"))
            "EXTRA_GAP" -> create(root.resolve("page-0003.rec"))
            else -> error("Unknown trace action: $action")
        }

    private fun mutate(path: Path, data: String): Boolean {
        Files.write(path, data.toByteArray(Charsets.US_ASCII), StandardOpenOption.TRUNCATE_EXISTING)
        return true
    }

    private fun create(path: Path): Boolean {
        Files.write(path, "orphan".toByteArray(Charsets.US_ASCII), StandardOpenOption.CREATE_NEW)
        return true
    }

    @Test fun sharedThirtyActualDiskRecoveryTraces() {
        val lines = Files.readAllLines(fixture(), Charsets.US_ASCII)
            .filter { it.isNotBlank() && !it.startsWith('#') }
        assertEquals(30, lines.size)
        val names = HashSet<String>()
        var count = 0
        for (line in lines) {
            val cells = line.split('\t')
            assertEquals(5, cells.size)
            assertTrue("duplicate scenario " + cells[0], names.add(cells[0]))
            val actions = cells[1].split(',')
            val expected = cells[2].split(',')
            assertEquals(cells[0], actions.size, expected.size)
            val root = Files.createTempDirectory("escanner-journal-")
            try {
                val journal = open(root)
                actions.forEachIndexed { idx, action ->
                    assertEquals(cells[0] + " action " + action,
                        expected[idx], if (execute(root, journal, action)) "A" else "R")
                    count++
                }
                val observed = recover(root)
                assertEquals(cells[0] + " recovery", cells[3], observed.status.name)
                assertEquals(cells[0] + " committed pages", cells[4].toInt(), observed.confirmedPages)
            } finally { deleteTree(root) }
        }
        assertEquals(64, count)
    }

    @Test fun rejectsUntrustedDirectoriesAndOversizedPagePolicy() {
        val root = Files.createTempDirectory("escanner-private-")
        val file = root.resolve("not-a-directory")
        val link = root.resolve("symbolic-link")
        try {
            Files.writeString(file, "notdir")
            Files.createSymbolicLink(link, root)
            assertNull(DurableReceiveJournalV1.open(file, session, digest, 1000, 2000, 1024, 2))
            assertNull(DurableReceiveJournalV1.open(link, session, digest, 1000, 2000, 1024, 2))
            assertNull(DurableReceiveJournalV1.open(root.resolve("missing"), session,
                digest, 1000, 2000, 1024, 2))
            assertNull(DurableReceiveJournalV1.open(root, session, digest,
                1000, 2000, DurableReceiveJournalV1.MAX_STAGE_BYTES.toLong() + 1, 2))
            assertNotNull(open(root))
        } finally { deleteTree(root) }
    }

    @Test fun exclusiveTokenCreateNewHasSingleWinnerAcrossInstances() {
        val root = Files.createTempDirectory("escanner-race-")
        val pool = Executors.newFixedThreadPool(8)
        try {
            val gates = (1..24).map { open(root) }
            val latch = CountDownLatch(1)
            val futures = gates.map { g ->
                pool.submit<Boolean> { latch.await(); g.claimToken(token, 1001) }
            }
            latch.countDown()
            assertEquals(1, futures.count { it.get(15, TimeUnit.SECONDS) })
            assertEquals(DurableReceiveJournalV1.RecoveryStatus.TOKEN_CONSUMED,
                recover(root).status)
            assertFalse(open(root).claimToken(token, 1002))
        } finally {
            pool.shutdownNow()
            deleteTree(root)
        }
    }

    private fun deleteTree(root: Path) {
        if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            Files.walk(root).use { walk ->
                walk.sorted(Comparator.reverseOrder<Path>()).forEach {
                    Files.deleteIfExists(it)
                }
            }
        }
    }
}
