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
        assertEquals(37, lines.size)
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
        assertEquals(90, count)
    }

    @Test fun rejectsUntrustedDirectoriesAndOversizedPagePolicy() {
        val root = Files.createTempDirectory("escanner-private-")
        val file = root.resolve("not-a-directory")
        val link = root.resolve("symbolic-link")
        try {
            Files.write(file, "notdir".toByteArray(Charsets.US_ASCII))
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

    @Test fun orphanFolderFailsClosedBeforeAnyTokenGrant() {
        val root = Files.createTempDirectory("escanner-orphan-start-")
        val unknown = root.resolve("orphan.tmp")
        try {
            Files.write(unknown, "partial".toByteArray(Charsets.US_ASCII),
                StandardOpenOption.CREATE_NEW)
            val journal = open(root)
            assertFalse("existing orphan must block claim", journal.claimToken(token, 1001))
            assertEquals(DurableReceiveJournalV1.RecoveryStatus.POISONED,
                recover(root).status)
            // Same in-memory instance remains terminal even if an external actor
            // later deletes the orphan. No silent recovery or token grant.
            Files.delete(unknown)
            assertFalse(journal.claimToken(token, 1002))
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

    /** Single PUBLIC fixture shared with Windows NTFS tests. Missing cases fail. */
    private fun aliasGolden(id: String): List<String> {
        val rows = Files.readAllLines(
            fixture().parent.resolve("private-root-alias-v1.tsv"), Charsets.US_ASCII)
            .filter { it.isNotBlank() && !it.startsWith('#') }
            .map { it.split('\t') }
        require(rows.size == 2 && rows.all { it.size == 4 } &&
            rows.map { it[0] }.toSet() ==
                setOf("ancestor_symlink", "external_token_hardlink"))
        return rows.single { it[0] == id }
    }

    @Test fun ancestorSymlinkMustNotProvidePrivateRoot() {
        val parent = Files.createTempDirectory("escanner-ancestor-")
        try {
            val real = Files.createDirectory(parent.resolve("real"))
            val sessionDir = Files.createDirectory(real.resolve("session"))
            val alias = parent.resolve("alias")
            Files.createSymbolicLink(alias, real)
            assertNotNull("control must be usable", DurableReceiveJournalV1.open(
                sessionDir, session, digest, 1000, 2000, 1024, 2))
            val expected = aliasGolden("ancestor_symlink")
            val admitted = DurableReceiveJournalV1.open(alias.resolve("session"),
                session, digest, 1000, 2000, 1024, 2)
            assertEquals("symlink in PARENT cannot authenticate private root",
                expected[1], if (admitted == null) "REJECT" else "ACCEPT")
            assertEquals(expected[2], recover(alias.resolve("session")).status.name)
        } finally { deleteTree(parent) }
    }

    @Test fun externalHardlinkToConsumedTokenMustPoisonJournal() {
        val root = Files.createTempDirectory("escanner-hardlink-")
        val alias = Files.createTempFile(root.parent, "escanner-outside-", ".link")
        Files.delete(alias)
        try {
            val journal = open(root)
            assertTrue(journal.claimToken(token, 1001))
            Files.createLink(alias, root.resolve("token.claim"))
            val expected = aliasGolden("external_token_hardlink")
            assertEquals("token with external hardlink must be poisoned",
                expected[2], recover(root).status.name)
            assertEquals("prior claim alias forbids new page",
                expected[3], if (journal.commit(wire(page0, 0), body, 1002))
                    "ACCEPT" else "REJECT")
        } finally {
            Files.deleteIfExists(alias)
            deleteTree(root)
        }
    }

    @Test fun syntheticLedgerRehashProfile20And100Pages() {
        // This is a filesystem cost probe, NOT a latency SLA, Android-device QA
        // or full-resolution scan benchmark. Extra 500/1000 opt-in may take long.
        val sizes = if (System.getenv("EMBASIC_ESCANNER_PERF_EXTENDED") == "1")
            intArrayOf(20, 100, 500, 1000) else intArrayOf(20, 100)
        for (pages in sizes) {
            val root = Files.createTempDirectory("escanner-perf-")
            try {
                val journal = DurableReceiveJournalV1.open(root, session, digest,
                    1000, 2000, 1024, pages)!!
                assertTrue("perf claim $pages", journal.claimToken(token, 1001))
                val started = System.nanoTime()
                repeat(pages) { index ->
                    val id = (index + 1).toString(16).padStart(8, '0') +
                        "-89ab-4cde-8f01-23456789abcd"
                    assertTrue("perf page $index / $pages",
                        journal.commit(wire(id, index), body, 1001))
                }
                val elapsed = (System.nanoTime() - started) / 1_000_000L
                val recovery = DurableReceiveJournalV1.inspect(root, session, digest,
                    1000, 2000, 1024, pages)
                assertEquals(DurableReceiveJournalV1.RecoveryStatus.TOKEN_CONSUMED,
                    recovery.status)
                assertEquals(pages, recovery.confirmedPages)
                println("FOUNDATION_PERF_ANDROID_JVM pages=$pages elapsedMs=$elapsed " +
                    "syntheticBytesPerPage=3 noLatencySla=true")
            } finally { deleteTree(root) }
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
    @Test fun insecureWorldWritableRootMustNotBeAdmitted() {
        // Android/JVM owner-owned 0700 sandbox is the positive control. A
        // chmod-open directory must NEVER be trusted merely for its inode.
        val root = Files.createTempDirectory("escanner-private-mode-")
        try {
            val privateMode =
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")
            Files.setPosixFilePermissions(root, privateMode)
            assertNotNull("0700 owner-private control should open", open(root))
            // Deliberately invoke an INDEPENDENT chmod process on the host
            // Linux filesystem; not an Android device or a live race proof.
            val attacker = ProcessBuilder("chmod", "0777", root.toString()).start()
            assertTrue("external chmod timed out", attacker.waitFor(15,
                java.util.concurrent.TimeUnit.SECONDS))
            assertEquals("external chmod failed", 0, attacker.exitValue())
            assertNull("0777 admits an untrusted writer", DurableReceiveJournalV1.open(
                root, session, digest, 1000, 2000, 1024, 2))
            assertEquals(DurableReceiveJournalV1.RecoveryStatus.POISONED,
                recover(root).status)
        } finally {
            Files.setPosixFilePermissions(root,
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
            deleteTree(root)
        }
    }

}
