using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Embasic.EScanner.Contracts;

/// <summary>Real local Windows NTFS/temp-file tests; never a production TLS/QR/device claim.</summary>
internal static class DurableReceiveJournalSelfTest
{
    private const string Session = "01234567-89ab-4cde-8f01-23456789abcd";
    private const string Page0 = "11234567-89ab-4cde-8f01-23456789abcd";
    private const string Page1 = "21234567-89ab-4cde-8f01-23456789abcd";
    private const string Digest = "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb";
    private const string Hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    private static readonly byte[] Body = Encoding.ASCII.GetBytes("abc");
    private static readonly string Token = new('a', 64); // synthetic ONLY

    private static DurableReceiveJournalV1 Open(string dir) =>
        DurableReceiveJournalV1.Open(dir, Session, Digest, 1000, 2000, 1024, 2)
        ?? throw new InvalidOperationException("Valid synthetic policy rejected");

    private static bool CanOpen(string dir, long maxBytes = 1024, int maxPages = 2)
    {
        using var gate = DurableReceiveJournalV1.Open(dir, Session, Digest,
            1000, 2000, maxBytes, maxPages);
        return gate is not null;
    }

    private static bool AttemptConsumedReplay(string dir)
    {
        using var newJournal = Open(dir);
        return newJournal.ClaimToken(Token, 1002);
    }

    private static DurableReceiveJournalV1.Recovery Inspect(string dir) =>
        DurableReceiveJournalV1.Inspect(dir, Session, Digest, 1000, 2000, 1024, 2);

    private static byte[] Wire(string page, int order, string sid = Session, string sha = Hash) =>
        Encoding.ASCII.GetBytes($"{{\"protocolVersion\":1,\"sessionId\":\"{sid}\"," +
            $"\"pageId\":\"{page}\",\"order\":{order},\"byteSize\":3," +
            $"\"mime\":\"image/jpeg\",\"sha256\":\"{sha}\"}}");

    private static bool Create(string path)
    {
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        output.Write(Encoding.ASCII.GetBytes("orphan"));
        output.Flush(flushToDisk: true);
        return true;
    }
    private static bool Tamper(string path, string value)
    {
        File.WriteAllText(path, value, Encoding.ASCII);
        return true;
    }

    private static bool Action(string root, DurableReceiveJournalV1 gate, string action) =>
        action switch
        {
            "INSPECT_FRESH" => Inspect(root).Status == DurableReceiveJournalV1.RecoveryStatus.Fresh,
            "CLAIM_GOOD" => gate.ClaimToken(Token, 1001),
            "CLAIM_BAD" => gate.ClaimToken(new string('b', 64), 1001),
            "CLAIM_EXPIRED" => gate.ClaimToken(Token, 2000),
            "RESTART_CLAIM" => AttemptConsumedReplay(root),
            "COMMIT0" => gate.Commit(Wire(Page0, 0), Body, 1002),
            "COMMIT1" => gate.Commit(Wire(Page1, 1), Body, 1003),
            "COMMIT2" => gate.Commit(Wire(Page1, 2), Body, 1004),
            "COMMIT0_EXPIRED" => gate.Commit(Wire(Page0, 0), Body, 2000),
            "COMMIT0_BAD_BYTES" => gate.Commit(Wire(Page0, 0), Encoding.ASCII.GetBytes("abd"), 1002),
            "COMMIT0_PARTIAL" => gate.Commit(Wire(Page0, 0), Encoding.ASCII.GetBytes("ab"), 1002),
            "COMMIT0_BAD_HASH" => gate.Commit(Wire(Page0, 0, sha: new string('0', 64)), Body, 1002),
            "COMMIT0_FOREIGN" => gate.Commit(
                Wire(Page0, 0, sid: "31234567-89ab-4cde-8f01-23456789abcd"), Body, 1002),
            "COMMIT1_DUPID" => gate.Commit(Wire(Page0, 1), Body, 1003),
            "COMMIT1_BAD_BYTES" => gate.Commit(Wire(Page1, 1), Encoding.ASCII.GetBytes("abd"), 1003),
            "TAMPER_BLOB" => Tamper(Path.Combine(root, "page-0000.blob"), "abd"),
            "TAMPER_RECEIPT" => Tamper(Path.Combine(root, "page-0000.rec"), "torn"),
            "TAMPER_CLAIM" => Tamper(Path.Combine(root, "token.claim"), "torn"),
            "ORPHAN_TEMP" => Create(Path.Combine(root, "stage-0000.tmp")),
            "ORPHAN_BLOB" => Create(Path.Combine(root, "page-0000.blob")),
            "ORPHAN_RECEIPT" => Create(Path.Combine(root, "page-0000.rec")),
            "UNKNOWN_FILE" => Create(Path.Combine(root, "unknown.file")),
            "EXTRA_GAP" => Create(Path.Combine(root, "page-0003.rec")),
            _ => throw new InvalidOperationException("Unknown journal action: " + action)
        };

    private static string? GoldenPath()
    {
        var dir = Directory.GetCurrentDirectory();
        for (int i = 0; i < 8; i++)
        {
            var candidate = Path.Combine(dir, "tests", "golden", "durable-receipt-v1.tsv");
            if (File.Exists(candidate)) return candidate;
            var parent = Directory.GetParent(dir);
            if (parent is null) break;
            dir = parent.FullName;
        }
        return null;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW",
        CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLinkNative(string newName, string existingName,
        IntPtr securityAttributes);

    private static string[] AliasGoldenCase(string id)
    {
        var golden = GoldenPath() ?? throw new InvalidOperationException("Missing canonical trace fixture");
        var path = Path.Combine(Path.GetDirectoryName(golden)!,
            "private-root-alias-v1.tsv");
        var rows = File.ReadAllLines(path, Encoding.ASCII)
            .Where(x => !string.IsNullOrWhiteSpace(x) && !x.StartsWith('#'))
            .Select(x => x.Split('\t')).ToArray();
        if (rows.Length != 2 || rows.Any(x => x.Length != 4) ||
            rows.Select(x => x[0]).ToHashSet(StringComparer.Ordinal)
                .SetEquals(new[] { "ancestor_symlink", "external_token_hardlink" }) == false)
            throw new InvalidOperationException("Shared alias-root golden matrix is incomplete");
        return rows.Single(x => x[0] == id);
    }

    // Test fixture must actually satisfy the production owner/DACL contract:
    // inherited write grants on GitHub runner TEMP may be broader than app-private.
    private static DirectoryInfo CreatePrivateTempSubdirectory(string prefix) =>
        HardenTestDirectory(Directory.CreateTempSubdirectory(prefix));

    private static DirectoryInfo HardenTestDirectory(DirectoryInfo directory)
    {
        // Platform guard is required by CA1416 under TreatWarningsAsErrors.
        // The SelfTest is intentionally a Windows/NTFS-only physical fixture.
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Private NTFS ACL fixture needs Windows");
        var acl = directory.GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var rule in acl.GetAccessRules(true, false, typeof(SecurityIdentifier))
                     .OfType<FileSystemAccessRule>().ToArray())
            acl.RemoveAccessRuleSpecific(rule);
        var user = WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException("Windows current user SID unavailable");
        // A temporary directory can default to a creator-group OWNER SID
        // even after inherited ACEs are removed. Explicitly align its owner
        // with the test process, matching the real admission policy.
        acl.SetOwner(user);
        const InheritanceFlags inherit =
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        acl.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
            inherit, PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None,
            AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None,
            AccessControlType.Allow));
        directory.SetAccessControl(acl);
        return directory;
    }

    private static string[] PermissionGoldenCase(string id)
    {
        var golden = GoldenPath() ?? throw new InvalidOperationException("Missing durable fixture");
        var path = Path.Combine(Path.GetDirectoryName(golden)!,
            "private-root-permission-v1.tsv");
        var rows = File.ReadAllLines(path, Encoding.ASCII)
            .Where(x => !string.IsNullOrWhiteSpace(x) && !x.StartsWith('#'))
            .Select(x => x.Split('\t')).ToArray();
        if (rows.Length != 2 || rows.Any(x => x.Length != 3) ||
            !rows.Select(x => x[0]).ToHashSet(StringComparer.Ordinal)
                .SetEquals(new[] { "owner_private_0700", "world_writer_grant" }))
            throw new InvalidOperationException("Missing/duplicate private-root permission golden");
        return rows.Single(x => x[0] == id);
    }


    // The adversary is a REAL, separately launched OS process. Both blocked
    // and allowed outcomes are checked, avoiding false PASS from missing pwsh.
    private static bool HostileRenameFromSecondProcess(string from, string to)
    {
        static string Quote(string value) => value.Replace("'", "''", StringComparison.Ordinal);
        var psi = new System.Diagnostics.ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add("try { [System.IO.Directory]::Move('" +
            Quote(from) + "', '" + Quote(to) + "'); exit 0 } catch { exit 17 }");
        using var process = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("Missing adversarial subprocess");
        if (!process.WaitForExit(15000))
        {
            process.Kill(entireProcessTree: true);
            throw new InvalidOperationException("Hostile rename timeout, not a PASS");
        }
        return process.ExitCode == 0;
    }


    private static string[] KilledWriterGolden()
    {
        var canonical = GoldenPath() ?? throw new InvalidOperationException("Missing golden base");
        var path = Path.Combine(Path.GetDirectoryName(canonical)!, "crash-orphan-v1.tsv");
        var rows = File.ReadAllLines(path, Encoding.ASCII)
            .Where(x => !string.IsNullOrWhiteSpace(x) && !x.StartsWith('#'))
            .Select(x => x.Split('\t')).ToArray();
        if (rows.Length != 1 || rows[0].Length != 4 ||
            rows[0][0] != "killed_external_stage_writer")
            throw new InvalidOperationException("Missing/duplicate killed-writer fixture");
        return rows[0];
    }

    private static bool HostileWriterDiesAfterStage(string root)
    {
        var stage = Path.Combine(root, "stage-0000.tmp").Replace("'", "''",
            StringComparison.Ordinal);
        var psi = new System.Diagnostics.ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add("try { [System.IO.File]::WriteAllText('" + stage +
            "', 'partial'); [System.Diagnostics.Process]::GetCurrentProcess().Kill(); " +
            "exit 0 } catch { exit 19 }");
        using var child = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to spawn external writer");
        if (!child.WaitForExit(15000))
        {
            child.Kill(entireProcessTree: true);
            throw new InvalidOperationException("Killed-writer subprocess timed out");
        }
        return child.ExitCode != 0 && File.Exists(Path.Combine(root, "stage-0000.tmp"));
    }

    public static bool Run()
    {
        string? golden = GoldenPath();
        if (golden is null)
        {
            Console.Error.WriteLine("FAIL: missing exact cross-platform durable-receipt-v1.tsv");
            return false;
        }
        int scenarios = 0, actions = 0;
        var caseIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in File.ReadAllLines(golden, Encoding.ASCII))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
            var fields = line.Split('\t');
            if (fields.Length != 5 || !caseIds.Add(fields[0]))
            {
                Console.Error.WriteLine("FAIL: invalid/duplicate durable receipt fixture");
                return false;
            }
            string[] events = fields[1].Split(','), expectations = fields[2].Split(',');
            if (events.Length != expectations.Length) return false;
            string root = CreatePrivateTempSubdirectory("escanner-receipt-").FullName;
            try
            {
                using var gate = Open(root);
                for (int i = 0; i < events.Length; i++)
                {
                    bool pass = Action(root, gate, events[i]);
                    if ((pass ? "A" : "R") != expectations[i])
                    {
                        Console.Error.WriteLine("FAIL: " + fields[0] + " action " + events[i]);
                        return false;
                    }
                    actions++;
                }
                var summary = Inspect(root);
                string status = summary.Status switch
                {
                    DurableReceiveJournalV1.RecoveryStatus.Fresh => "FRESH",
                    DurableReceiveJournalV1.RecoveryStatus.TokenConsumed => "TOKEN_CONSUMED",
                    _ => "POISONED"
                };
                if (status != fields[3] ||
                    summary.ConfirmedPages.ToString(System.Globalization.CultureInfo.InvariantCulture) != fields[4])
                {
                    Console.Error.WriteLine("FAIL: recovery differs: " + fields[0] +
                        " expected " + fields[3] + "/" + fields[4] + " got " +
                        status + "/" + summary.ConfirmedPages);
                    return false;
                }
                scenarios++;
            }
            finally { Directory.Delete(root, recursive: true); }
        }
        if (scenarios != 37 || actions != 90)
        {
            Console.Error.WriteLine("FAIL: incomplete durable receipt golden scenarios");
            return false;
        }


        // Test-FIRST RED: prior Open() only sampled a directory file ID and
        // released its handle. An external same-user process could rename that
        // authenticated root and substitute a different path afterward.
        string pinnedRoot = CreatePrivateTempSubdirectory("escanner-pin-").FullName;
        string movedRoot = pinnedRoot + ".outside";
        try
        {
            var journal = Open(pinnedRoot);
            try
            {
                if (HostileRenameFromSecondProcess(pinnedRoot, movedRoot) ||
                    !Directory.Exists(pinnedRoot) || Directory.Exists(movedRoot))
                {
                    Console.Error.WriteLine(
                        "FAIL: hostile subprocess renamed OPEN Windows private root");
                    return false;
                }
            }
            finally
            {
                // Test compiles against the pre-fix implementation (RED)
                // while verifying that the GREEN implementation is IDisposable.
                ((object)journal as IDisposable)?.Dispose();
            }
            // A blocked subprocess alone is not evidence: prove that this
            // same hostile process CAN rename once our handle is released.
            if (!HostileRenameFromSecondProcess(pinnedRoot, movedRoot) ||
                Directory.Exists(pinnedRoot) || !Directory.Exists(movedRoot))
            {
                Console.Error.WriteLine(
                    "FAIL: positive-control adversary could not rename after release");
                return false;
            }
            Console.WriteLine(
                "PASS: pinned Windows directory denies separate-process rename until dispose");
        }
        finally
        {
            if (Directory.Exists(movedRoot) && !Directory.Exists(pinnedRoot))
                Directory.Move(movedRoot, pinnedRoot);
            if (Directory.Exists(pinnedRoot))
                Directory.Delete(pinnedRoot, recursive: true);
        }


        // RED: the root HANDLE alone does not authorize a path through an
        // ancestor that an independent writer can rename. A real same-user
        // process attempts the rename while the leaf journal is OPEN. The
        // same process MUST be able to rename after deterministic Dispose,
        // proving that a blocked attack is not an unavailable-process false PASS.
        string parentPinFixture = CreatePrivateTempSubdirectory("escanner-parent-pin-").FullName;
        string parentNode = Path.Combine(parentPinFixture, "parent");
        string movedParent = Path.Combine(parentPinFixture, "parent.moved");
        try
        {
            string nestedRoot = Path.Combine(parentNode, "session");
            HardenTestDirectory(Directory.CreateDirectory(nestedRoot));
            using (var active = Open(nestedRoot))
            {
                if (HostileRenameFromSecondProcess(parentNode, movedParent) ||
                    !Directory.Exists(nestedRoot) || Directory.Exists(movedParent))
                {
                    Console.Error.WriteLine(
                        "FAIL: hostile subprocess renamed ANCESTOR of an OPEN private root");
                    return false;
                }
                if (!active.ClaimToken(Token, 1001))
                {
                    Console.Error.WriteLine("FAIL: live pinned journal lost claimed token");
                    return false;
                }
            }
            if (!HostileRenameFromSecondProcess(parentNode, movedParent) ||
                Directory.Exists(parentNode) || !Directory.Exists(movedParent))
            {
                Console.Error.WriteLine("FAIL: ancestor rename positive control after Dispose");
                return false;
            }
            Console.WriteLine(
                "PASS: pinned Windows ancestor denies external rename until Dispose");
        }
        finally
        {
            if (Directory.Exists(movedParent) && !Directory.Exists(parentNode))
                Directory.Move(movedParent, parentNode);
            if (Directory.Exists(parentPinFixture))
                Directory.Delete(parentPinFixture, recursive: true);
        }

        // RED: a secure leaf below an attacker-writable ancestor is not a
        // private path. Run icacls in a SEPARATE Windows OS process to grant
        // Everyone write on the PARENT ONLY. The child is DACL-protected, so
        // leaf-only admission misses the ancestor poisoning.
        string unsafeParent = CreatePrivateTempSubdirectory("escanner-hostile-parent-").FullName;
        try
        {
            string protectedChild = Path.Combine(unsafeParent, "private-session");
            HardenTestDirectory(Directory.CreateDirectory(protectedChild));
            if (!CanOpen(protectedChild))
            {
                Console.Error.WriteLine("FAIL: private child positive control did not open");
                return false;
            }
            var hostileAcl = new System.Diagnostics.ProcessStartInfo("icacls.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            hostileAcl.ArgumentList.Add(unsafeParent);
            hostileAcl.ArgumentList.Add("/grant");
            hostileAcl.ArgumentList.Add("*S-1-1-0:(W)");
            using var hostileProcess = System.Diagnostics.Process.Start(hostileAcl);
            if (hostileProcess is null || !hostileProcess.WaitForExit(15000) ||
                hostileProcess.ExitCode != 0)
            {
                Console.Error.WriteLine("NOT VERIFIED: ancestor DACL hostile process unavailable");
                return false;
            }
            if (CanOpen(protectedChild) ||
                Inspect(protectedChild).Status != DurableReceiveJournalV1.RecoveryStatus.Poisoned)
            {
                Console.Error.WriteLine(
                    "FAIL: hostile ancestor NTFS DACL admitted secure child root");
                return false;
            }
            Console.WriteLine("PASS: separate-process hostile ancestor DACL rejected");
        }
        finally { Directory.Delete(unsafeParent, recursive: true); }

        // Same common golden row as Android JVM test. The attacking writer is
        // a real independent Windows process terminated after emitting an
        // orphan staging record. Not a low-disk/power-cut simulation.
        string killedRoot = CreatePrivateTempSubdirectory("escanner-kill-").FullName;
        try
        {
            using var journal = Open(killedRoot);
            if (!journal.ClaimToken(Token, 1001) ||
                !HostileWriterDiesAfterStage(killedRoot))
            {
                Console.Error.WriteLine("FAIL: real killed-writer fixture did not execute");
                return false;
            }
            var goldenKilled = KilledWriterGolden();
            var recovered = Inspect(killedRoot).Status.ToString().ToUpperInvariant();
            var next = journal.Commit(Wire(Page0, 0), Body, 1002)
                ? "ACCEPT" : "REJECT";
            var presence = File.Exists(Path.Combine(killedRoot, "stage-0000.tmp"))
                ? "PRESENT" : "ABSENT";
            if (recovered != goldenKilled[1] || next != goldenKilled[2] ||
                presence != goldenKilled[3] || AttemptConsumedReplay(killedRoot))
            {
                Console.Error.WriteLine("FAIL: killed external writer reopened poisoned journal");
                return false;
            }
            Console.WriteLine(
                "PASS: externally killed writer leaves orphan and poisons restart");
        }
        finally { Directory.Delete(killedRoot, recursive: true); }

        // Separate OS PROCESS mutates the DACL; the adapter must refuse an
        // attacker-writable NTFS directory even when its path/inode is stable.
        // This is an ACL admission fixture, NOT an exhaustive TOCTOU proof.
        string aclRoot = CreatePrivateTempSubdirectory("escanner-acl-").FullName;
        try
        {
            var secure = PermissionGoldenCase("owner_private_0700");
            bool secureOpen = CanOpen(aclRoot);
            if ((secureOpen ? "ACCEPT" : "REJECT") != secure[1] ||
                Inspect(aclRoot).Status.ToString().ToUpperInvariant() != secure[2])
            {
                Console.Error.WriteLine("FAIL: secure owner-only NTFS root rejected");
                return false;
            }
            var psi = new System.Diagnostics.ProcessStartInfo("icacls.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add(aclRoot);
            psi.ArgumentList.Add("/grant");
            psi.ArgumentList.Add("*S-1-1-0:(W)"); // World SID: write
            using var attacker = System.Diagnostics.Process.Start(psi);
            if (attacker is null || !attacker.WaitForExit(15000) || attacker.ExitCode != 0)
            {
                Console.Error.WriteLine("NOT VERIFIED: hostile icacls process failed");
                return false;
            }
            var hostile = PermissionGoldenCase("world_writer_grant");
            bool hostileOpen = CanOpen(aclRoot);
            if ((hostileOpen ? "ACCEPT" : "REJECT") != hostile[1] ||
                Inspect(aclRoot).Status.ToString().ToUpperInvariant() != hostile[2])
            {
                Console.Error.WriteLine("FAIL: world-writable NTFS DACL reached private root");
                return false;
            }
            Console.WriteLine("PASS: separate-process hostile NTFS DACL rejected");
        }
        finally { Directory.Delete(aclRoot, recursive: true); }

        string privateRoot = CreatePrivateTempSubdirectory("escanner-dir-").FullName;
        try
        {
            string badFile = Path.Combine(privateRoot, "file.txt");
            File.WriteAllText(badFile, "not a directory");
            if (CanOpen(badFile) ||
                CanOpen(Path.Combine(privateRoot, "missing")) ||
                CanOpen(privateRoot, DurableReceiveJournalV1.MaxStageBytes + 1))
            {
                Console.Error.WriteLine("FAIL: invalid durable receipt root or cap admitted");
                return false;
            }
            // A symlink/junction test may need Windows Developer Mode; if not allowed,
            // report NOT VERIFIED instead of claiming that physical attack was tested.
            string link = Path.Combine(privateRoot, "link");
            bool linkCreated = false;
            try
            {
                Directory.CreateSymbolicLink(link, privateRoot);
                linkCreated = true;
                if (CanOpen(link))
                {
                    Console.Error.WriteLine("FAIL: Windows reparse directory admitted");
                    return false;
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("NOT VERIFIED: Windows symlink creation requires privilege");
            }
            catch (IOException)
            {
                Console.WriteLine("NOT VERIFIED: Windows symlink creation unavailable");
            }
            finally { if (linkCreated) Directory.Delete(link); }
        }
        finally { Directory.Delete(privateRoot, recursive: true); }

        string orphanRoot = CreatePrivateTempSubdirectory("escanner-orphan-start-").FullName;
        try
        {
            string orphan = Path.Combine(orphanRoot, "orphan.tmp");
            File.WriteAllText(orphan, "partial", Encoding.ASCII);
            using var gate = Open(orphanRoot);
            if (gate.ClaimToken(Token, 1001) ||
                Inspect(orphanRoot).Status != DurableReceiveJournalV1.RecoveryStatus.Poisoned)
            {
                Console.Error.WriteLine("FAIL: pre-existing orphan unexpectedly granted token");
                return false;
            }
            File.Delete(orphan);
            if (gate.ClaimToken(Token, 1002))
            {
                Console.Error.WriteLine("FAIL: tampered folder revived previously denied token");
                return false;
            }
        }
        finally { Directory.Delete(orphanRoot, recursive: true); }

        string raceRoot = CreatePrivateTempSubdirectory("escanner-claim-race-").FullName;
        try
        {
            var gates = Enumerable.Range(0, 24).Select(_ => Open(raceRoot)).ToArray();
            try
            {
                int admitted = 0;
                System.Threading.Tasks.Parallel.ForEach(gates, gate =>
                {
                    if (gate.ClaimToken(Token, 1001))
                        System.Threading.Interlocked.Increment(ref admitted);
                });
                if (admitted != 1 ||
                    Inspect(raceRoot).Status != DurableReceiveJournalV1.RecoveryStatus.TokenConsumed ||
                    AttemptConsumedReplay(raceRoot))
                {
                    Console.Error.WriteLine("FAIL: durable CREATE_NEW token replay race");
                    return false;
                }
            }
            finally { foreach (var gate in gates) gate.Dispose(); }
        }
        finally { Directory.Delete(raceRoot, recursive: true); }

        // A symlink in an ANCESTOR is different from the existing root-link test.
        // Windows symlink privilege is runner-dependent; absent privilege means NOT VERIFIED.
        string ancestorParent = CreatePrivateTempSubdirectory("escanner-parent-").FullName;
        try
        {
            var real = Path.Combine(ancestorParent, "real");
            var sessionDir = Path.Combine(real, "session");
            HardenTestDirectory(Directory.CreateDirectory(sessionDir));
            var alias = Path.Combine(ancestorParent, "alias");
            bool made = false;
            try
            {
                Directory.CreateSymbolicLink(alias, real);
                made = true;
                var expected = AliasGoldenCase("ancestor_symlink");
                var actualOpen = CanOpen(Path.Combine(alias, "session"))
                    ? "ACCEPT" : "REJECT";
                var actualRecovery = Inspect(Path.Combine(alias, "session"))
                    .Status.ToString().ToUpperInvariant();
                if (!CanOpen(sessionDir) ||
                    actualOpen != expected[1] || actualRecovery != expected[2])
                {
                    Console.Error.WriteLine("FAIL: symlinked ancestor reached private root");
                    return false;
                }
                Console.WriteLine("PASS: Windows parent-directory symlink rejected");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("NOT VERIFIED: Windows parent symlink privilege unavailable");
            }
            catch (IOException)
            {
                Console.WriteLine("NOT VERIFIED: Windows parent symlink creation unavailable");
            }
            finally { if (made) Directory.Delete(alias); }
        }
        finally { Directory.Delete(ancestorParent, recursive: true); }

        // A token-claim with an outside hardlink is an unsafe alias even when
        // its bytes have not changed yet. Windows NTFS supports this without
        // elevated privilege; failed fixture creation is NOT a PASS.
        string hardlinkRoot = CreatePrivateTempSubdirectory("escanner-hardlink-").FullName;
        string hardlinkAlias = Path.Combine(Path.GetDirectoryName(hardlinkRoot)!,
            Path.GetRandomFileName() + ".hardlink");
        try
        {
            using var journal = Open(hardlinkRoot);
            if (!journal.ClaimToken(Token, 1001) ||
                !CreateHardLinkNative(hardlinkAlias, Path.Combine(hardlinkRoot, "token.claim"),
                    IntPtr.Zero))
            {
                Console.Error.WriteLine("FAIL: unable to prepare NTFS hardlink admission fixture");
                return false;
            }
            var expected = AliasGoldenCase("external_token_hardlink");
            var recovery = Inspect(hardlinkRoot).Status.ToString().ToUpperInvariant();
            var actualCommit = journal.Commit(Wire(Page0, 0), Body, 1002) ?
                "ACCEPT" : "REJECT";
            if (recovery != expected[2] || actualCommit != expected[3])
            {
                Console.Error.WriteLine("FAIL: external hardlink to token.claim admitted");
                return false;
            }
            Console.WriteLine("PASS: external hardlink marker rejected before further commit");
        }
        finally
        {
            if (File.Exists(hardlinkAlias)) File.Delete(hardlinkAlias);
            Directory.Delete(hardlinkRoot, recursive: true);
        }

        // Real NTFS/temp-file profiling, NOT a product latency target.
        // Extended 500/1000 rounds are opt-in to avoid excessive CI load.
        var sizes = Environment.GetEnvironmentVariable("EMBASIC_ESCANNER_PERF_EXTENDED") == "1"
            ? new[] { 20, 100, 500, 1000 }
            : new[] { 20, 100 };
        foreach (int pages in sizes)
        {
            string perfRoot = CreatePrivateTempSubdirectory("escanner-perf-").FullName;
            try
            {
                using var gate = DurableReceiveJournalV1.Open(perfRoot, Session, Digest,
                    1000, 2000, 1024, pages);
                if (gate is null || !gate.ClaimToken(Token, 1001))
                {
                    Console.Error.WriteLine("FAIL: synthetic perf session setup " + pages);
                    return false;
                }
                long started = System.Diagnostics.Stopwatch.GetTimestamp();
                for (int i = 0; i < pages; i++)
                {
                    string syntheticId = (i + 1).ToString("x8",
                        System.Globalization.CultureInfo.InvariantCulture) +
                        "-89ab-4cde-8f01-23456789abcd";
                    if (!gate.Commit(Wire(syntheticId, i), Body, 1001))
                    {
                        Console.Error.WriteLine("FAIL: synthetic perf page " + i + "/" + pages);
                        return false;
                    }
                }
                long milliseconds = (long)System.Diagnostics.Stopwatch
                    .GetElapsedTime(started).TotalMilliseconds;
                var recovery = DurableReceiveJournalV1.Inspect(perfRoot, Session,
                    Digest, 1000, 2000, 1024, pages);
                if (recovery.Status != DurableReceiveJournalV1.RecoveryStatus.TokenConsumed ||
                    recovery.ConfirmedPages != pages)
                {
                    Console.Error.WriteLine("FAIL: synthetic perf receipt accounting " + pages);
                    return false;
                }
                Console.WriteLine($"FOUNDATION_PERF_WINDOWS_NTFS pages={pages} " +
                    $"elapsedMs={milliseconds} syntheticBytesPerPage=3 noLatencySla=true");
            }
            finally { Directory.Delete(perfRoot, recursive: true); }
        }

        Console.WriteLine($"PASS: {scenarios} actual-file cross-platform durable receipt cases / " +
            $"{actions} decisions; private-root policy and 24-instance exclusive token race");
        return true;
    }
}
