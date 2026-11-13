using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Embasic.EScanner.Contracts;

// Independent opt-in Windows NTFS contract test. These are structurally
// valid 8-bit RGB PNG files with real 12MP dimensions and uncompressed zlib
// IDAT blocks. This does NOT invoke an ImageEngine, camera, OCR or PdfEngine.
internal static partial class DurableReceiveJournalSelfTest
{
    private static readonly uint[] PngCrcTable = CreatePngCrcTable();

    private static uint[] CreatePngCrcTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < table.Length; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[(int)i] = c;
        }
        return table;
    }

    private static uint UpdatePngCrc(uint crc, ReadOnlySpan<byte> span)
    {
        foreach (byte b in span)
            crc = PngCrcTable[(int)((crc ^ b) & 255)] ^ (crc >> 8);
        return crc;
    }

    private static void WritePngChunk(Stream target, string name, byte[] payload)
    {
        if (name.Length != 4) throw new ArgumentException("Invalid PNG chunk");
        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteInt32BigEndian(header[..4], payload.Length);
        Encoding.ASCII.GetBytes(name).CopyTo(header[4..]);
        target.Write(header);
        target.Write(payload);
        uint crc = ~UpdatePngCrc(UpdatePngCrc(0xFFFFFFFFu, header[4..]), payload);
        Span<byte> trailer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(trailer, crc);
        target.Write(trailer);
    }

    private static byte[] GenerateSyntheticRgbPng(int width, int height, int seed)
    {
        if (width < 1 || height < 1) throw new ArgumentOutOfRangeException();
        using var png = new MemoryStream();
        png.Write(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 });
        byte[] ihdr = new byte[13];
        BinaryPrimitives.WriteInt32BigEndian(ihdr.AsSpan(0, 4), width);
        BinaryPrimitives.WriteInt32BigEndian(ihdr.AsSpan(4, 4), height);
        ihdr[8] = 8; // bit depth
        ihdr[9] = 2; // RGB truecolor, not indexed, no alpha
        WritePngChunk(png, "IHDR", ihdr);
        using var compressed = new MemoryStream();
        using (var zlib = new ZLibStream(compressed, CompressionLevel.NoCompression, true))
        {
            var row = new byte[checked(1 + 3 * width)];
            var random = new Random(seed); // synthetic pixels, NEVER a security nonce
            for (int y = 0; y < height; y++)
            {
                row[0] = 0; // PNG scanline filter: None
                random.NextBytes(row.AsSpan(1));
                zlib.Write(row);
            }
        }
        WritePngChunk(png, "IDAT", compressed.ToArray());
        WritePngChunk(png, "IEND", Array.Empty<byte>());
        return png.ToArray();
    }

    // Independent structural verification: CRC over each encoded chunk and
    // a real ZLibStream DECOMPRESSION of IDAT. No image processing is claimed.
    private static bool CheckSyntheticPng(byte[] png, int width, int height)
    {
        ReadOnlySpan<byte> signature = new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 };
        if (png.Length < 57 || !png.AsSpan(0, 8).SequenceEqual(signature)) return false;
        int pos = 8, chunks = 0;
        long uncompressed = -1;
        while (pos <= png.Length - 12)
        {
            int len = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(pos, 4));
            if (len < 0 || len > png.Length - pos - 12) return false;
            var name = png.AsSpan(pos + 4, 4);
            var data = png.AsSpan(pos + 8, len);
            uint claimed = BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(pos + 8 + len, 4));
            uint actual = ~UpdatePngCrc(UpdatePngCrc(0xFFFFFFFFu, name), data);
            if (claimed != actual) return false;
            if (chunks == 0)
            {
                if (!name.SequenceEqual("IHDR"u8) || len != 13 ||
                    BinaryPrimitives.ReadInt32BigEndian(data[..4]) != width ||
                    BinaryPrimitives.ReadInt32BigEndian(data.Slice(4, 4)) != height ||
                    data[8] != 8 || data[9] != 2 ||
                    data[10] != 0 || data[11] != 0 || data[12] != 0)
                    return false;
            }
            else if (chunks == 1)
            {
                if (!name.SequenceEqual("IDAT"u8)) return false;
                using var compressed = new MemoryStream(png, pos + 8, len, false);
                using var zlib = new ZLibStream(compressed, CompressionMode.Decompress);
                var buffer = new byte[65536];
                uncompressed = 0;
                int n;
                while ((n = zlib.Read(buffer)) != 0)
                    uncompressed += n;
            }
            else if (chunks == 2)
            {
                if (!name.SequenceEqual("IEND"u8) || len != 0) return false;
            }
            else return false;
            pos = checked(pos + 12 + len);
            chunks++;
        }
        return chunks == 3 && pos == png.Length &&
            uncompressed == (long)height * (1L + 3L * width);
    }

    private static byte[] PngWire(string pageId, int order, byte[] png)
    {
        var sha = Convert.ToHexString(SHA256.HashData(png)).ToLowerInvariant();
        string json = $"{{\"protocolVersion\":1,\"sessionId\":\"{Session}\"," +
            $"\"pageId\":\"{pageId}\",\"order\":{order},\"byteSize\":{png.Length}," +
            $"\"mime\":\"image/png\",\"sha256\":\"{sha}\"}}";
        return Encoding.ASCII.GetBytes(json);
    }

    internal static int RunHighResolutionPngJournalTest()
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("NOT VERIFIED: 12MP PNG NTFS test requires real Windows");
            return 2;
        }
        const int w = 3264, h = 2448; // 7,990,272 pixels, ~24MB PNG
        // A 12MP claim requires at least twelve million actual RGB pixels.
        // The old 3264x2448 fixture was 7.99MP despite its mistaken label.
        if ((long)w * h < 12_000_000)
        {
            Console.Error.WriteLine("FAIL: PNG fixture incorrectly labeled 12MP: " +
                ((long)w * h).ToString(System.Globalization.CultureInfo.InvariantCulture) +
                " pixels");
            return 1;
        }
        const int maxPages = 2;
        const long cap = DurableReceiveJournalV1.MaxStageBytes;
        string root = CreatePrivateTempSubdirectory("escanner-png-12mp-").FullName;
        string overRoot = CreatePrivateTempSubdirectory("escanner-png-overcap-").FullName;
        try
        {
            byte[] png = GenerateSyntheticRgbPng(w, h, 20261113);
            if (png.Length < 20 * 1024 * 1024 || png.Length >= cap ||
                !CheckSyntheticPng(png, w, h))
            {
                Console.Error.WriteLine("NOT VERIFIED: generated 12MP RGB PNG is invalid or unbounded");
                return 1;
            }
            using var current = System.Diagnostics.Process.GetCurrentProcess();
            current.Refresh();
            int baseline = current.HandleCount;
            long elapsedMs;
            int live;
            int exactPins;
            using (var journal = DurableReceiveJournalV1.Open(root, Session, Digest,
                       1000, 2000, cap, maxPages))
            {
                if (journal is null || !journal.ClaimToken(Token, 1001))
                {
                    Console.Error.WriteLine("FAIL: 12MP PNG journal token positive control");
                    return 1;
                }
                long start = System.Diagnostics.Stopwatch.GetTimestamp();
                if (!journal.Commit(PngWire(Page0, 0, png), png, 1002) ||
                    !journal.Commit(PngWire(Page1, 1, png), png, 1003))
                {
                    Console.Error.WriteLine("FAIL: 12MP PNG root-relative staged receipt commit " +
                        journal.LastNativeFailureStage);
                    return 1;
                }
                elapsedMs = (long)System.Diagnostics.Stopwatch
                    .GetElapsedTime(start).TotalMilliseconds;
                foreach (string leaf in new[] { "page-0000.blob", "page-0001.blob" })
                    if (!File.ReadAllBytes(Path.Combine(root, leaf)).AsSpan().SequenceEqual(png))
                    {
                        Console.Error.WriteLine("FAIL: full-size PNG staged byte mismatch " + leaf);
                        return 1;
                    }
                var inspected = DurableReceiveJournalV1.Inspect(root, Session, Digest,
                    1000, 2000, cap, maxPages);
                if (inspected.Status != DurableReceiveJournalV1.RecoveryStatus.TokenConsumed ||
                    inspected.ConfirmedPages != maxPages)
                {
                    Console.Error.WriteLine("FAIL: 12MP PNG live receipt recovery");
                    return 1;
                }
                current.Refresh();
                live = current.HandleCount;
                exactPins = journal.LivePinnedAssetHandleCount;
                if (exactPins != 2 * maxPages ||
                    live - baseline > 2 * maxPages + 128)
                {
                    Console.Error.WriteLine("FAIL: 12MP PNG live handle budget");
                    return 1;
                }
            }
            current.Refresh();
            int disposed = current.HandleCount;
            if (Math.Abs(disposed - baseline) > 64)
            {
                Console.Error.WriteLine("FAIL: 12MP PNG handle leak after Dispose");
                return 1;
            }
            var recovery = DurableReceiveJournalV1.Inspect(root, Session, Digest,
                1000, 2000, cap, maxPages);
            using var replay = DurableReceiveJournalV1.Open(root, Session, Digest,
                1000, 2000, cap, maxPages);
            if (recovery.Status != DurableReceiveJournalV1.RecoveryStatus.TokenConsumed ||
                recovery.ConfirmedPages != maxPages ||
                replay is null || replay.ClaimToken(Token, 1004))
            {
                Console.Error.WriteLine("FAIL: 12MP PNG read-only restart or token replay");
                return 1;
            }
            replay.Dispose();
            // Real on-disk corruption AFTER owner disposal must fail closed.
            using (var writer = new FileStream(Path.Combine(root, "page-0000.blob"),
                       FileMode.Open, FileAccess.Write, FileShare.None))
            {
                writer.WriteByte(0);
                writer.Flush(flushToDisk: true);
            }
            if (DurableReceiveJournalV1.Inspect(root, Session, Digest,
                    1000, 2000, cap, maxPages).Status !=
                DurableReceiveJournalV1.RecoveryStatus.Poisoned)
            {
                Console.Error.WriteLine("FAIL: 12MP PNG offline corruption admitted");
                return 1;
            }
            Console.WriteLine("PASS: REAL NTFS 12MP valid RGB PNG pages=2 " +
                $"dimensions={w}x{h} pngBytesPerPage={png.Length} " +
                $"elapsedMs={elapsedMs} baselineHandles={baseline} liveHandles={live} " +
                $"exactNativeReadPins={exactPins} afterDisposeHandles={disposed} restartPages=2 replayDenied=true " +
                "offlineTamperPoisoned=true noLatencySla=true");

            // Another real valid PNG larger than the strict 32MiB wire policy:
            // pre-admission rejection must not create ANY stage/blob/receipt.
            byte[] oversized = GenerateSyntheticRgbPng(4096, 3072, 20261114);
            if (oversized.LongLength <= cap ||
                !CheckSyntheticPng(oversized, 4096, 3072))
            {
                Console.Error.WriteLine("NOT VERIFIED: over-limit RGB PNG control invalid");
                return 1;
            }
            using var bounded = DurableReceiveJournalV1.Open(overRoot, Session,
                Digest, 1000, 2000, cap, 1);
            if (bounded is null || !bounded.ClaimToken(Token, 1001) ||
                bounded.Commit(PngWire(Page0, 0, oversized), oversized, 1002) ||
                Directory.EnumerateFileSystemEntries(overRoot).Count() != 1 ||
                !bounded.Commit(PngWire(Page0, 0, png), png, 1003))
            {
                Console.Error.WriteLine("FAIL: over-limit PNG admitted or damaged bounded journal");
                return 1;
            }
            Console.WriteLine("PASS: REAL NTFS over-limit PNG dimensions=4096x3072 " +
                $"bytes={oversized.Length} hardCapBytes={cap} " +
                "rejectedBeforeStaging=true validRetryAccepted=true noLatencySla=true");
            return 0;
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
            if (Directory.Exists(overRoot)) Directory.Delete(overRoot, recursive: true);
        }
    }
}
