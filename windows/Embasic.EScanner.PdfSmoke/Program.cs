using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Embasic.EScanner.Desktop;

static byte[] TinyPng()
{
    using var output = new MemoryStream();
    output.Write(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 });
    static uint Crc(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (var b in data)
        {
            crc ^= b;
            for (int k = 0; k < 8; k++)
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return ~crc;
    }
    void Chunk(string kind, byte[] data)
    {
        var label = Encoding.ASCII.GetBytes(kind);
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(len, data.Length);
        output.Write(len); output.Write(label); output.Write(data);
        var payload = new byte[checked(data.Length + 4)];
        label.CopyTo(payload, 0); data.CopyTo(payload, 4);
        Span<byte> tail = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(tail, Crc(payload));
        output.Write(tail);
    }
    var ihdr = new byte[13];
    BinaryPrimitives.WriteInt32BigEndian(ihdr.AsSpan(0, 4), 3);
    BinaryPrimitives.WriteInt32BigEndian(ihdr.AsSpan(4, 4), 2);
    ihdr[8] = 8; ihdr[9] = 2;
    Chunk("IHDR", ihdr);
    byte[] pixels =
    [
        0, 255,0,0, 0,255,0, 0,0,255,
        0, 255,255,0, 255,0,255, 0,255,255
    ];
    using var compressed = new MemoryStream();
    using (var zlib = new ZLibStream(compressed, CompressionLevel.Optimal, true))
        zlib.Write(pixels);
    Chunk("IDAT", compressed.ToArray());
    Chunk("IEND", Array.Empty<byte>());
    return output.ToArray();
}

string folder = Path.Combine(Path.GetTempPath(), "embasic-pdf-real-smoke-" +
    Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(folder);
try
{
    string a = Path.Combine(folder, "first.png");
    string b = Path.Combine(folder, "second.png");
    string pdf = Path.Combine(folder, "result.pdf");
    File.WriteAllBytes(a, TinyPng());
    File.WriteAllBytes(b, TinyPng());
    int pages = await RasterPdfWriter.ExportVerifiedAsync([a, b], pdf);
    if (pages != 2 || !File.Exists(pdf) || new FileInfo(pdf).Length < 350)
        throw new Exception("real PDF was not created");
    var bytes = File.ReadAllBytes(pdf);
    if (!bytes.AsSpan(0, 8).SequenceEqual(Encoding.ASCII.GetBytes("%PDF-1.4")) ||
        !Encoding.ASCII.GetString(bytes.AsSpan(Math.Max(0, bytes.Length - 100)))
            .Contains("%%EOF", StringComparison.Ordinal))
        throw new Exception("PDF header/trailer invalid");

    byte[] baseline = SHA256.HashData(bytes);
    string invalid = Path.Combine(folder, "bad.png");
    File.WriteAllText(invalid, "not a PNG", Encoding.ASCII);
    bool rejected = false;
    try
    {
        await RasterPdfWriter.ExportVerifiedAsync([a, invalid], pdf);
    }
    catch { rejected = true; }
    if (!rejected || !SHA256.HashData(File.ReadAllBytes(pdf)).AsSpan().SequenceEqual(baseline) ||
        Directory.EnumerateFiles(folder, ".embasic-*.tmp").Any())
        throw new Exception("failed PDF save replaced target or left temporary stage");

    Console.WriteLine("PASS: REAL Windows raster PDF produced and reopened pages=2 " +
        "pdfBytes=" + bytes.Length + " existingTargetPreservedOnError=true " +
        "stagingClean=true noOCR=true noSignedRuntimeSmoke=true");
    return 0;
}
catch (Exception e)
{
    Console.Error.WriteLine("FAIL: Windows raster PDF smoke: " + e);
    return 1;
}
finally
{
    Directory.Delete(folder, recursive: true);
}
