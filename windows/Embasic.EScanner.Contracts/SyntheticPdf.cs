using System.Globalization;
using System.Text;

namespace Embasic.EScanner.Contracts;

/// <summary>Deterministic, synthetic-only single-page PDF fixture; NOT a production export engine.</summary>
public static class SyntheticPdf
{
    public static byte[] Create()
    {
        const string text = "EMBASIC SYNTHETIC TEST";
        var stream = "BT /F1 18 Tf 48 140 Td (" + text + ") Tj ET\n";
        var streamBytes = Encoding.ASCII.GetBytes(stream);
        string[] objects =
        [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            "<< /Length " + streamBytes.Length.ToString(CultureInfo.InvariantCulture) + " >>\nstream\n" + stream + "endstream"
        ];
        using var output = new MemoryStream();
        void Write(string s) => output.Write(Encoding.ASCII.GetBytes(s));
        Write("%PDF-1.4\n");
        var offsets = new List<long> { 0 };
        for (var i = 0; i < objects.Length; i++)
        {
            offsets.Add(output.Position);
            Write((i + 1).ToString(CultureInfo.InvariantCulture) + " 0 obj\n" + objects[i] + "\nendobj\n");
        }
        var xref = output.Position;
        Write("xref\n0 6\n0000000000 65535 f \n");
        for (var i = 1; i < offsets.Count; i++)
            Write(offsets[i].ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \n");
        Write("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n" +
              xref.ToString(CultureInfo.InvariantCulture) + "\n%%EOF\n");
        return output.ToArray();
    }

    public static bool VerifyFixture(byte[]? bytes)
    {
        if (bytes is null || bytes.Length < 100) return false;
        var s = Encoding.ASCII.GetString(bytes);
        if (!s.StartsWith("%PDF-1.4\n", StringComparison.Ordinal) ||
            !s.EndsWith("%%EOF\n", StringComparison.Ordinal)) return false;
        var marker = s.LastIndexOf("startxref\n", StringComparison.Ordinal);
        if (marker < 0) return false;
        var end = s.IndexOf('\n', marker + 10);
        if (end < 0 ||
            !long.TryParse(s.AsSpan(marker + 10, end - marker - 10),
                NumberStyles.None, CultureInfo.InvariantCulture, out var offset) ||
            offset < 0 || offset >= bytes.Length ||
            !s.AsSpan((int)offset).StartsWith("xref\n", StringComparison.Ordinal)) return false;
        var offsets = new List<int>();
        foreach (var line in s.Substring((int)offset).Split('\n').Skip(2).Take(6).Skip(1))
        {
            if (line.Length < 17 || !int.TryParse(line.AsSpan(0, 10), NumberStyles.None,
                CultureInfo.InvariantCulture, out var value) || value < 0 || value >= offset)
                return false;
            offsets.Add(value);
        }
        if (offsets.Count != 5) return false;
        for (var i = 0; i < 5; i++)
            if (!s.AsSpan(offsets[i]).StartsWith((i + 1).ToString(CultureInfo.InvariantCulture) + " 0 obj\n",
                StringComparison.Ordinal)) return false;
        return s.Contains("/Count 1", StringComparison.Ordinal) &&
               s.Contains("/MediaBox [0 0 300 200]", StringComparison.Ordinal) &&
               s.Contains("EMBASIC SYNTHETIC TEST", StringComparison.Ordinal);
    }
}
