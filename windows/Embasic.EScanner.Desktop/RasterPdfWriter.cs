using System.Globalization;
using System.IO.Compression;
using System.Text;
using Windows.Graphics.Imaging;
using Windows.Storage;
using Windows.Data.Pdf;

namespace Embasic.EScanner.Desktop;

/// <summary>
/// First real offline raster PDF writer using the platform PNG/JPEG decoder.
/// Produces a validated staged PDF before same-directory atomic replace.
/// It is NOT a full PdfEngine (no OCR, text layer, ICC profile, annotations
/// or signed release), and its runtime/visual QA is still NOT VERIFIED.
/// </summary>
internal static class RasterPdfWriter
{
    private const long MaxPdfBytes = 512L * 1024L * 1024L;
    private const long MaxImagePixels = 24_000_000;
    private static readonly CultureInfo Invariant = CultureInfo.InvariantCulture;

    internal static async Task<int> ExportVerifiedAsync(
        IReadOnlyList<string> immutableImagePaths, string destination)
    {
        if (immutableImagePaths.Count is < 1 or > 100)
            throw new InvalidDataException("PDF sayfa sayısı sınırı");
        if (string.IsNullOrWhiteSpace(destination) ||
            !string.Equals(Path.GetExtension(destination), ".pdf", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("PDF hedefi geçersiz");

        // Stage in the TARGET directory, not cache on another drive:
        // replacement is a same-volume File.Move without a copy fallback.
        string directory = Path.GetDirectoryName(Path.GetFullPath(destination))
            ?? throw new InvalidDataException("Hedef klasör yok");
        string staging = Path.Combine(directory, ".embasic-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await WriteRasterPdfAsync(immutableImagePaths, staging);
            var tempFile = await StorageFile.GetFileFromPathAsync(staging);
            // Open and close the native validation STREAM before atomic move,
            // so this process does not hold a sharing lock on the staged PDF.
            using (var readStream = await tempFile.OpenReadAsync())
            {
                var reopened = await PdfDocument.LoadFromStreamAsync(readStream);
                if (reopened.PageCount != immutableImagePaths.Count)
                    throw new InvalidDataException("PDF sayfa sayısı uyuşmuyor");
            }
            // Same-directory atomic replacement; never copy an unvalidated PDF.
            File.Move(staging, destination, overwrite: true);
            return immutableImagePaths.Count;
        }
        finally { if (File.Exists(staging)) File.Delete(staging); }
    }

    private static async Task WriteRasterPdfAsync(
        IReadOnlyList<string> images, string stagedPath)
    {
        await using var output = new FileStream(stagedPath, FileMode.CreateNew,
            FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough);
        var offsets = new List<long> { 0 };

        void W(string ascii)
        {
            var bytes = Encoding.ASCII.GetBytes(ascii);
            output.Write(bytes);
        }
        void Begin(int index)
        {
            if (index != offsets.Count)
                throw new InvalidDataException("PDF nesne sırası");
            offsets.Add(output.Position);
            W(index.ToString(Invariant) + " 0 obj\n");
        }
        void End() => W("endobj\n");

        W("%PDF-1.4\n");
        Begin(1);
        W("<< /Type /Catalog /Pages 2 0 R >>\n"); End();

        Begin(2);
        W("<< /Type /Pages /Kids [ ");
        for (int i = 0; i < images.Count; i++)
            W((3 + i * 3).ToString(Invariant) + " 0 R ");
        W("] /Count " + images.Count.ToString(Invariant) + " >>\n");
        End();

        for (int i = 0; i < images.Count; i++)
        {
            (byte[] rgb, uint width, uint height) = await DecodeRgbAsync(images[i]);
            byte[] compressed;
            using (var buffer = new MemoryStream())
            {
                using (var zlib = new ZLibStream(buffer, CompressionLevel.Fastest, leaveOpen: true))
                    zlib.Write(rgb);
                compressed = buffer.ToArray();
            }

            int pageId = 3 + 3 * i, contentId = pageId + 1, imageId = pageId + 2;
            Begin(pageId);
            W("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] " +
              "/Resources << /XObject << /Im0 " + imageId + " 0 R >> >> " +
              "/Contents " + contentId + " 0 R >>\n"); End();

            // Fit the raster to A4 without stretching, preserve all edges.
            double scale = Math.Min(555.0 / width, 802.0 / height);
            string drawW = (width * scale).ToString("0.###", Invariant);
            string drawH = (height * scale).ToString("0.###", Invariant);
            string offsetX = ((595 - width * scale) / 2).ToString("0.###", Invariant);
            string offsetY = ((842 - height * scale) / 2).ToString("0.###", Invariant);
            byte[] commands = Encoding.ASCII.GetBytes(
                "q " + drawW + " 0 0 " + drawH + " " + offsetX + " " + offsetY +
                " cm /Im0 Do Q\n");
            Begin(contentId);
            W("<< /Length " + commands.Length.ToString(Invariant) + " >>\nstream\n");
            output.Write(commands);
            W("endstream\n"); End();

            Begin(imageId);
            W("<< /Type /XObject /Subtype /Image /Width " + width.ToString(Invariant) +
              " /Height " + height.ToString(Invariant) +
              " /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode" +
              " /Length " + compressed.Length.ToString(Invariant) + " >>\nstream\n");
            output.Write(compressed);
            W("\nendstream\n"); End();
            if (output.Length > MaxPdfBytes)
                throw new InvalidDataException("512MiB PDF boyut sınırı");
        }

        long xref = output.Position;
        W("xref\n0 " + offsets.Count.ToString(Invariant) +
          "\n0000000000 65535 f \n");
        for (int i = 1; i < offsets.Count; i++)
            W(offsets[i].ToString("D10", Invariant) + " 00000 n \n");
        W("trailer\n<< /Root 1 0 R /Size " + offsets.Count.ToString(Invariant) +
          " >>\nstartxref\n" + xref.ToString(Invariant) + "\n%%EOF\n");
        output.Flush(flushToDisk: true);
    }

    private static async Task<(byte[] Rgb, uint Width, uint Height)> DecodeRgbAsync(string path)
    {
        using var stream = await (await StorageFile.GetFileFromPathAsync(path)).OpenReadAsync();
        var decoder = await BitmapDecoder.CreateAsync(stream);
        uint width = decoder.OrientedPixelWidth, height = decoder.OrientedPixelHeight;
        if (width == 0 || height == 0 || (long)width * height > MaxImagePixels)
            throw new InvalidDataException("PNG/JPEG görüntü boyutu sınırı");

        var pixelProvider = await decoder.GetPixelDataAsync(
            BitmapPixelFormat.Rgba8, BitmapAlphaMode.Straight, new BitmapTransform(),
            ExifOrientationMode.RespectExifOrientation, ColorManagementMode.DoNotColorManage);
        byte[] rgba = pixelProvider.DetachPixelData();
        if (rgba.LongLength != checked((long)width * height * 4))
            throw new InvalidDataException("Görüntü pikselleri eksik");
        var rgb = new byte[checked((int)((long)width * height * 3))];
        for (int x = 0, y = 0; x < rgba.Length; x += 4)
        {
            int a = rgba[x + 3];
            rgb[y++] = (byte)((rgba[x] * a + 255 * (255 - a)) / 255);
            rgb[y++] = (byte)((rgba[x + 1] * a + 255 * (255 - a)) / 255);
            rgb[y++] = (byte)((rgba[x + 2] * a + 255 * (255 - a)) / 255);
        }
        return (rgb, width, height);
    }
}
