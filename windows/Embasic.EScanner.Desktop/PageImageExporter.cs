using System.Security.Cryptography;
using Windows.Graphics.Imaging;
using Windows.Storage;

namespace Embasic.EScanner.Desktop;

/// <summary>
/// Native WinRT JPEG/PNG encoding for one immutable workspace page.
/// No direct target writes: validate staged bytes, codec, geometry and SHA-256
/// before same-directory replacement. Device and visual QA NOT VERIFIED.
/// </summary>
internal static class PageImageExporter
{
    private const long MaxStageBytes = 256L * 1024L * 1024L;

    internal static async Task<string> ExportVerifiedAsync(
        RasterPdfPage page, string destination, PageImageFormat format)
    {
        if (string.IsNullOrWhiteSpace(destination) ||
            !PageRotationRecipe.IsValid(page.RotationDegrees) ||
            !(page.Quad ?? PageQuadRecipe.Full).IsValid())
            throw new InvalidDataException("Geçersiz sayfa veya hedef");

        string target = Path.GetFullPath(destination);
        string parent = Path.GetDirectoryName(target)
            ?? throw new InvalidDataException("Hedef klasör yok");
        if (!Directory.Exists(parent) ||
            string.Equals(Path.GetFullPath(page.ImagePath), target,
                StringComparison.OrdinalIgnoreCase) ||
            (File.Exists(target) &&
             (File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0))
            throw new InvalidDataException("Güvensiz hedef yolu");

        // Reject invalid names/formats BEFORE creating any output.
        PageImageOutputPlan.Measure(format, target, 1, 1, page.RotationDegrees,
            PageQuadRecipe.Full);
        string stagePath = Path.Combine(parent,
            ".embasic-image-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var created = new FileStream(stagePath, FileMode.CreateNew,
                FileAccess.Write, FileShare.None)) { }

            using (var original = await (await StorageFile.GetFileFromPathAsync(
                page.ImagePath)).OpenReadAsync())
            {
                var decoder = await BitmapDecoder.CreateAsync(original);
                uint w = decoder.OrientedPixelWidth, h = decoder.OrientedPixelHeight;
                var quad = page.Quad ?? PageQuadRecipe.Full;
                var plan = PageImageOutputPlan.Measure(format, target, w, h,
                    page.RotationDegrees, quad);
                var data = await decoder.GetPixelDataAsync(
                    BitmapPixelFormat.Rgba8, BitmapAlphaMode.Straight,
                    new BitmapTransform(), ExifOrientationMode.RespectExifOrientation,
                    ColorManagementMode.DoNotColorManage);
                byte[] rgba = data.DetachPixelData();
                if (rgba.LongLength != checked((long)w * h * 4))
                    throw new InvalidDataException("Eksik kaynak pikselleri");
                if (!quad.IsFullFrame)
                    (rgba, w, h) = PagePerspective.WarpRgba(rgba, w, h, quad);
                byte[] pixels = PageImageOutputPlan.RotateRgbaToBgra(
                    rgba, w, h, page.RotationDegrees, format);
                var stage = await StorageFile.GetFileFromPathAsync(stagePath);
                using (var stream = await stage.OpenAsync(FileAccessMode.ReadWrite))
                {
                    // Align the requested JPEG quality with Android's quality 92 policy.
                    var encoder = format == PageImageFormat.Jpeg
                        ? await BitmapEncoder.CreateAsync(BitmapEncoder.JpegEncoderId,
                            stream, new BitmapPropertySet {
                                { "ImageQuality", new BitmapTypedValue(
                                    0.92f, Windows.Foundation.PropertyType.Single) }
                            })
                        : await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId,
                            stream);
                    encoder.SetPixelData(BitmapPixelFormat.Bgra8,
                        format == PageImageFormat.Jpeg
                            ? BitmapAlphaMode.Ignore : BitmapAlphaMode.Straight,
                        plan.Width, plan.Height, 96, 96, pixels);
                    await encoder.FlushAsync();
                    await stream.FlushAsync();
                }
                await ValidateStageAsync(stage, stagePath, plan);
            }

            // The old target remains untouched for any codec/readback failure.
            // A single same-directory rename/replace is the publication point.
            File.Move(stagePath, target, overwrite: true);
            return target;
        }
        finally { if (File.Exists(stagePath)) File.Delete(stagePath); }
    }

    private static async Task ValidateStageAsync(
        StorageFile stage, string stagePath, PageImageOutputPlan plan)
    {
        var info = new FileInfo(stagePath);
        if (info.Length < 16 || info.Length > MaxStageBytes)
            throw new InvalidDataException("Kodlanmış görsel boyut sınırı");
        byte[] header = new byte[8];
        await using (var fs = File.OpenRead(stagePath))
        {
            if (await fs.ReadAsync(header) != header.Length)
                throw new InvalidDataException("Eksik görsel imzası");
        }
        bool signature = plan.Format == PageImageFormat.Jpeg
            ? header[0] == 0xff && header[1] == 0xd8 && header[2] == 0xff
            : header.AsSpan().SequenceEqual(
                new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 });
        if (!signature) throw new InvalidDataException("Hatalı JPEG/PNG imzası");
        using (var reopened = await stage.OpenReadAsync())
        {
            var decoder = await BitmapDecoder.CreateAsync(reopened);
            if (decoder.OrientedPixelWidth != plan.Width ||
                decoder.OrientedPixelHeight != plan.Height ||
                !decoder.DecoderInformation.MimeTypes.Contains(plan.MimeType,
                    StringComparer.OrdinalIgnoreCase))
                throw new InvalidDataException("Kodlanmış MIME/geometri uyuşmazlığı");
        }
        // Stream must be fully closed before File.Move on Windows.
        await using var shaStream = File.OpenRead(stagePath);
        byte[] sha = await SHA256.HashDataAsync(shaStream);
        if (sha.Length != 32 || sha.All(b => b == 0))
            throw new InvalidDataException("Kodlanmış SHA-256 doğrulanamadı");
    }
}
