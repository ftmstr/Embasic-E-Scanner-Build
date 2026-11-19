namespace Embasic.EScanner.Desktop;

// Windows equivalent of Android's per-page JPEG/PNG export policy.
// Pure .NET: testable without WinRT, a desktop, or a physical device.
internal enum PageImageFormat { Jpeg, Png }

internal readonly record struct PageImageOutputPlan(
    uint Width, uint Height, string MimeType, PageImageFormat Format)
{
    internal const long MaxPixels = 24_000_000;
    internal const uint MaxEdge = 8_000;

    internal static PageImageOutputPlan Measure(
        PageImageFormat format, string destination, uint width, uint height,
        int degrees, PageQuadRecipe quad)
    {
        if (!Enum.IsDefined(format) || !PageRotationRecipe.IsValid(degrees) ||
            !quad.IsValid() || width == 0 || height == 0 ||
            width > MaxEdge || height > MaxEdge || (long)width * height > MaxPixels)
            throw new InvalidDataException("Geçersiz görüntü dönüşümü veya boyutu");
        string extension = format == PageImageFormat.Jpeg ? ".jpg" : ".png";
        if (string.IsNullOrWhiteSpace(destination) ||
            !string.Equals(Path.GetExtension(destination), extension,
                StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(Path.GetFileNameWithoutExtension(destination)))
            throw new InvalidDataException("Hedef uzantı ve format uyuşmuyor");
        if (!quad.IsFullFrame)
        {
            var crop = CropOutputPlan.Measure(checked((int)width), checked((int)height), quad);
            width = checked((uint)crop.Width);
            height = checked((uint)crop.Height);
        }
        if (degrees is 90 or 270) (width, height) = (height, width);
        return new PageImageOutputPlan(width, height,
            format == PageImageFormat.Jpeg ? "image/jpeg" : "image/png", format);
    }

    // Transform the already EXIF-normalized/cropped straight-alpha RGBA pixels.
    // Android parity: clockwise right angles; white JPEG matte; PNG keeps alpha.
    internal static byte[] RotateRgbaToBgra(
        byte[] rgba, uint width, uint height, int degrees, PageImageFormat format)
    {
        if (!Enum.IsDefined(format) || !PageRotationRecipe.IsValid(degrees) ||
            width == 0 || height == 0 || width > MaxEdge || height > MaxEdge ||
            (long)width * height > MaxPixels ||
            rgba.LongLength != checked((long)width * height * 4))
            throw new InvalidDataException("Geçersiz RGB(A) tamponu");
        uint outWidth = degrees is 90 or 270 ? height : width;
        byte[] bgra = new byte[checked((int)((long)width * height * 4))];
        for (uint y = 0; y < height; y++)
        for (uint x = 0; x < width; x++)
        {
            uint tx = x, ty = y;
            switch (degrees)
            {
                case 90: tx = height - 1 - y; ty = x; break;
                case 180: tx = width - 1 - x; ty = height - 1 - y; break;
                case 270: tx = y; ty = width - 1 - x; break;
            }
            int src = checked((int)(((long)y * width + x) * 4));
            int dst = checked((int)(((long)ty * outWidth + tx) * 4));
            int alpha = rgba[src + 3];
            if (format == PageImageFormat.Jpeg)
            {
                bgra[dst] = (byte)((rgba[src + 2] * alpha + 255 * (255 - alpha)) / 255);
                bgra[dst + 1] = (byte)((rgba[src + 1] * alpha + 255 * (255 - alpha)) / 255);
                bgra[dst + 2] = (byte)((rgba[src] * alpha + 255 * (255 - alpha)) / 255);
                bgra[dst + 3] = 255;
            }
            else
            {
                bgra[dst] = rgba[src + 2];
                bgra[dst + 1] = rgba[src + 1];
                bgra[dst + 2] = rgba[src];
                bgra[dst + 3] = (byte)alpha;
            }
        }
        return bgra;
    }
}
