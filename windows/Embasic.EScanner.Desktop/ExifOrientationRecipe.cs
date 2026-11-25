namespace Embasic.EScanner.Desktop;

/// <summary>
/// JVM-independent EXIF orientation geometry parity oracle.
/// Actual Windows PDF uses BitmapDecoder ExifOrientationMode.RespectExifOrientation,
/// not this coordinate model. Does not validate a live WinRT decode.
/// </summary>
internal readonly record struct ExifOrientationRecipe(int Tag)
{
    internal static bool TryParse(int tag, out ExifOrientationRecipe recipe)
    {
        recipe = new ExifOrientationRecipe(tag);
        return tag is >= 1 and <= 8;
    }

    internal (int Width, int Height) OutputSize(int width, int height)
    {
        if (Tag is < 1 or > 8 || width <= 0 || height <= 0 ||
            (long)width * height > 100_000_000L)
            throw new InvalidDataException("EXIF source geometry or orientation invalid");
        return Tag >= 5 ? (height, width) : (width, height);
    }

    internal (int X, int Y) MapPixel(int width, int height, int x, int y)
    {
        OutputSize(width, height);
        if (x < 0 || y < 0 || x >= width || y >= height)
            throw new InvalidDataException("EXIF pixel outside source raster");
        return Tag switch
        {
            1 => (x, y),
            2 => (width - 1 - x, y),
            3 => (width - 1 - x, height - 1 - y),
            4 => (x, height - 1 - y),
            5 => (y, x),
            6 => (height - 1 - y, x),
            7 => (height - 1 - y, width - 1 - x),
            8 => (y, width - 1 - x),
            _ => throw new InvalidDataException("EXIF orientation invalid")
        };
    }
}
