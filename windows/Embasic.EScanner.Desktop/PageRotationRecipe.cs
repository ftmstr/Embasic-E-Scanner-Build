using System.Globalization;

namespace Embasic.EScanner.Desktop;

/// <summary>
/// Immutable-source right-angle recipe shared by WinUI3 thumbnails and PDF.
/// Pixels and SHA-256 of imported original assets are never changed.
/// Angles are clockwise in the displayed document coordinate system.
/// </summary>
internal static class PageRotationRecipe
{
    internal static bool IsValid(int degrees) =>
        degrees is 0 or 90 or 180 or 270;

    internal static int Clockwise(int current) =>
        IsValid(current) ? (current + 90) % 360 :
            throw new InvalidDataException("Invalid persisted page rotation");

    internal static bool TryParse(string? field, out int degrees)
    {
        degrees = 0;
        if (field is null) return true; // legacy two-column workspace
        if (field is not ("0" or "90" or "180" or "270"))
            return false;
        return int.TryParse(field, NumberStyles.None, CultureInfo.InvariantCulture, out degrees);
    }

    /// <summary>
    /// PDF image unit-square affine mapping inside A4 595x842.
    /// Returned commands ONLY rotate the PDF presentation; do not touch the
    /// original image or its encoded/hashed binary bytes.
    /// </summary>
    internal static string PdfImageCommand(uint width, uint height, int rotationDegrees)
    {
        if (width == 0 || height == 0 || !IsValid(rotationDegrees))
            throw new InvalidDataException("Invalid image geometry or rotation");
        bool swapped = rotationDegrees is 90 or 270;
        double orientedW = swapped ? height : width;
        double orientedH = swapped ? width : height;
        double scale = Math.Min(555.0 / orientedW, 802.0 / orientedH);
        double w = orientedW * scale, h = orientedH * scale;
        double x = (595.0 - w) / 2.0, y = (842.0 - h) / 2.0;
        static string F(double d) => d.ToString("0.###", CultureInfo.InvariantCulture);
        return rotationDegrees switch
        {
            0   => $"q {F(w)} 0 0 {F(h)} {F(x)} {F(y)} cm /Im0 Do Q\n",
            90  => $"q 0 {F(-h)} {F(w)} 0 {F(x)} {F(y + h)} cm /Im0 Do Q\n",
            180 => $"q {F(-w)} 0 0 {F(-h)} {F(x + w)} {F(y + h)} cm /Im0 Do Q\n",
            270 => $"q 0 {F(h)} {F(-w)} 0 {F(x + w)} {F(y)} cm /Im0 Do Q\n",
            _   => throw new InvalidDataException("Invalid page rotation")
        };
    }
}
