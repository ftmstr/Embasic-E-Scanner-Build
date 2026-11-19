namespace Embasic.EScanner.Desktop;

/// <summary>
/// Original-image-space crop sizing shared with Android's CropOutputPlan.
/// Preserve source pixel density up to 6000px/edge and 12MP per crop;
/// bounded downsampling beyond those limits (not tile streaming).
/// </summary>
internal static class CropOutputPlan
{
    internal const int MaxEdge = 6000;
    internal const long MaxPixels = 12_000_000;
    internal const long MaxInputGeometry = 100_000_000;
    internal readonly record struct Size(int Width, int Height);

    internal static Size Measure(int width, int height, PageQuadRecipe quad)
    {
        if (width <= 0 || height <= 0 ||
            (long)width * height > MaxInputGeometry || !quad.IsValid())
            throw new InvalidDataException("Invalid input geometry or quad");
        double w = width, h = height;
        double Distance(int i, int j)
        {
            double dx = (quad.X(j) - quad.X(i)) * w;
            double dy = (quad.Y(j) - quad.Y(i)) * h;
            return Math.Sqrt(dx * dx + dy * dy);
        }
        double targetW = Math.Max(Distance(0, 1), Distance(3, 2));
        double targetH = Math.Max(Distance(0, 3), Distance(1, 2));
        if (!double.IsFinite(targetW) || !double.IsFinite(targetH) ||
            targetW <= 0 || targetH <= 0)
            throw new InvalidDataException("Degenerate perspective dimensions");
        double factor = Math.Min(1.0, Math.Min(MaxEdge / Math.Max(targetW, targetH),
            Math.Sqrt((double)MaxPixels / (targetW * targetH))));
        // Half-up for nonnegative geometry: exactly matches Kotlin's floor(v+.5).
        int outW = Math.Max(32, checked((int)Math.Floor(targetW * factor + 0.5)));
        int outH = Math.Max(32, checked((int)Math.Floor(targetH * factor + 0.5)));
        if (outW > MaxEdge || outH > MaxEdge || (long)outW * outH > MaxPixels)
            throw new InvalidDataException("Crop output geometry exceeds safety limit");
        return new Size(outW, outH);
    }
}
