namespace Embasic.EScanner.Desktop;

/// <summary>
/// CPU-only bounded inverse projective mapping for PDF raster export.
/// Reads the already decoded/EXIF-oriented image, never alters original bytes.
/// Source-resolution crop up to 6000px/edge and 12MP; WinRT PDF QA NOT VERIFIED.
/// </summary>
internal static class PagePerspective
{
    internal static (byte[] Rgb, uint Width, uint Height) WarpRgb(
        byte[] source, uint width, uint height, PageQuadRecipe quad)
    {
        if (!quad.IsValid() || width == 0 || height == 0 ||
            source.LongLength != checked((long)width * height * 3))
            throw new InvalidDataException("Invalid quad or source image pixels");
        if (quad.IsFullFrame) return (source, width, height);
        double w = width, h = height;
        var plan = CropOutputPlan.Measure(checked((int)width), checked((int)height), quad);
        int outW = plan.Width;
        int outH = plan.Height;
        // Homography from unit destination rectangle (u,v) -> original quad.
        double x0 = quad.X(0) * (w - 1), y0 = quad.Y(0) * (h - 1);
        double x1 = quad.X(1) * (w - 1), y1 = quad.Y(1) * (h - 1);
        double x2 = quad.X(2) * (w - 1), y2 = quad.Y(2) * (h - 1);
        double x3 = quad.X(3) * (w - 1), y3 = quad.Y(3) * (h - 1);
        double dx1 = x1 - x2, dy1 = y1 - y2;
        double dx2 = x3 - x2, dy2 = y3 - y2;
        double dx3 = x0 - x1 + x2 - x3, dy3 = y0 - y1 + y2 - y3;
        double g = 0, k = 0;
        if (Math.Abs(dx3) > 1e-9 || Math.Abs(dy3) > 1e-9)
        {
            double den = dx1 * dy2 - dx2 * dy1;
            if (Math.Abs(den) < 1e-9)
                throw new InvalidDataException("Singular perspective crop");
            g = (dx3 * dy2 - dx2 * dy3) / den;
            k = (dx1 * dy3 - dx3 * dy1) / den;
        }
        double a = x1 - x0 + g * x1, b = x3 - x0 + k * x3;
        double d = y1 - y0 + g * y1, e = y3 - y0 + k * y3;
        byte[] output = new byte[checked(outW * outH * 3)];
        for (int y = 0; y < outH; y++)
        {
            double v = (y + 0.5) / outH;
            for (int x = 0; x < outW; x++)
            {
                double u = (x + 0.5) / outW;
                double denom = g * u + k * v + 1;
                if (Math.Abs(denom) < 1e-9)
                    throw new InvalidDataException("Singular projective coordinate");
                double px = (a * u + b * v + x0) / denom;
                double py = (d * u + e * v + y0) / denom;
                if (!double.IsFinite(px) || !double.IsFinite(py))
                    throw new InvalidDataException("Nonfinite projective coordinate");
                px = Math.Clamp(px, 0, w - 1);
                py = Math.Clamp(py, 0, h - 1);
                int ix = (int)px, iy = (int)py;
                int xx = Math.Min(ix + 1, (int)width - 1);
                int yy = Math.Min(iy + 1, (int)height - 1);
                double fx = px - ix, fy = py - iy;
                int base00 = checked((iy * (int)width + ix) * 3);
                int base10 = checked((iy * (int)width + xx) * 3);
                int base01 = checked((yy * (int)width + ix) * 3);
                int base11 = checked((yy * (int)width + xx) * 3);
                int target = (y * outW + x) * 3;
                for (int color = 0; color < 3; color++)
                {
                    double top = source[base00 + color] * (1 - fx) +
                                 source[base10 + color] * fx;
                    double bottom = source[base01 + color] * (1 - fx) +
                                    source[base11 + color] * fx;
                    output[target + color] =
                        (byte)Math.Clamp((int)Math.Round(top * (1 - fy) +
                                                       bottom * fy), 0, 255);
                }
            }
        }
        return (output, (uint)outW, (uint)outH);
    }
}
