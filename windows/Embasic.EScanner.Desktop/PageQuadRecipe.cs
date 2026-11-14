using System.Globalization;

namespace Embasic.EScanner.Desktop;

/// <summary>
/// Immutable original-image-space normalized quad (0..1000).
/// TL, TR, BR, BL; fixed integer canonical wire-free persistence on both OSes.
/// </summary>
internal sealed record PageQuadRecipe(
    int X0, int Y0, int X1, int Y1, int X2, int Y2, int X3, int Y3)
{
    internal static readonly PageQuadRecipe Full = new(0, 0, 1000, 0, 1000, 1000, 0, 1000);
    internal static readonly PageQuadRecipe Inset = new(80, 80, 920, 80, 920, 920, 80, 920);
    internal bool IsFullFrame => this == Full;
    internal double X(int index) => At(index).X / 1000.0;
    internal double Y(int index) => At(index).Y / 1000.0;
    internal (int X, int Y) At(int index) => index switch
    {
        0 => (X0, Y0), 1 => (X1, Y1),
        2 => (X2, Y2), 3 => (X3, Y3),
        _ => throw new ArgumentOutOfRangeException(nameof(index))
    };
    internal string Encode() => FormattableString.Invariant(
        $"{X0},{Y0};{X1},{Y1};{X2},{Y2};{X3},{Y3}");

    internal static bool TryParse(string? raw, out PageQuadRecipe quad)
    {
        quad = Full;
        if (raw is null) return true; // older persisted workspace
        var pts = raw.Split(';');
        if (pts.Length != 4) return false;
        var values = new int[8];
        for (int i = 0; i < 4; i++)
        {
            var coords = pts[i].Split(',');
            if (coords.Length != 2) return false;
            for (int j = 0; j < 2; j++)
            {
                string literal = coords[j];
                if (!int.TryParse(literal, NumberStyles.None,
                        CultureInfo.InvariantCulture, out int v) ||
                    v is < 0 or > 1000 ||
                    literal != v.ToString(CultureInfo.InvariantCulture))
                    return false;
                values[2 * i + j] = v;
            }
        }
        var candidate = new PageQuadRecipe(values[0], values[1], values[2],
            values[3], values[4], values[5], values[6], values[7]);
        if (!candidate.IsValid()) return false;
        quad = candidate;
        return true;
    }

    internal PageQuadRecipe? Moved(int index, int x, int y)
    {
        x = Math.Clamp(x, 0, 1000);
        y = Math.Clamp(y, 0, 1000);
        var next = index switch
        {
            0 => this with { X0 = x, Y0 = y },
            1 => this with { X1 = x, Y1 = y },
            2 => this with { X2 = x, Y2 = y },
            3 => this with { X3 = x, Y3 = y },
            _ => null
        };
        return next?.IsValid() == true ? next : null;
    }

    internal bool IsValid()
    {
        long[] xs = [X0, X1, X2, X3], ys = [Y0, Y1, Y2, Y3];
        if (xs.Any(x => x is < 0 or > 1000) ||
            ys.Any(y => y is < 0 or > 1000)) return false;
        long area2 = 0;
        for (int i = 0; i < 4; i++)
        {
            int j = (i + 1) % 4, k = (i + 2) % 4;
            area2 += xs[i] * ys[j] - xs[j] * ys[i];
            long ex = xs[j] - xs[i], ey = ys[j] - ys[i];
            long fx = xs[k] - xs[j], fy = ys[k] - ys[j];
            if (ex * fy - ey * fx <= 0 || ex * ex + ey * ey < 400)
                return false;
        }
        return area2 >= 100_000L;
    }
}
