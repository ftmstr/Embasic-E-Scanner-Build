using Embasic.EScanner.Desktop;

static void Require(bool condition, string why)
{
    if (!condition) throw new Exception("FAIL: " + why);
}

// Same UX contract as Android: canonical persisted 0,90,180,270;
// original image SHA/bytes unchanged; cyclic clockwise and reset.
int angle = 0;
foreach (int expected in new[] { 90, 180, 270, 0 })
{
    angle = PageRotationRecipe.Clockwise(angle);
    Require(angle == expected, "clockwise 90-degree sequence");
    Require(PageRotationRecipe.TryParse(expected.ToString(), out int parsed) &&
            parsed == expected, "strict manifest round trip");
}
Require(PageRotationRecipe.TryParse(null, out int legacy) && legacy == 0,
    "legacy manifest migration");
foreach (string invalid in new[] { "", "45", "-90", "360", "090", "abc", "1.5", " 90" })
    Require(!PageRotationRecipe.TryParse(invalid, out _),
        "reject noncanonical rotation: " + invalid);
try { PageRotationRecipe.Clockwise(12); throw new Exception("invalid angle accepted"); }
catch (InvalidDataException) { /* expected */ }

// PDF unit image matrices must occupy the A4 safe region. Test exact
// axis swaps and clockwise signs for all four angles at unequal geometry.
var zero = PageRotationRecipe.PdfImageCommand(200, 100, 0);
var right = PageRotationRecipe.PdfImageCommand(200, 100, 90);
var half = PageRotationRecipe.PdfImageCommand(200, 100, 180);
var left = PageRotationRecipe.PdfImageCommand(200, 100, 270);
Require(zero.Contains("q 555 0 0 277.5 20 282.25 cm"),
    "PDF 0-degree unrotated matrix");
Require(right.Contains("q 0 -802 401 0 97 822 cm"),
    "PDF 90-degree clockwise/portrait matrix");
Require(half.Contains("q -555 0 0 -277.5 575 559.75 cm"),
    "PDF 180-degree matrix");
Require(left.Contains("q 0 802 -401 0 498 20 cm"),
    "PDF 270-degree counterclockwise matrix");
foreach (int invalid in new[] { -90, 45, 360 })
{
    try { PageRotationRecipe.PdfImageCommand(200, 100, invalid);
          throw new Exception("invalid PDF transform accepted"); }
    catch (InvalidDataException) { /* expected */ }
}
foreach (var (w, h) in new[] { (0u, 100u), (100u, 0u) })
{
    try { PageRotationRecipe.PdfImageCommand(w, h, 90);
          throw new Exception("zero image dimension accepted"); }
    catch (InvalidDataException) { /* expected */ }
}
Require(PageQuadRecipe.TryParse(null, out var legacyQuad) &&
    legacyQuad.IsFullFrame, "legacy quad identity");
Require(PageQuadRecipe.Inset.IsValid() &&
    PageQuadRecipe.TryParse(PageQuadRecipe.Inset.Encode(), out var reloaded) &&
    reloaded == PageQuadRecipe.Inset, "quad persisted roundtrip");
Require(PageQuadRecipe.Full.Moved(0, 120, 150) is { } moved &&
    PageQuadRecipe.TryParse(moved.Encode(), out var saved) &&
    moved == saved, "move/canonical persistence");
foreach (var invalidQuad in new[] {
    "", "0,0;1000,0;1000,1000", "0,0;1000,1000;1000,0;0,1000",
    "0,0;20,0;20,20;0,20", "000,0;1000,0;1000,1000;0,1000",
    "-1,0;1000,0;1000,1000;0,1000", "0,0;1001,0;1000,1000;0,1000"
})
    Require(!PageQuadRecipe.TryParse(invalidQuad, out _), "reject unsafe quad");
Require(PageQuadRecipe.Full.Moved(0, 1000, 1000) is null,
    "folded quad must reject before apply");
// One canonical TSV drives Android JUnit and Windows .NET exact geometry parity.
string fixture = Path.Combine(AppContext.BaseDirectory, "perspective-output-v1.tsv");
Require(File.Exists(fixture), "shared perspective geometry fixture copied");
int sharedCases = 0;
foreach (string row in File.ReadLines(fixture))
{
    if (string.IsNullOrWhiteSpace(row) || row.StartsWith('#')) continue;
    string[] fields = row.Split('\t');
    Require(fields.Length == 6, "shared golden TSV field count");
    Require(PageQuadRecipe.TryParse(fields[3], out var quad), "shared golden quad");
    var plan = CropOutputPlan.Measure(int.Parse(fields[1]), int.Parse(fields[2]), quad);
    Require(plan.Width == int.Parse(fields[4]) &&
        plan.Height == int.Parse(fields[5]), "shared golden geometry " + fields[0]);
    Require(plan.Width <= CropOutputPlan.MaxEdge &&
        (long)plan.Width * plan.Height <= CropOutputPlan.MaxPixels,
        "bounded plan " + fields[0]);
    sharedCases++;
}
Require(sharedCases == 5, "shared golden case count");
foreach (var (w0, h0) in new[] { (0, 100), (-1, 200), (100, 0), (20000, 20000) })
{
    try { CropOutputPlan.Measure(w0, h0, PageQuadRecipe.Inset);
        throw new Exception("accepted invalid input geometry"); }
    catch (InvalidDataException) { /* expected */ }
}
Console.WriteLine("PASS: 5 shared Android/Windows 12MP perspective geometry goldens");
// Shared Android JUnit / .NET EXIF tag 0x0112 parity geometry (NOT a WinRT decode).
string exifFixture = Path.Combine(AppContext.BaseDirectory, "exif-orientation-v1.tsv");
Require(File.Exists(exifFixture), "EXIF synthetic fixture copied into .NET test output");
int exifCases = 0;
var exifTags = new HashSet<int>();
foreach (string line in File.ReadLines(exifFixture))
{
    if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
    var fields = line.Split('\t').Select(int.Parse).ToArray();
    Require(fields.Length == 9, "EXIF fixture column count");
    Require(ExifOrientationRecipe.TryParse(fields[0], out var recipe),
        "EXIF supported tag");
    var dims = recipe.OutputSize(fields[1], fields[2]);
    var pixel = recipe.MapPixel(fields[1], fields[2], fields[3], fields[4]);
    Require(dims == (fields[5], fields[6]) &&
            pixel == (fields[7], fields[8]), "EXIF golden tag " + fields[0]);
    exifCases++;
    exifTags.Add(fields[0]);
}
Require(exifCases == 16 && exifTags.SetEquals(Enumerable.Range(1, 8)),
    "all eight EXIF tag geometries and 16 corner goldens executed");
foreach (int invalidExif in new[] { -1, 0, 9, 255 })
    Require(!ExifOrientationRecipe.TryParse(invalidExif, out _),
        "EXIF malformed orientation tag rejected");
foreach (var (badW, badH) in new[] { (0, 3), (3, 0), (-1, 3), (20000, 20000) })
{
    try { new ExifOrientationRecipe(1).OutputSize(badW, badH);
        throw new Exception("invalid EXIF geometry admitted"); }
    catch (InvalidDataException) { /* expected */ }
}
Console.WriteLine("PASS: 16 shared Android/Windows EXIF golden coordinate cases for eight tags; Windows decoder runtime NOT VERIFIED");

byte[] synthetic = new byte[8 * 8 * 3];
for (int y = 0; y < 8; y++)
    for (int x = 0; x < 8; x++)
    {
        int offset = (y * 8 + x) * 3;
        synthetic[offset] = (byte)(x * 20);
        synthetic[offset + 1] = (byte)(y * 20);
        synthetic[offset + 2] = 17;
    }
var warped = PagePerspective.WarpRgb(synthetic, 8, 8, PageQuadRecipe.Inset);
Require(warped.Width >= 32 && warped.Height >= 32 &&
    warped.Rgb.Length == warped.Width * warped.Height * 3,
    "real CPU projective warp output dimensions");
Require(warped.Rgb[2] == 17, "perspective corner sampling retains synthetic blue");
Require(PagePerspective.WarpRgb(synthetic, 8, 8,
    PageQuadRecipe.Full).Rgb == synthetic, "identity preserves RGB bytes");
try {
    PagePerspective.WarpRgb(new byte[7], 8, 8, PageQuadRecipe.Inset);
    throw new Exception("corrupt pixel buffer accepted");
}
catch (InvalidDataException) { /* expected */ }
Console.WriteLine("PASS: Windows normalized manual crop quad and bounded CPU perspective warp");
Console.WriteLine("PASS: Windows right-angle rotation manifest migration, " +
    "four A4 PDF matrices, corrupt angles and zero dimensions rejected; " +
    "actual WinUI3 visual/PDF-runtime test NOT VERIFIED");
return 0;
