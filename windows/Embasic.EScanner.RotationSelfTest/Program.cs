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
Console.WriteLine("PASS: Windows right-angle rotation manifest migration, " +
    "four A4 PDF matrices, corrupt angles and zero dimensions rejected; " +
    "actual WinUI3 visual/PDF-runtime test NOT VERIFIED");
return 0;
