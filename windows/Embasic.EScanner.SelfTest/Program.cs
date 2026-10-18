using Embasic.EScanner.Contracts;
if (!ScanContract.IsSupportedVersion(1) || ScanContract.IsSupportedVersion(0) || ScanContract.IsSupportedVersion(2) || !ScanContract.IsValidPageOrder(0) || ScanContract.IsValidPageOrder(-1))
{
    Console.Error.WriteLine("FAIL: contract boundary");
    return 1;
}
Console.WriteLine("PASS: 5 contract assertions");
return 0;

var fixture = SyntheticPdf.Create();
if (!SyntheticPdf.VerifyFixture(fixture))
{
    Console.Error.WriteLine("FAIL: synthetic PDF structure");
    return 1;
}
var damaged = (byte[])fixture.Clone();
damaged[0] = (byte)'X';
if (SyntheticPdf.VerifyFixture(damaged))
{
    Console.Error.WriteLine("FAIL: corrupt PDF header accepted");
    return 1;
}
damaged = (byte[])fixture.Clone();
damaged[^2] = (byte)'X';
if (SyntheticPdf.VerifyFixture(damaged))
{
    Console.Error.WriteLine("FAIL: corrupt PDF trailer accepted");
    return 1;
}
Console.WriteLine("PASS: 3 synthetic PDF fixture assertions");
