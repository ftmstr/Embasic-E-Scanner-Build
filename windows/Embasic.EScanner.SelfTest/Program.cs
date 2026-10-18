using Embasic.EScanner.Contracts;
if (!ScanContract.IsSupportedVersion(1) || ScanContract.IsSupportedVersion(0) || ScanContract.IsSupportedVersion(2) || !ScanContract.IsValidPageOrder(0) || ScanContract.IsValidPageOrder(-1))
{
    Console.Error.WriteLine("FAIL: contract boundary");
    return 1;
}
Console.WriteLine("PASS: 5 contract assertions");
return 0;
