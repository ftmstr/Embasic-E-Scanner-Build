namespace Embasic.EScanner.Contracts;

public static class ScanContract
{
    public const int ProtocolVersion = 1;
    public static bool IsSupportedVersion(int version) => version == ProtocolVersion;
    public static bool IsValidPageOrder(int order) => order >= 0;
}
