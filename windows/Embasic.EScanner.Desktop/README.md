# Embasic E-Scanner — Windows WinUI 3 workspace preview (PUBLIC)

This is the **first real Windows graphical application project** in the
PUBLIC repo. It targets **C#/.NET 10, WinUI 3 and Windows App SDK 2.6.4**,
using an unpackaged, framework-dependent build
(`UseWinUI=true; WindowsPackageType=None; win-x64`).

The source implements a launchable XAML window, an OS image file picker,
JPEG/PNG file signature checks, per-file 64MiB admission, full private copies
in `%LOCALAPPDATA%/Embasic/E-Scanner/originals`, SHA-256 manifest recovery,
image thumbnails, page movement up/down and deletion. It uses app-generated
UUIDs and no camera, network, advertising or device identifiers.

**Scope:** this preview now has a **first real raster A4 PDF export
source path**, using the Windows image decoder + in-house .NET PDF stream,
same-target-directory staging, reopening via Windows.Data.Pdf for page-count
validation and same-volume atomic replacement. The XAML project's actual
native compile and the exported PDF's physical Windows GUI/runtime smoke
must be recorded separately; source code alone is NOT a passing feature.
This preview still does NOT crop, rotate, correct perspective, invoke OCR,
pair with Android, or provide a validated shipping installer. File picker's local `StorageFile.Path` must
be available; cloud-backed/virtual providers are not yet supported. The
initial manifest has simple private atomic `File.Move` replacement but
has not passed adversarial powercut tests. Large-image decode, visual QA
and installed Windows runtime smoke are NOT VERIFIED.

`dotnet build windows/Embasic.EScanner.Desktop/Embasic.EScanner.Desktop.csproj
-c Release -p:Platform=x64 -p:RuntimeIdentifier=win-x64` is the intended
Windows CI compilation check, not a GUI/runtime acceptance. The unpackaged
app requires matching Windows App SDK runtime on the device.
**Microsoft.WindowsAppSDK 2.6.4 and its Windows SDK BuildTools transitive
dependencies have unresolved EULA/REDIST and source licensing gates.**
Distribution is **NO-GO**, even if compile succeeds.

Next: on-device GUI smoke, Windows real PDF export with staging/validation
and atomic replacement, local workspace parity tests with Android, then
perspective, image engine, offline OCR, secure QR/TLS and signing.
