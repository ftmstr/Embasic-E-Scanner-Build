using System.Security.Cryptography;
using System.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Storage;
using Windows.Storage.Pickers;

namespace Embasic.EScanner.Desktop;

/// <summary>
/// Unpackaged WinUI3 first vertical slice: local PNG/JPEG originals, thumbnails,
/// ordering and deletion. No OCR, crop, PDF engine, or release packaging yet.
/// </summary>
public sealed partial class MainWindow : Window
{
    private sealed record ScanPage(string FileName, string Sha256);
    private readonly List<ScanPage> _pages = [];
    private readonly string _privateRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Embasic", "E-Scanner", "originals");
    private bool _busy;
    private const long MaxBytes = 64L * 1024L * 1024L;
    private const int MaxPages = 100;

    public MainWindow()
    {
        InitializeComponent();
        Directory.CreateDirectory(_privateRoot);
        PageStack.Loaded += async (_, _) => await RestoreAsync();
    }

    private string ManifestPath => Path.Combine(_privateRoot, "workspace-v1.txt");

    private async Task RestoreAsync()
    {
        if (_busy) return;
        SetBusy(true, "Yerel sayfalar doğrulanıyor…");
        try
        {
            if (File.Exists(ManifestPath))
            {
                var lines = await File.ReadAllLinesAsync(ManifestPath);
                foreach (var entry in lines.Take(MaxPages))
                {
                    var chunks = entry.Split(':');
                    if (chunks.Length != 2 ||
                        !System.Text.RegularExpressions.Regex.IsMatch(
                            chunks[0], @"^[0-9a-fA-F-]{36}\.(jpg|png)$") ||
                        !System.Text.RegularExpressions.Regex.IsMatch(
                            chunks[1], @"^[0-9a-f]{64}$")) continue;
                    var path = Path.Combine(_privateRoot, chunks[0]);
                    if (File.Exists(path) && new FileInfo(path).Length <= MaxBytes &&
                        await DigestAsync(path) == chunks[1])
                        _pages.Add(new ScanPage(chunks[0], chunks[1]));
                }
            }
            await RenderPagesAsync();
            StatusText.Text = $"{_pages.Count} sayfa hazır (yerel çalışma alanı).";
        }
        catch (Exception e) { StatusText.Text = "Çalışma alanı okunamadı: " + e.GetType().Name; }
        finally { SetBusy(false); }
    }

    private async void AddImages_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add(".jpg");
        picker.FileTypeFilter.Add(".jpeg");
        picker.FileTypeFilter.Add(".png");
        WinRT.Interop.InitializeWithWindow.Initialize(
            picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        var picked = await picker.PickMultipleFilesAsync();
        if (picked is null || picked.Count == 0) return;
        SetBusy(true, "Görseller uygulama içine kopyalanıyor…");
        int imported = 0, refused = 0;
        try
        {
            foreach (var source in picked.Take(MaxPages - _pages.Count))
            {
                try
                {
                    var result = await CopyPrivateAsync(source);
                    _pages.Add(result);
                    imported++;
                }
                catch (Exception) { refused++; }
            }
            SaveOrder();
            await RenderPagesAsync();
            StatusText.Text = $"{imported} görsel eklendi, {refused} reddedildi.";
        }
        finally { SetBusy(false); }
    }

    private async void SavePdf_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _pages.Count == 0) return;
        var picker = new FileSavePicker();
        picker.FileTypeChoices.Add("PDF dosyası", new List<string> { ".pdf" });
        picker.SuggestedFileName = "Embasic-Scan";
        WinRT.Interop.InitializeWithWindow.Initialize(
            picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        var file = await picker.PickSaveFileAsync();
        if (file is null) return;
        SetBusy(true, "PDF geçici dosyada oluşturuluyor ve yeniden açılarak doğrulanıyor…");
        try
        {
            // Validate immutable private images before writing anything.
            var paths = new List<string>();
            foreach (var page in _pages)
            {
                string image = Path.Combine(_privateRoot, page.FileName);
                if (await DigestAsync(image) != page.Sha256)
                    throw new InvalidDataException("Orijinal dosya SHA-256 uyuşmuyor");
                paths.Add(image);
            }
            if (string.IsNullOrWhiteSpace(file.Path))
                throw new InvalidDataException("Bu konumdaki dosya doğrudan yazılamıyor");
            int count = await RasterPdfWriter.ExportVerifiedAsync(paths, file.Path);
            StatusText.Text = $"A4 PDF kaydedildi: {count} sayfa. (OCR yok.)";
        }
        catch (Exception error)
        {
            StatusText.Text = "PDF kaydedilemedi: " + error.GetType().Name +
                ". Doğrulama başarısızsa mevcut hedef korunur.";
        }
        finally { SetBusy(false); }
    }

    private async Task<ScanPage> CopyPrivateAsync(StorageFile source)
    {
        var path = source.Path;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            throw new IOException("Yalnız yerel dosyalar destekleniyor");
        var length = new FileInfo(path).Length;
        if (length < 1 || length > MaxBytes) throw new IOException("64MiB dosya sınırı");
        var temporary = Path.Combine(_privateRoot, "in-" + Guid.NewGuid().ToString("N") + ".tmp");
        string? permanent = null;
        try
        {
            await using (var input = File.OpenRead(path))
            await using (var output = new FileStream(
                temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536,
                FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                await input.CopyToAsync(output);
                await output.FlushAsync();
            }
            string ext = SniffExtension(temporary)
                ?? throw new IOException("Yalnız geçerli JPEG/PNG");
            string id = Guid.NewGuid().ToString("D");
            string name = $"{id}.{ext}";
            permanent = Path.Combine(_privateRoot, name);
            File.Move(temporary, permanent); // same-private-directory, no overwrite
            string digest = await DigestAsync(permanent);
            return new ScanPage(name, digest);
        }
        catch
        {
            if (permanent is not null && File.Exists(permanent)) File.Delete(permanent);
            throw;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static string? SniffExtension(string file)
    {
        Span<byte> prefix = stackalloc byte[8];
        using var fs = File.OpenRead(file);
        if (fs.Read(prefix) != prefix.Length) return null;
        if (prefix[0] == 0xFF && prefix[1] == 0xD8) return "jpg";
        if (prefix.SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }))
            return "png";
        return null;
    }

    private static async Task<string> DigestAsync(string path)
    {
        await using var fs = File.OpenRead(path);
        var bytes = await SHA256.HashDataAsync(fs);
        return Convert.ToHexStringLower(bytes);
    }

    private async Task RenderPagesAsync()
    {
        PageStack.Children.Clear();
        PageCount.Text = $"{_pages.Count} sayfa";
        SavePdfButton.IsEnabled = !_busy && _pages.Count > 0;
        for (int index = 0; index < _pages.Count; index++)
        {
            var page = _pages[index];
            var card = new Border {
                Background = new SolidColorBrush(
                    Microsoft.UI.Colors.AliceBlue),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(12),
            };
            var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12 };
            var thumbnail = new Image {
                Width = 92, Height = 120, Stretch = Stretch.Uniform
            };
            var bitmap = new BitmapImage { DecodePixelWidth = 240 };
            var file = await StorageFile.GetFileFromPathAsync(
                Path.Combine(_privateRoot, page.FileName));
            using (var stream = await file.OpenReadAsync())
                await bitmap.SetSourceAsync(stream);
            thumbnail.Source = bitmap;
            row.Children.Add(thumbnail);
            var controls = new StackPanel { Spacing = 7, VerticalAlignment = VerticalAlignment.Center };
            controls.Children.Add(new TextBlock {
                Text = $"Sayfa {index + 1} · {page.FileName[(page.FileName.LastIndexOf('.') + 1)..].ToUpperInvariant()}",
                FontSize = 17, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold
            });
            var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            int selected = index;
            var up = new Button { Content = "↑", IsEnabled = index > 0 };
            up.Click += async (_, _) => await MovePageAsync(selected, selected - 1);
            var down = new Button { Content = "↓", IsEnabled = index < _pages.Count - 1 };
            down.Click += async (_, _) => await MovePageAsync(selected, selected + 1);
            var delete = new Button { Content = "Sil" };
            delete.Click += async (_, _) => await RemovePageAsync(selected);
            buttons.Children.Add(up);
            buttons.Children.Add(down);
            buttons.Children.Add(delete);
            controls.Children.Add(buttons);
            row.Children.Add(controls);
            card.Child = row;
            PageStack.Children.Add(card);
        }
    }

    private async Task MovePageAsync(int from, int to)
    {
        if (_busy || from < 0 || from >= _pages.Count || to < 0 || to >= _pages.Count) return;
        var page = _pages[from]; _pages.RemoveAt(from); _pages.Insert(to, page);
        SaveOrder();
        await RenderPagesAsync();
        StatusText.Text = "Sayfa sırası güncellendi.";
    }

    private async Task RemovePageAsync(int index)
    {
        if (_busy || index < 0 || index >= _pages.Count) return;
        var page = _pages[index];
        _pages.RemoveAt(index);
        SaveOrder();
        File.Delete(Path.Combine(_privateRoot, page.FileName));
        await RenderPagesAsync();
        StatusText.Text = "Sayfa silindi.";
    }

    private void SaveOrder()
    {
        var stage = Path.Combine(_privateRoot, "workspace-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            File.WriteAllLines(stage, _pages.Select(p => p.FileName + ":" + p.Sha256),
                Encoding.UTF8);
            File.Move(stage, ManifestPath, true);
        }
        finally { if (File.Exists(stage)) File.Delete(stage); }
    }

    private void SetBusy(bool value, string? message = null)
    {
        _busy = value;
        SavePdfButton.IsEnabled = !value && _pages.Count > 0;
        if (message is not null) StatusText.Text = message;
    }
}
