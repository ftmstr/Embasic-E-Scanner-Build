package com.embasic.escanner.android

import android.app.Activity
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.pdf.PdfDocument
import android.graphics.pdf.PdfRenderer
import android.net.Uri
import android.os.Bundle
import android.os.ParcelFileDescriptor
import androidx.compose.foundation.Image
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color as UiColor
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.unit.dp
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.Executors
import kotlin.math.min
import kotlin.math.roundToInt

/**
 * Initial usable local-first scanning WORKSPACE: import immutable private copies,
 * preview, reorder, remove and export a raster A4 PDF using platform APIs.
 * Not camera capture, perspective correction, OCR or a signed release.
 */
class MainActivity : Activity() {
    private data class ScanPage(
        val id: String, val extension: String, val sha256: String,
        val file: File, val thumbnail: Bitmap, val rotationDegrees: Int = 0,
        val quad: PageQuadRecipe = PageQuadRecipe.FULL
    )

    private val pages = mutableStateListOf<ScanPage>()
    private val io = Executors.newSingleThreadExecutor()
    private var editingPageId by mutableStateOf<String?>(null)
    private var busy by mutableStateOf(true)
    private var status by mutableStateOf("Yerel çalışma alanı yükleniyor…")
    private val assets by lazy { File(filesDir, "originals").also { it.mkdirs() } }
    private val preferences by lazy { getSharedPreferences("scan-workspace-v1", MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = Color.rgb(15, 23, 42)
        setContentView(ComposeView(this).apply {
            setContent { MaterialTheme {
                Surface(color = MaterialTheme.colorScheme.background) {
                    Column(
                        modifier = Modifier.fillMaxSize().padding(18.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text("EMBASIC  /  E-SCANNER", style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary)
                        Text("Tarama çalışma alanı", style = MaterialTheme.typography.headlineSmall)
                        Text("Çevrimdışı · Cihazınıza kayıtlı · İlk kullanılabilir sürüm",
                            style = MaterialTheme.typography.bodySmall)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { openImages() }, enabled = !busy) {
                                Text("Görsel ekle")
                            }
                            OutlinedButton(onClick = { choosePdf() },
                                enabled = !busy && pages.isNotEmpty()) { Text("PDF kaydet") }
                        }
                        Text(status, style = MaterialTheme.typography.bodySmall)
                        if (busy) Text("İşlem sürüyor…", color = MaterialTheme.colorScheme.primary)
                        if (pages.isEmpty() && !busy) {
                            Spacer(Modifier.height(24.dp))
                            Text("Henüz sayfa yok. Görsel ekle ile PNG veya JPEG seçin.")
                        }
                        LazyColumn(
                            modifier = Modifier.fillMaxWidth().weight(1f),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            itemsIndexed(pages, key = { _, page -> page.id }) { index, page ->
                                Card {
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(10.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                                    ) {
                                        Image(
                                            bitmap = page.thumbnail.asImageBitmap(),
                                            contentDescription = "Sayfa ${index + 1} önizlemesi",
                                            modifier = Modifier.size(84.dp)
                                                .graphicsLayer { rotationZ = page.rotationDegrees.toFloat() }
                                                .background(MaterialTheme.colorScheme.surfaceVariant,
                                                    RoundedCornerShape(8.dp)),
                                            contentScale = ContentScale.Fit
                                        )
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text("Sayfa ${index + 1}", style = MaterialTheme.typography.titleMedium)
                                            Text(page.extension.uppercase() + " · " +
                                                (page.file.length() / 1024) + " KB",
                                                style = MaterialTheme.typography.bodySmall)
                                            Text("Döndürme: ${page.rotationDegrees}° · " +
                                                (if (page.quad.isFullFrame) "Kırpma yok" else "4-köşe kırpma") +
                                                " · Orijinal korunur",
                                                style = MaterialTheme.typography.labelSmall)
                                            Row(horizontalArrangement = Arrangement.spacedBy(3.dp)) {
                                                OutlinedButton(
                                                    enabled = !busy && index > 0,
                                                    onClick = { movePage(index, index - 1) }
                                                ) { Text("↑") }
                                                OutlinedButton(
                                                    enabled = !busy && index < pages.lastIndex,
                                                    onClick = { movePage(index, index + 1) }
                                                ) { Text("↓") }
                                                OutlinedButton(enabled = !busy,
                                                    onClick = { removePage(index) }) { Text("Sil") }
                                            }
                                            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                                OutlinedButton(enabled = !busy,
                                                    onClick = { rotatePage(index) }) { Text("↻ 90°") }
                                                OutlinedButton(enabled = !busy && page.rotationDegrees != 0,
                                                    onClick = { resetRotation(index) }) { Text("Sıfırla") }
                                                OutlinedButton(enabled = !busy,
                                                    onClick = { editingPageId = page.id }) { Text("4 köşe") }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Text("PDF: A4 · 90° dönüş ve 4-köşe perspektif uygulanır (sınırlı raster). " +
                            "OCR yok; SAF hedef yazımı atomik değildir.",
                            style = MaterialTheme.typography.labelSmall)
                    }
                    val editing = pages.firstOrNull { it.id == editingPageId }
                    if (editing != null) {
                        QuadDialog(editing, onCancel = { editingPageId = null },
                            onApply = { candidate ->
                                setQuad(editing.id, candidate)
                                editingPageId = null
                            })
                    }
                }
            } }
        })
        io.execute {
            // Recover only recognized private PDF cache stages left by a crash.
            // Live exports from any recreated Activity remain registered.
            val recovery = try { PrivatePdfStageCache.recover(cacheDir) }
                catch (_: Exception) { PrivatePdfStageCache.Recovery(0, 0, 0, 1) }
            val restored = mutableListOf<ScanPage>()
            var invalid = 0
            for (entry in preferences.getString("order", "").orEmpty().lines()) {
                // Empty new workspaces are not corrupt manifest entries.
                if (entry.isBlank()) continue
                val parts = entry.split(':')
                val rotation = if (parts.size in 2..4)
                    PageRotationRecipe.parsePersisted(parts.getOrNull(2)) else null
                val quad = if (parts.size in 2..4)
                    PageQuadRecipe.parse(parts.getOrNull(3)) else null
                if (rotation == null || quad == null || !parts[0].matches(Regex("[0-9a-fA-F-]{36}\\.(jpg|png)")) ||
                    !parts[1].matches(Regex("[0-9a-f]{64}"))) { invalid++; continue }
                val source = File(assets, parts[0])
                try {
                    if (source.isFile && source.length() in 1..MAX_BYTES &&
                        digestFile(source) == parts[1]) {
                        restored.add(ScanPage(
                            parts[0].substringBefore('.'), parts[0].substringAfterLast('.'),
                            parts[1], source, thumbnail(source), rotation, quad
                        ))
                    } else invalid++
                } catch (_: Exception) { invalid++ }
            }
            runOnUiThread {
                pages.addAll(restored.take(MAX_PAGES))
                busy = false
                val workspaceStatus = if (invalid > 0)
                    "$invalid bozuk/eksik kaynak reddedildi"
                    else "${pages.size} sayfa hazır"
                val cleanupStatus = when {
                    recovery.failed > 0 || recovery.unsafeSkipped > 0 ->
                        "PDF geçici önbelleğinde ${recovery.failed + recovery.unsafeSkipped} " +
                            "öğe güvenle temizlenemedi"
                    recovery.removed > 0 ->
                        "${recovery.removed} eski PDF geçici dosyası temizlendi"
                    else -> ""
                }
                status = if (cleanupStatus.isEmpty()) workspaceStatus
                         else "$workspaceStatus · $cleanupStatus"
            }
        }
    }

    private fun openImages() {
        val pick = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "image/*"
            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
        }
        startActivityForResult(pick, REQUEST_IMPORT)
    }

    private fun choosePdf() {
        val create = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/pdf"
            putExtra(Intent.EXTRA_TITLE, "Embasic-Scan.pdf")
        }
        startActivityForResult(create, REQUEST_PDF)
    }

    @Deprecated("Platform document picker result; Android SDK Activity contract.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data == null || busy) return
        when (requestCode) {
            REQUEST_IMPORT -> {
                val selected = mutableListOf<Uri>()
                data.data?.let(selected::add)
                data.clipData?.let { clip ->
                    for (i in 0 until clip.itemCount) {
                        val uri = clip.getItemAt(i).uri
                        if (uri !in selected) selected.add(uri)
                    }
                }
                if (selected.isEmpty()) return
                busy = true
                status = "Orijinaller uygulama içine kopyalanıyor…"
                io.execute {
                    val imported = mutableListOf<ScanPage>()
                    var refused = 0
                    for (uri in selected.take(MAX_PAGES - pages.size)) {
                        try { imported.add(copyPrivate(uri)) }
                        catch (_: Exception) { refused++ }
                    }
                    runOnUiThread {
                        pages.addAll(imported)
                        persistOrder()
                        busy = false
                        status = "${imported.size} sayfa eklendi, $refused reddedildi"
                    }
                }
            }
            REQUEST_PDF -> data.data?.let { destination ->
                busy = true
                status = "PDF hazırlanıyor; SAF sağlayıcısına yazım atomik değildir…"
                val snapshot = pages.toList()
                io.execute {
                    var staged: File? = null
                    var cleanupFailed = false
                    val result = try {
                        staged = PrivatePdfStageCache.create(cacheDir)
                        // Real native PdfRenderer rasterizes each staged A4
                        // page before any SAF provider target is touched.
                        val stagedRaster = createAndValidatePdf(snapshot, staged)
                        // ACTION_CREATE_DOCUMENT only. Use explicit truncate mode
                        // ("wt"), then CLOSE before reopening the provider bytes.
                        // "w" is provider-dependent and may leave trailing bytes.
                        val receipt = VerifiedSafPdfTransfer.copyAndVerify(
                            staged = staged,
                            openTarget = { contentResolver.openOutputStream(destination, "wt") },
                            reopenTarget = { contentResolver.openInputStream(destination) }
                        )
                        // A matching hash is necessary but not the final
                        // validation: reopen the TARGET through PdfRenderer.
                        // Some SAF providers return nonseekable file descriptors;
                        // fail closed rather than claim a valid document.
                        val descriptor = contentResolver.openFileDescriptor(destination, "r")
                            ?: throw IOException("SAF PDF yeniden açılamıyor")
                        // The target must open and rasterize EVERY A4 page
                        // with the same native renderer, not merely parse
                        // its page count. Compare page-indexed low-res ARGB
                        // digests of staged and provider-backed renderings.
                        val targetRaster = PdfRasterGate.verify(descriptor, snapshot.size)
                        if (targetRaster != stagedRaster)
                            throw IOException("SAF PDF raster pikselleri uyuşmuyor")
                        "PDF doğrulandı (${snapshot.size} A4 sayfa; ${receipt.bytes} bayt; " +
                            "SHA-256 ve raster eşleşti). SAF atomik kayıt garantisi yok."
                    } catch (e: Exception) {
                        // SAF may expose partially written bytes on crash/denial.
                        // Never delete/overwrite a possibly preexisting provider
                        // URI automatically: it could contain user content.
                        "PDF hedef doğrulaması başarısız: ${e.javaClass.simpleName}. " +
                            "SAF hedefinde eksik dosya bulunabilir; dosyayı kontrol edin."
                    } finally {
                        staged?.let { file ->
                            try { PrivatePdfStageCache.finish(cacheDir, file) }
                            catch (_: Exception) { cleanupFailed = true }
                        }
                    }
                    runOnUiThread {
                        status = if (cleanupFailed)
                            "$result Özel PDF geçici dosyası temizlenemedi."
                            else result
                        busy = false
                    }
                }
            }
        }
    }

    private fun copyPrivate(uri: Uri): ScanPage {
        if (pages.size >= MAX_PAGES) throw IOException("Sayfa sınırı")
        val descriptor = contentResolver.openAssetFileDescriptor(uri, "r")
            ?: throw IOException("Görsel bulunamadı")
        descriptor.use {
            if (it.length > MAX_BYTES) throw IOException("Dosya boyutu sınırı")
        }
        val temp = File.createTempFile("in-", ".pending", assets)
        val digest = MessageDigest.getInstance("SHA-256")
        var saved: File? = null
        try {
            var bytes = 0L
            contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(temp).use { output ->
                    val buffer = ByteArray(65536)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        bytes += count
                        if (bytes > MAX_BYTES) throw IOException("64MiB dosya sınırı")
                        digest.update(buffer, 0, count)
                        output.write(buffer, 0, count)
                    }
                    output.fd.sync()
                }
            } ?: throw IOException("Görsel okunamadı")
            val ext = sniffExtension(temp) ?: throw IOException("PNG/JPEG dışındaki dosya")
            val name = UUID.randomUUID().toString()
            saved = File(assets, "$name.$ext")
            Files.move(temp.toPath(), saved.toPath(), StandardCopyOption.ATOMIC_MOVE)
            return ScanPage(name, ext, digest.digest().toHex(), saved, thumbnail(saved))
        } catch (e: Exception) {
            saved?.delete()
            throw e
        } finally { temp.delete() }
    }

    private fun sniffExtension(file: File): String? {
        val bytes = file.inputStream().use { stream ->
            ByteArray(8).also { stream.read(it) }
        }
        return when {
            bytes[0] == 0xFF.toByte() && bytes[1] == 0xD8.toByte() -> "jpg"
            bytes.contentEquals(byteArrayOf(137.toByte(),80,78,71,13,10,26,10)) -> "png"
            else -> null
        }
    }

    private fun thumbnail(file: File): Bitmap = decodeBounded(file, 480)

    /**
     * Export-only decode; unlike the preview's 2400px limit this preserves
     * 12MP and eligible <=24MP sources without resampling. JPEG EXIF geometry
     * is normalized before crop/rotation on the working pixels; original asset
     * stays untouched. Above 24MP a power-of-two sample may be required.
     * Reject before bitmap allocation if the process heap cannot hold both
     * decode + projective output + scratch; never fall back silently to 2400px.
     */
    private fun decodeForExport(file: File, quad: PageQuadRecipe): Bitmap {
        val orientation = ExifBitmapNormalizer.read(file)
        val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, opts)
        if (opts.outWidth <= 0 || opts.outHeight <= 0 ||
            opts.outWidth.toLong() * opts.outHeight > 100_000_000L)
            throw IOException("PDF görsel geometrisi sınırı")
        var sample = 1
        while (opts.outWidth.toLong() / sample * (opts.outHeight / sample) > 24_000_000L ||
            maxOf(opts.outWidth, opts.outHeight) / sample > 8000) {
            sample *= 2
        }
        val plannedWidth = maxOf(1, opts.outWidth / sample)
        val plannedHeight = maxOf(1, opts.outHeight / sample)
        val (orientedWidth, orientedHeight) =
            orientation.outputSize(plannedWidth, plannedHeight)
        val projected = if (quad.isFullFrame) 0L
                        else CropOutputPlan.measure(orientedWidth, orientedHeight, quad)
                            .let { it.width.toLong() * it.height }
        val decodeBytes = plannedWidth.toLong() * plannedHeight * 4
        // JPEG EXIF tag 2..8 creates a second ARGB bitmap; reserve both
        // buffers BEFORE decoding. In-memory PDF page allocation is additional.
        val orientedBytes = if (orientation.tag == 1) 0L else decodeBytes
        val estimatedPeak = decodeBytes + orientedBytes + projected * 4 +
                            24L * 1024 * 1024
        val runtime = Runtime.getRuntime()
        val headroom = runtime.maxMemory() - (runtime.totalMemory() - runtime.freeMemory())
        if (estimatedPeak > headroom)
            throw IOException("PDF kırpma için kullanılabilir bellek yetersiz")
        opts.inJustDecodeBounds = false
        opts.inPreferredConfig = Bitmap.Config.ARGB_8888
        opts.inScaled = false
        opts.inSampleSize = sample
        val bitmap = BitmapFactory.decodeFile(file.absolutePath, opts)
            ?: throw IOException("PDF görseli çözümlenemedi")
        if (bitmap.width.toLong() * bitmap.height > 24_000_000L ||
            maxOf(bitmap.width, bitmap.height) > 8000) {
            bitmap.recycle()
            throw IOException("Çözümlenen görüntü kaynak sınırı")
        }
        return try {
            val oriented = ExifBitmapNormalizer.apply(bitmap, orientation)
            if (oriented !== bitmap) bitmap.recycle()
            oriented
        } catch (error: Exception) {
            bitmap.recycle()
            throw error
        }
    }

    private fun decodeBounded(file: File, largestEdge: Int): Bitmap {
        val orientation = ExifBitmapNormalizer.read(file)
        val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, opts)
        if (opts.outWidth <= 0 || opts.outHeight <= 0 ||
            opts.outWidth.toLong() * opts.outHeight.toLong() > 100_000_000L)
            throw IOException("Görsel geometrisi reddedildi")
        var sample = 1
        while (opts.outWidth / sample > largestEdge * 2 ||
            opts.outHeight / sample > largestEdge * 2) sample *= 2
        opts.inJustDecodeBounds = false
        opts.inSampleSize = sample
        opts.inScaled = false
        val raw = BitmapFactory.decodeFile(file.absolutePath, opts)
            ?: throw IOException("Görsel çözümlenemedi")
        return try {
            val oriented = ExifBitmapNormalizer.apply(raw, orientation)
            if (oriented !== raw) raw.recycle()
            oriented
        } catch (error: Exception) {
            raw.recycle()
            throw error
        }
    }

    private fun createAndValidatePdf(
        snapshot: List<ScanPage>, stage: File
    ): PdfRasterGate.Receipt {
        if (snapshot.isEmpty()) throw IOException("Boş belge")
        val pdf = PdfDocument()
        try {
            for ((index, image) in snapshot.withIndex()) {
                if (digestFile(image.file) != image.sha256)
                    throw IOException("Orijinal değişti")
                if (!PageRotationRecipe.isValid(image.rotationDegrees))
                    throw IOException("Geçersiz döndürme açısı")
                val original = decodeForExport(image.file, image.quad)
                val bitmap = try {
                    if (image.quad.isFullFrame) original
                    else PagePerspective.warp(original, image.quad)
                } catch (error: Exception) {
                    original.recycle()
                    throw error
                }
                try {
                    val page = pdf.startPage(
                        PdfDocument.PageInfo.Builder(595, 842, index + 1).create()
                    )
                    page.canvas.drawColor(Color.WHITE)
                    // A4 orientation is stable; only the drawing recipe rotates.
                    // The immutable original PNG/JPEG bytes never change.
                    val quarter = image.rotationDegrees % 180 != 0
                    val orientedWidth = if (quarter) bitmap.height else bitmap.width
                    val orientedHeight = if (quarter) bitmap.width else bitmap.height
                    val scale = minOf(555f / orientedWidth, 802f / orientedHeight)
                    val outWidth = orientedWidth * scale
                    val outHeight = orientedHeight * scale
                    val canvas = page.canvas
                    canvas.save()
                    canvas.translate((595f - outWidth) / 2f, (842f - outHeight) / 2f)
                    when (image.rotationDegrees) {
                        90 -> { canvas.translate(outWidth, 0f); canvas.rotate(90f) }
                        180 -> { canvas.translate(outWidth, outHeight); canvas.rotate(180f) }
                        270 -> { canvas.translate(0f, outHeight); canvas.rotate(270f) }
                    }
                    canvas.drawBitmap(
                        bitmap, null, RectF(0f, 0f, bitmap.width * scale, bitmap.height * scale),
                        Paint(Paint.FILTER_BITMAP_FLAG)
                    )
                    canvas.restore()
                    pdf.finishPage(page)
                } finally {
                    if (bitmap !== original) bitmap.recycle()
                    original.recycle()
                }
            }
            FileOutputStream(stage).use { pdf.writeTo(it); it.fd.sync() }
        } finally { pdf.close() }
        // Independent native render/readback of each staged page:
        // geometry + bounded actual raster pixels, in ordered SHA-256.
        return PdfRasterGate.verify(
            ParcelFileDescriptor.open(stage, ParcelFileDescriptor.MODE_READ_ONLY),
            snapshot.size
        )
    }

    private fun setQuad(id: String, quad: PageQuadRecipe) {
        if (busy) return
        val index = pages.indexOfFirst { it.id == id }
        if (index < 0) return
        pages[index] = pages[index].copy(quad = quad)
        persistOrder()
        status = if (quad.isFullFrame) "Sayfa ${index + 1}: kırpma sıfırlandı"
                 else "Sayfa ${index + 1}: 4 köşe kaydedildi; orijinal korunuyor"
    }

    @Composable
    private fun QuadDialog(page: ScanPage, onCancel: () -> Unit,
                           onApply: (PageQuadRecipe) -> Unit) {
        var draft by remember(page.id) { mutableStateOf(page.quad) }
        Dialog(onDismissRequest = onCancel) {
            Surface(shape = RoundedCornerShape(16.dp)) {
                Column(Modifier.fillMaxWidth().padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Manuel 4-köşe kırpma", style = MaterialTheme.typography.titleLarge)
                    Text("Mavi köşeleri sürükleyin. Geçersiz/katlanmış alanlar reddedilir.",
                        style = MaterialTheme.typography.bodySmall)
                    Box(Modifier.fillMaxWidth().height(340.dp)) {
                        Image(page.thumbnail.asImageBitmap(),
                            contentDescription = "Orijinal görsel üzerinde 4-köşe alanı",
                            modifier = Modifier.matchParentSize(), contentScale = ContentScale.Fit)
                        Canvas(Modifier.matchParentSize().pointerInput(page.id) {
                            var active = -1
                            fun imageMetrics(): FloatArray {
                                val scale = min(size.width.toFloat() / page.thumbnail.width,
                                    size.height.toFloat() / page.thumbnail.height)
                                val w = page.thumbnail.width * scale
                                val h = page.thumbnail.height * scale
                                return floatArrayOf((size.width - w) / 2f,
                                    (size.height - h) / 2f, w, h)
                            }
                            detectDragGestures(
                                onDragStart = { position ->
                                    val m = imageMetrics()
                                    active = (0..3).minByOrNull { i ->
                                        val dx = position.x - m[0] - draft.x(i) * m[2]
                                        val dy = position.y - m[1] - draft.y(i) * m[3]
                                        dx * dx + dy * dy
                                    } ?: -1
                                    if (active >= 0) {
                                        val dx = position.x - m[0] - draft.x(active) * m[2]
                                        val dy = position.y - m[1] - draft.y(active) * m[3]
                                        if (dx * dx + dy * dy > 48f * 48f) active = -1
                                    }
                                },
                                onDragEnd = { active = -1 },
                                onDragCancel = { active = -1 }
                            ) { change, _ ->
                                if (active >= 0) {
                                    val m = imageMetrics()
                                    val x = (((change.position.x - m[0]) / m[2]) * 1000f)
                                        .roundToInt()
                                    val y = (((change.position.y - m[1]) / m[3]) * 1000f)
                                        .roundToInt()
                                    draft.moved(active, x, y)?.let { draft = it }
                                    change.consume()
                                }
                            }
                        }) {
                            val scale = min(size.width / page.thumbnail.width,
                                size.height / page.thumbnail.height)
                            val width = page.thumbnail.width * scale
                            val height = page.thumbnail.height * scale
                            val left = (size.width - width) / 2f
                            val top = (size.height - height) / 2f
                            fun p(i: Int) = Offset(left + draft.x(i) * width,
                                                    top + draft.y(i) * height)
                            for (i in 0..3) {
                                drawLine(UiColor.Cyan, p(i), p((i + 1) % 4), strokeWidth = 4f)
                                drawCircle(UiColor(0xFF0284C7), radius = 12f, center = p(i))
                                drawCircle(UiColor.White, radius = 5f, center = p(i))
                            }
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { draft = PageQuadRecipe.FULL }) {
                            Text("Sıfırla")
                        }
                        OutlinedButton(onClick = onCancel) { Text("İptal") }
                        Button(onClick = { onApply(draft) }) { Text("Uygula") }
                    }
                }
            }
        }
    }

    private fun movePage(from: Int, to: Int) {
        pages.add(to, pages.removeAt(from))
        persistOrder()
        status = "Sayfa sırası güncellendi"
    }

    private fun rotatePage(index: Int) {
        if (busy || index !in pages.indices) return
        val current = pages[index]
        pages[index] = current.copy(
            rotationDegrees = PageRotationRecipe.clockwise(current.rotationDegrees))
        persistOrder()
        status = "Sayfa ${index + 1}: ${pages[index].rotationDegrees}° saat yönünde"
    }

    private fun resetRotation(index: Int) {
        if (busy || index !in pages.indices) return
        pages[index] = pages[index].copy(rotationDegrees = PageRotationRecipe.reset())
        persistOrder()
        status = "Sayfa ${index + 1}: orijinal yön"
    }

    private fun removePage(index: Int) {
        val removed = pages.removeAt(index)
        removed.file.delete()
        persistOrder()
        status = "Sayfa silindi"
    }

    private fun persistOrder() {
        val manifest = pages.joinToString("\n") {
            "${it.id}.${it.extension}:${it.sha256}:${it.rotationDegrees}:${it.quad.encode()}"
        }
        preferences.edit().putString("order", manifest).apply()
    }

    private fun digestFile(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(65536)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                md.update(buffer, 0, n)
            }
        }
        return md.digest().toHex()
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it.toInt() and 255) }

    override fun onDestroy() {
        io.shutdown()
        super.onDestroy()
    }

    private companion object {
        const val REQUEST_IMPORT = 101
        const val REQUEST_PDF = 102
        const val MAX_PAGES = 100
        const val MAX_BYTES = 64L * 1024L * 1024L
    }
}
