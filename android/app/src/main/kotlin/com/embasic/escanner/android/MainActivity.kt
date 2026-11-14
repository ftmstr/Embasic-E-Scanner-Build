package com.embasic.escanner.android

import android.app.Activity
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.pdf.PdfDocument
import android.graphics.pdf.PdfRenderer
import android.net.Uri
import android.os.Bundle
import android.os.ParcelFileDescriptor
import androidx.compose.foundation.Image
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
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

/**
 * Initial usable local-first scanning WORKSPACE: import immutable private copies,
 * preview, reorder, remove and export a raster A4 PDF using platform APIs.
 * Not camera capture, perspective correction, OCR or a signed release.
 */
class MainActivity : Activity() {
    private data class ScanPage(
        val id: String, val extension: String, val sha256: String,
        val file: File, val thumbnail: Bitmap
    )

    private val pages = mutableStateListOf<ScanPage>()
    private val io = Executors.newSingleThreadExecutor()
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
                                                .background(MaterialTheme.colorScheme.surfaceVariant,
                                                    RoundedCornerShape(8.dp)),
                                            contentScale = ContentScale.Fit
                                        )
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text("Sayfa ${index + 1}", style = MaterialTheme.typography.titleMedium)
                                            Text(page.extension.uppercase() + " · " +
                                                (page.file.length() / 1024) + " KB",
                                                style = MaterialTheme.typography.bodySmall)
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
                                        }
                                    }
                                }
                            }
                        }
                        Text("PDF: A4 sayfaları. OCR/kırpma henüz yok. SAF hedefe " +
                            "yazım atomik değildir.", style = MaterialTheme.typography.labelSmall)
                    }
                }
            } }
        })
        io.execute {
            val restored = mutableListOf<ScanPage>()
            var invalid = 0
            for (entry in preferences.getString("order", "").orEmpty().lines()) {
                val parts = entry.split(':')
                if (parts.size != 2 || !parts[0].matches(Regex("[0-9a-fA-F-]{36}\\.(jpg|png)")) ||
                    !parts[1].matches(Regex("[0-9a-f]{64}"))) continue
                val source = File(assets, parts[0])
                try {
                    if (source.isFile && source.length() in 1..MAX_BYTES &&
                        digestFile(source) == parts[1]) {
                        restored.add(ScanPage(
                            parts[0].substringBefore('.'), parts[0].substringAfterLast('.'),
                            parts[1], source, thumbnail(source)
                        ))
                    } else invalid++
                } catch (_: Exception) { invalid++ }
            }
            runOnUiThread {
                pages.addAll(restored.take(MAX_PAGES))
                busy = false
                status = if (invalid > 0) "$invalid bozuk/eksik kaynak reddedildi"
                         else "${pages.size} sayfa hazır"
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
                status = "PDF geçici dosyada oluşturuluyor ve doğrulanıyor…"
                val snapshot = pages.toList()
                io.execute {
                    var staged: File? = null
                    val result = try {
                        staged = File.createTempFile("escanner-pdf-", ".tmp", cacheDir)
                        createAndValidatePdf(snapshot, staged)
                        contentResolver.openOutputStream(destination, "w")?.use { output ->
                            staged.inputStream().use { it.copyTo(output) }
                            output.flush()
                        } ?: throw IOException("Hedef belge açılamıyor")
                        "PDF kaydedildi (${snapshot.size} sayfa)."
                    } catch (e: Exception) {
                        "PDF kaydedilemedi: ${e.javaClass.simpleName}. Hedefte eksik dosya kalabilir."
                    } finally { staged?.delete() }
                    runOnUiThread { status = result; busy = false }
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

    private fun decodeBounded(file: File, largestEdge: Int): Bitmap {
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
        return BitmapFactory.decodeFile(file.absolutePath, opts)
            ?: throw IOException("Görsel çözümlenemedi")
    }

    private fun createAndValidatePdf(snapshot: List<ScanPage>, stage: File) {
        if (snapshot.isEmpty()) throw IOException("Boş belge")
        val pdf = PdfDocument()
        try {
            for ((index, image) in snapshot.withIndex()) {
                if (digestFile(image.file) != image.sha256)
                    throw IOException("Orijinal değişti")
                val bitmap = decodeBounded(image.file, 2400)
                try {
                    val page = pdf.startPage(
                        PdfDocument.PageInfo.Builder(595, 842, index + 1).create()
                    )
                    page.canvas.drawColor(Color.WHITE)
                    val scale = minOf(555f / bitmap.width, 802f / bitmap.height)
                    val width = (bitmap.width * scale).toInt()
                    val height = (bitmap.height * scale).toInt()
                    val left = (595 - width) / 2
                    val top = (842 - height) / 2
                    page.canvas.drawBitmap(
                        bitmap, null, Rect(left, top, left + width, top + height),
                        Paint(Paint.FILTER_BITMAP_FLAG)
                    )
                    pdf.finishPage(page)
                } finally { bitmap.recycle() }
            }
            FileOutputStream(stage).use { pdf.writeTo(it); it.fd.sync() }
        } finally { pdf.close() }
        ParcelFileDescriptor.open(stage, ParcelFileDescriptor.MODE_READ_ONLY).use { fd ->
            PdfRenderer(fd).use { renderer ->
                if (renderer.pageCount != snapshot.size)
                    throw IOException("PDF sayfa sayısı uyuşmuyor")
            }
        }
    }

    private fun movePage(from: Int, to: Int) {
        pages.add(to, pages.removeAt(from))
        persistOrder()
        status = "Sayfa sırası güncellendi"
    }

    private fun removePage(index: Int) {
        val removed = pages.removeAt(index)
        removed.file.delete()
        persistOrder()
        status = "Sayfa silindi"
    }

    private fun persistOrder() {
        val manifest = pages.joinToString("\n") {
            "${it.id}.${it.extension}:${it.sha256}"
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
