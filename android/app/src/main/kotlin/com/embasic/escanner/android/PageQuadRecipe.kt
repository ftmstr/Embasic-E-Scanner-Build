package com.embasic.escanner.android

/**
 * Immutable, normalized manual document quad in ORIGINAL (unrotated) image space.
 * Point order: top-left, top-right, bottom-right, bottom-left. Integer 0..1000
 * avoids locale/float persistence drift across Android and Windows.
 * Reject folded, self-intersecting, tiny or non-canonical persisted polygons.
 */
internal data class PageQuadRecipe private constructor(val coordinates: List<Int>) {
    fun encode(): String = (0..3).joinToString(";") { i ->
        "${coordinates[i * 2]},${coordinates[i * 2 + 1]}"
    }
    fun x(i: Int): Float = coordinates[i * 2] / 1000f
    fun y(i: Int): Float = coordinates[i * 2 + 1] / 1000f
    val isFullFrame: Boolean get() = this == FULL

    fun moved(corner: Int, x: Int, y: Int): PageQuadRecipe? {
        if (corner !in 0..3) return null
        val changed = coordinates.toMutableList()
        changed[corner * 2] = x.coerceIn(0, 1000)
        changed[corner * 2 + 1] = y.coerceIn(0, 1000)
        return if (valid(changed)) PageQuadRecipe(changed) else null
    }

    companion object {
        val FULL: PageQuadRecipe = PageQuadRecipe(listOf(0, 0, 1000, 0, 1000, 1000, 0, 1000))
        val INSET: PageQuadRecipe = PageQuadRecipe(listOf(80, 80, 920, 80, 920, 920, 80, 920))

        fun parse(field: String?): PageQuadRecipe? {
            if (field == null) return FULL // legacy two/three-column rows
            val pairs = field.split(';')
            if (pairs.size != 4) return null
            val values = ArrayList<Int>(8)
            for (pair in pairs) {
                val items = pair.split(',')
                if (items.size != 2) return null
                for (item in items) {
                    val n = item.toIntOrNull() ?: return null
                    if (n !in 0..1000 || item != n.toString()) return null
                    values.add(n)
                }
            }
            if (!valid(values)) return null
            return PageQuadRecipe(values)
        }

        private fun valid(a: List<Int>): Boolean {
            if (a.size != 8 || a.any { it !in 0..1000 }) return false
            var area2 = 0L
            for (i in 0..3) {
                val j = (i + 1) % 4
                val x = a[i * 2].toLong()
                val y = a[i * 2 + 1].toLong()
                val nextX = a[j * 2].toLong()
                val nextY = a[j * 2 + 1].toLong()
                area2 += x * nextY - nextX * y
                val k = (i + 2) % 4
                val ex = nextX - x
                val ey = nextY - y
                val fx = a[k * 2].toLong() - nextX
                val fy = a[k * 2 + 1].toLong() - nextY
                if (ex * fy - ey * fx <= 0L || ex * ex + ey * ey < 400L)
                    return false
            }
            return area2 >= 100_000L // >= 5% original canvas area
        }
    }
}
