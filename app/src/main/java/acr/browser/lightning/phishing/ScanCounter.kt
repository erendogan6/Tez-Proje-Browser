package acr.browser.lightning.phishing

import android.content.Context
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ScanCounter @Inject constructor(
    private val context: Context
) {
    private val prefs = context.getSharedPreferences("PhishingDetectorPrefs", Context.MODE_PRIVATE)

    // Toplam tarama sayısı
    private var totalScanCount: Int = prefs.getInt("totalScanCount", 0)
        set(value) {
            field = value
            prefs.edit().putInt("totalScanCount", value).apply()
        }

    // Tarama sayacını artır
    fun incrementScanCount() {
        totalScanCount++
    }

    // Toplam tarama sayısını al
    fun getTotalScanCount(): Int = totalScanCount
}