package acr.browser.lightning.phishing

import android.annotation.SuppressLint
import android.content.Context
import android.util.JsonReader
import android.util.Log
import org.tensorflow.lite.Interpreter
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class PhishingDetector @Inject constructor(
    private val context: Context,
    private val scanCounter: ScanCounter
) {
    private var interpreter: Interpreter? = null
    private var tokenizer: MutableMap<String, Int>? = null
    private val maxSequenceLength = 500
    private var modelVersion = 1.0F

    private companion object {
        const val TAG = "PhishingDetector"
        const val INFER_KEY = "infer"
        const val INFER_INPUT_NAME = "infer_input"
        const val INFER_OUTPUT_NAME = "infer_output"
    }

    init {
        initModel()
    }

    @SuppressLint("LogConditional")
    fun initModel() {
        try {
            // Model yükleme
            loadModelFromAssets()

            // Tokenizer yükleme
            loadTokenizerInChunks()

            Log.d(TAG, "Model başarıyla başlatıldı, sürüm: $modelVersion")
        } catch (e: Exception) {
            Log.e(TAG, "Model başlatılamadı", e)
        }
    }

    @SuppressLint("LogConditional")
    private fun loadModelFromAssets() {
        try {
            val options = Interpreter.Options().apply {
                setUseNNAPI(false)
            }

            // Assets'ten modeli yükle
            context.assets.openFd("federated_model.tflite").use { fd ->
                interpreter = Interpreter(
                    FileInputStream(fd.fileDescriptor).channel.map(
                        FileChannel.MapMode.READ_ONLY,
                        fd.startOffset,
                        fd.declaredLength
                    ),
                    options
                )
            }

            // Temel sürüme sıfırla
            modelVersion = 1.0f

            Log.d(TAG, "Model assets'ten başarıyla yüklendi")
        } catch (e: Exception) {
            Log.e(TAG, "Assets'ten model yükleme başarısız oldu", e)
            throw RuntimeException("Model yükleme başarısız: ${e.message}")
        }
    }

    @SuppressLint("LogConditional")
    private fun loadTokenizerInChunks() {
        tokenizer = mutableMapOf()
        try {
            // JSON okuyucu ile tokenizer yükleme
            context.assets.open("tokenizer_config.json").use { inputStream ->
                val reader = JsonReader(InputStreamReader(inputStream, "UTF-8"))

                // JSON yapısını okumaya başla
                reader.beginObject()
                while (reader.hasNext()) {
                    val name = reader.nextName()
                    if (name == "word_index") {
                        reader.beginObject()

                        // word_index girdilerini tek tek işle
                        var count = 0
                        while (reader.hasNext()) {
                            val word = reader.nextName()
                            val index = reader.nextInt()
                            tokenizer!![word] = index
                            count++
                        }
                        reader.endObject()
                    } else {
                        reader.skipValue()
                    }
                }
                reader.endObject()
            }
            Log.d(TAG, "Tokenizer yüklendi: ${tokenizer?.size} token")
        } catch (e: Exception) {
            Log.e(TAG, "Tokenizer yüklenemedi", e)
            tokenizer = mutableMapOf()
        }
    }

    /**
     * HTML içeriğini model girdisi için hazırlar
     */
    fun preprocessHtml(htmlContent: String?): IntArray {
        // Null içeriği işle
        val text = htmlContent ?: ""

        // Küçük harfe dönüştür
        val lowercaseText = text.lowercase()

        // Karakter filtreleme
        var filteredText = lowercaseText
        val specialChars = "!\"#$%&()*+,-./:;<=>?@[]\\^_`{|}~\t\n"
        for (char in specialChars) {
            filteredText = filteredText.replace(char.toString(), " ")
        }

        // Fazla boşlukları temizle
        val cleanText = filteredText.split("\\s+".toRegex())
            .filter { it.isNotEmpty() }
            .joinToString(" ")

        val tokens = tokenizeText(cleanText)
        return padSequence(tokens)
    }

    private fun tokenizeText(text: String): List<Int> {
        return text.split(" ").map { word ->
            val tokenId = tokenizer?.get(word)
            val oovTokenId = tokenizer?.get("<OOV>")

            when {
                tokenId != null -> tokenId
                oovTokenId != null -> oovTokenId
                else -> 1 // Fallback
            }
        }
    }

    /**
     * Token dizilerini gerekli sabit uzunluğa doldurur veya keser
     */
    private fun padSequence(tokens: List<Int>): IntArray {
        return IntArray(maxSequenceLength) { index ->
            if (index < tokens.size) tokens[index] else 0
        }
    }

    @SuppressLint("LogConditional")
    fun predict(input: IntArray): Float {
        try {
            require(input.size == 500) {
                "Geçersiz girdi boyutu: ${input.size}. Tam olarak 500 eleman olmalı."
            }

            val inputArray = Array(1) { input }
            val outputs = mutableMapOf<String, Any>()

            // Çıktı için float array oluştur
            val outputArray = Array(1) { FloatArray(1) }
            outputs[INFER_OUTPUT_NAME] = outputArray

            interpreter?.runSignature(
                mapOf(INFER_INPUT_NAME to inputArray),
                outputs,
                INFER_KEY
            ) ?: throw Exception("Interpreter null")

            // Çıktıyı kontrol et ve döndür
            val output = outputs["infer_output"] as? Array<*>
                ?: throw Exception("Geçersiz çıktı formatı")

            return (output[0] as FloatArray)[0]

        } catch (e: Exception) {
            Log.e(TAG, "Tahmin başarısız oldu", e)
            throw e
        }
    }

    /**
     * URL'nin phishing olup olmadığını tespit eder
     */
    fun isPhishing(htmlContent: String?): Boolean {
        return try {
            // HTML içeriğini model için hazırla
            val processedInput = preprocessHtml(htmlContent)

            // Modeli çalıştır ve tahmini al
            val predictionScore = predict(processedInput)

            // Tarama sayacını artır
            scanCounter.incrementScanCount()

            // 0.6'dan büyükse phishing olarak işaretle
            predictionScore > 0.6f
        } catch (e: Exception) {
            Log.e(TAG, "Phishing tespiti sırasında hata oluştu", e)
            false // Hata durumunda güvenli olarak kabul et
        }
    }

    /**
     * URL'yi analiz edip phishing skorunu ve phishing durumunu döndürür
     */
    fun analyzeForPhishing(htmlContent: String?): Pair<Boolean, Float> {
        return try {
            // HTML içeriğini model için hazırla
            val processedInput = preprocessHtml(htmlContent)

            // Modeli çalıştır ve tahmini al
            val predictionScore = predict(processedInput)
            println("Prediction Score: $predictionScore")

            // Tarama sayacını artır
            scanCounter.incrementScanCount()

            // 0.6'dan büyükse phishing olarak işaretle ve skoru döndür
            (predictionScore > 0.6f) to predictionScore
        } catch (e: Exception) {
            Log.e(TAG, "Phishing tespiti sırasında hata oluştu", e)
            false to 0.0f // Hata durumunda güvenli olarak kabul et
        }
    }

    fun close() {
        try {
            interpreter?.close()
            interpreter = null
            tokenizer?.clear()
            tokenizer = null
            System.gc()
        } catch (e: Exception) {
            Log.e(TAG, "Kapatma hatası", e)
        }
    }
}