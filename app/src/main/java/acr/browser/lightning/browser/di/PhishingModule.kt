package acr.browser.lightning.di

import acr.browser.lightning.phishing.PhishingDetector
import acr.browser.lightning.phishing.ScanCounter
import android.app.Application
import dagger.Module
import dagger.Provides
import javax.inject.Singleton

@Module
class PhishingModule {

    @Provides
    @Singleton
    fun provideScanCounter(application: Application): ScanCounter = ScanCounter(application)

    @Provides
    @Singleton
    fun providePhishingDetector(
        application: Application,
        scanCounter: ScanCounter
    ): PhishingDetector = PhishingDetector(application, scanCounter)
}