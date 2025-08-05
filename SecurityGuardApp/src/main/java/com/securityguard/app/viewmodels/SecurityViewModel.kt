package com.securityguard.app.viewmodels

import android.app.Application
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.*
import com.securityguard.app.SecurityStatus
import com.securityguard.app.SecurityThreat

class SecurityViewModel(application: Application) : AndroidViewModel(application) {

    private val _securityStatus = MutableStateFlow(SecurityStatus())
    val securityStatus: StateFlow<SecurityStatus> = _securityStatus.asStateFlow()

    private val _recentThreats = MutableStateFlow<List<SecurityThreat>>(emptyList())
    val recentThreats: StateFlow<List<SecurityThreat>> = _recentThreats.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _networkConnections = MutableStateFlow<List<NetworkConnection>>(emptyList())
    val networkConnections: StateFlow<List<NetworkConnection>> = _networkConnections.asStateFlow()

    private val _suspiciousApps = MutableStateFlow<List<SuspiciousApp>>(emptyList())
    val suspiciousApps: StateFlow<List<SuspiciousApp>> = _suspiciousApps.asStateFlow()

    private val _intruderDetectionEnabled = MutableStateFlow(false)
    val intruderDetectionEnabled: StateFlow<Boolean> = _intruderDetectionEnabled.asStateFlow()

    private val context = getApplication<Application>()
    private val packageManager = context.packageManager

    // Suspicious app signatures and behaviors
    private val malwareSignatures = listOf(
        "com.android.systemui.hack", 
        "com.spy.app", 
        "keylogger",
        "com.android.spyware",
        "stalkerware",
        "com.malware.app"
    )

    private val suspiciousPermissions = listOf(
        android.Manifest.permission.READ_SMS,
        android.Manifest.permission.RECORD_AUDIO,
        android.Manifest.permission.ACCESS_FINE_LOCATION,
        android.Manifest.permission.CAMERA,
        android.Manifest.permission.READ_CONTACTS,
        android.Manifest.permission.READ_CALL_LOG
    )

    init {
        performInitialSecurityCheck()
    }

    private fun performInitialSecurityCheck() {
        viewModelScope.launch {
            scanForThreats()
            monitorNetworkConnections()
            checkAppPermissions()
        }
    }

    fun scanForThreats() {
        viewModelScope.launch {
            _isScanning.value = true
            
            try {
                val threats = mutableListOf<SecurityThreat>()
                
                // Scan installed apps for suspicious behavior
                val suspiciousApps = scanInstalledApps()
                threats.addAll(suspiciousApps.map { app ->
                    SecurityThreat(
                        type = "Suspicious App",
                        description = "App '${app.name}' has suspicious permissions: ${app.riskyPermissions.joinToString()}",
                        timestamp = getCurrentTimestamp(),
                        severity = app.riskLevel
                    )
                })

                // Check for rooting/jailbreaking
                if (isDeviceRooted()) {
                    threats.add(
                        SecurityThreat(
                            type = "Rooted Device",
                            description = "Device appears to be rooted, which may compromise security",
                            timestamp = getCurrentTimestamp(),
                            severity = "High"
                        )
                    )
                }

                // Check for debugging
                if (isDebuggingEnabled()) {
                    threats.add(
                        SecurityThreat(
                            type = "Debug Mode",
                            description = "USB debugging is enabled, which may allow unauthorized access",
                            timestamp = getCurrentTimestamp(),
                            severity = "Medium"
                        )
                    )
                }

                // Check for unknown sources
                if (isUnknownSourcesEnabled()) {
                    threats.add(
                        SecurityThreat(
                            type = "Unknown Sources",
                            description = "Installation from unknown sources is enabled",
                            timestamp = getCurrentTimestamp(),
                            severity = "Medium"
                        )
                    )
                }

                // Update security status
                _recentThreats.value = threats
                _securityStatus.value = SecurityStatus(
                    isSecure = threats.isEmpty(),
                    lastScanTime = getCurrentTimestamp(),
                    threatCount = threats.size
                )

            } catch (e: Exception) {
                // Handle scan errors
                _recentThreats.value = listOf(
                    SecurityThreat(
                        type = "Scan Error",
                        description = "Error occurred during security scan: ${e.message}",
                        timestamp = getCurrentTimestamp(),
                        severity = "Low"
                    )
                )
            } finally {
                _isScanning.value = false
            }
        }
    }

    private suspend fun scanInstalledApps(): List<SuspiciousApp> = withContext(Dispatchers.IO) {
        val suspiciousApps = mutableListOf<SuspiciousApp>()
        
        try {
            val installedApps = packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            
            for (appInfo in installedApps) {
                val packageName = appInfo.packageName
                val appName = packageManager.getApplicationLabel(appInfo).toString()
                
                // Skip system apps (optional - can be configured)
                if (appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0) {
                    continue
                }

                val riskyPermissions = checkAppPermissions(packageName)
                val suspiciousSignatures = checkForMalwareSignatures(packageName, appName)
                
                if (riskyPermissions.isNotEmpty() || suspiciousSignatures.isNotEmpty()) {
                    val riskLevel = when {
                        suspiciousSignatures.isNotEmpty() -> "Critical"
                        riskyPermissions.size > 3 -> "High"
                        riskyPermissions.size > 1 -> "Medium"
                        else -> "Low"
                    }
                    
                    suspiciousApps.add(
                        SuspiciousApp(
                            packageName = packageName,
                            name = appName,
                            riskyPermissions = riskyPermissions,
                            suspiciousSignatures = suspiciousSignatures,
                            riskLevel = riskLevel
                        )
                    )
                }
            }
        } catch (e: Exception) {
            // Log error
        }
        
        _suspiciousApps.value = suspiciousApps
        return@withContext suspiciousApps
    }

    private fun checkAppPermissions(packageName: String): List<String> {
        return try {
            val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            val requestedPermissions = packageInfo.requestedPermissions ?: emptyArray()
            
            requestedPermissions.filter { permission ->
                suspiciousPermissions.contains(permission)
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun checkForMalwareSignatures(packageName: String, appName: String): List<String> {
        val foundSignatures = mutableListOf<String>()
        
        malwareSignatures.forEach { signature ->
            if (packageName.contains(signature, ignoreCase = true) || 
                appName.contains(signature, ignoreCase = true)) {
                foundSignatures.add(signature)
            }
        }
        
        return foundSignatures
    }

    private fun isDeviceRooted(): Boolean {
        // Check for common root indicators
        val rootPaths = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        )

        return rootPaths.any { path ->
            try {
                java.io.File(path).exists()
            } catch (e: Exception) {
                false
            }
        }
    }

    private fun isDebuggingEnabled(): Boolean {
        return try {
            android.provider.Settings.Global.getInt(
                context.contentResolver,
                android.provider.Settings.Global.ADB_ENABLED,
                0
            ) == 1
        } catch (e: Exception) {
            false
        }
    }

    private fun isUnknownSourcesEnabled(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                packageManager.canRequestPackageInstalls()
            } else {
                @Suppress("DEPRECATION")
                android.provider.Settings.Secure.getInt(
                    context.contentResolver,
                    android.provider.Settings.Secure.INSTALL_NON_MARKET_APPS,
                    0
                ) == 1
            }
        } catch (e: Exception) {
            false
        }
    }

    fun monitorNetworkConnections() {
        viewModelScope.launch {
            val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val networks = connectivityManager.allNetworks
            val connections = mutableListOf<NetworkConnection>()

            for (network in networks) {
                val networkCapabilities = connectivityManager.getNetworkCapabilities(network)
                networkCapabilities?.let { capabilities ->
                    val networkInfo = connectivityManager.getNetworkInfo(network)
                    val connection = NetworkConnection(
                        networkId = network.toString(),
                        type = when {
                            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
                            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
                            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
                            else -> "Unknown"
                        },
                        isSecure = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
                        timestamp = getCurrentTimestamp()
                    )
                    connections.add(connection)
                }
            }

            _networkConnections.value = connections
        }
    }

    fun checkAppPermissions() {
        viewModelScope.launch {
            scanInstalledApps()
        }
    }

    fun enableIntruderDetection() {
        _intruderDetectionEnabled.value = true
        // Here you would implement camera activation for intruder detection
        // This could involve using CameraX to capture photos when unauthorized access is detected
    }

    fun disableIntruderDetection() {
        _intruderDetectionEnabled.value = false
    }

    private fun getCurrentTimestamp(): String {
        val formatter = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
        return formatter.format(Date())
    }

    // Method to clear threats (for testing or user action)
    fun clearThreats() {
        _recentThreats.value = emptyList()
        _securityStatus.value = SecurityStatus(
            isSecure = true,
            lastScanTime = getCurrentTimestamp(),
            threatCount = 0
        )
    }

    // Method to export security report
    fun generateSecurityReport(): SecurityReport {
        return SecurityReport(
            scanTime = getCurrentTimestamp(),
            deviceSecure = _securityStatus.value.isSecure,
            threatsFound = _recentThreats.value,
            suspiciousApps = _suspiciousApps.value,
            networkConnections = _networkConnections.value,
            deviceRooted = isDeviceRooted(),
            debuggingEnabled = isDebuggingEnabled(),
            unknownSourcesEnabled = isUnknownSourcesEnabled()
        )
    }
}

// Data classes for the ViewModel
data class SuspiciousApp(
    val packageName: String,
    val name: String,
    val riskyPermissions: List<String>,
    val suspiciousSignatures: List<String>,
    val riskLevel: String
)

data class NetworkConnection(
    val networkId: String,
    val type: String,
    val isSecure: Boolean,
    val timestamp: String
)

data class SecurityReport(
    val scanTime: String,
    val deviceSecure: Boolean,
    val threatsFound: List<SecurityThreat>,
    val suspiciousApps: List<SuspiciousApp>,
    val networkConnections: List<NetworkConnection>,
    val deviceRooted: Boolean,
    val debuggingEnabled: Boolean,
    val unknownSourcesEnabled: Boolean
)