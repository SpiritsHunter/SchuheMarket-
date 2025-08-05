package com.securityguard.app.services

import android.app.*
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.work.*
import kotlinx.coroutines.*
import java.util.concurrent.TimeUnit
import android.app.usage.UsageStatsManager
import android.app.usage.UsageEvents
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest
import android.telephony.TelephonyManager
import java.text.SimpleDateFormat
import java.util.*
import com.securityguard.app.MainActivity
import com.securityguard.app.R

class SecurityMonitoringService : Service() {

    companion object {
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "security_monitoring_channel"
        private const val MONITORING_INTERVAL = 30L // seconds
    }

    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private var isMonitoring = false
    
    // Monitoring components
    private lateinit var connectivityManager: ConnectivityManager
    private lateinit var telephonyManager: TelephonyManager
    private lateinit var sensorManager: SensorManager
    private lateinit var usageStatsManager: UsageStatsManager
    
    // Network monitoring
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    
    // Sensor monitoring for device tampering detection
    private var accelerometer: Sensor? = null
    private var gyroscope: Sensor? = null
    private var sensorListener: SensorEventListener? = null
    
    // Threat detection state
    private val detectedThreats = mutableListOf<String>()
    private var lastAppUsageCheck = System.currentTimeMillis()
    
    override fun onCreate() {
        super.onCreate()
        
        initializeServices()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification("Security monitoring active"))
        
        startMonitoring()
    }

    private fun initializeServices() {
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        telephonyManager = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        sensorManager = getSystemService(Context.SENSOR_SERVICE) as SensorManager
        usageStatsManager = getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        
        // Initialize sensors
        accelerometer = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        gyroscope = sensorManager.getDefaultSensor(Sensor.TYPE_GYROSCOPE)
    }

    private fun startMonitoring() {
        if (isMonitoring) return
        
        isMonitoring = true
        
        // Start continuous monitoring tasks
        serviceScope.launch {
            while (isMonitoring) {
                try {
                    performSecurityChecks()
                    delay(MONITORING_INTERVAL * 1000)
                } catch (e: Exception) {
                    // Log error and continue monitoring
                    delay(MONITORING_INTERVAL * 1000)
                }
            }
        }
        
        // Start network monitoring
        startNetworkMonitoring()
        
        // Start sensor monitoring for tampering detection
        startSensorMonitoring()
        
        // Schedule periodic deep scans
        schedulePeriodicScans()
    }

    private suspend fun performSecurityChecks() {
        withContext(Dispatchers.IO) {
            
            // Check for suspicious app installations
            checkRecentAppInstallations()
            
            // Monitor app usage patterns
            checkSuspiciousAppUsage()
            
            // Check for unusual network activity
            checkNetworkActivity()
            
            // Check for SIM changes
            checkSimStatus()
            
            // Check for debugging attempts
            checkDebuggingAttempts()
            
            // Update notification with current status
            updateNotification()
        }
    }

    private fun checkRecentAppInstallations() {
        try {
            val packageManager = packageManager
            val installedApps = packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            
            // Check for apps installed in the last hour
            val oneHourAgo = System.currentTimeMillis() - (60 * 60 * 1000)
            
            for (appInfo in installedApps) {
                try {
                    val packageInfo = packageManager.getPackageInfo(appInfo.packageName, 0)
                    if (packageInfo.firstInstallTime > oneHourAgo) {
                        val appName = packageManager.getApplicationLabel(appInfo).toString()
                        
                        // Check if the app has suspicious characteristics
                        if (isSuspiciousApp(appInfo.packageName, appName)) {
                            addThreatDetection("Suspicious app installed: $appName")
                            sendSecurityAlert("New suspicious app detected", 
                                "App '$appName' was recently installed and may pose a security risk")
                        }
                    }
                } catch (e: Exception) {
                    // Continue checking other apps
                }
            }
        } catch (e: Exception) {
            // Log error
        }
    }

    private fun checkSuspiciousAppUsage() {
        try {
            val currentTime = System.currentTimeMillis()
            val usageEvents = usageStatsManager.queryEvents(lastAppUsageCheck, currentTime)
            lastAppUsageCheck = currentTime
            
            val event = UsageEvents.Event()
            while (usageEvents.hasNextEvent()) {
                usageEvents.getNextEvent(event)
                
                if (event.eventType == UsageEvents.Event.ACTIVITY_RESUMED) {
                    // Check if this is a known suspicious app
                    if (isSuspiciousPackage(event.packageName)) {
                        addThreatDetection("Suspicious app activity: ${event.packageName}")
                        sendSecurityAlert("Suspicious app activity", 
                            "App ${event.packageName} is running and may be malicious")
                    }
                }
            }
        } catch (e: SecurityException) {
            // Usage access permission not granted
        } catch (e: Exception) {
            // Log error
        }
    }

    private fun checkNetworkActivity() {
        // Monitor for unusual network connections
        // This would typically involve checking active connections
        // and comparing against known malicious IPs or domains
        
        try {
            val networks = connectivityManager.allNetworks
            for (network in networks) {
                val capabilities = connectivityManager.getNetworkCapabilities(network)
                capabilities?.let {
                    // Check for suspicious network characteristics
                    if (!it.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_TRUSTED)) {
                        addThreatDetection("Untrusted network connection detected")
                    }
                }
            }
        } catch (e: Exception) {
            // Log error
        }
    }

    private fun checkSimStatus() {
        try {
            val simState = telephonyManager.simState
            val simOperator = telephonyManager.simOperatorName
            
            // Store previous SIM info and compare
            val sharedPrefs = getSharedPreferences("security_prefs", Context.MODE_PRIVATE)
            val lastSimOperator = sharedPrefs.getString("last_sim_operator", "")
            
            if (lastSimOperator.isNotEmpty() && lastSimOperator != simOperator) {
                addThreatDetection("SIM card changed - possible SIM swap attack")
                sendSecurityAlert("SIM Card Changed", 
                    "Your SIM card has been changed. This could indicate a SIM swap attack.")
            }
            
            // Update stored SIM info
            sharedPrefs.edit().putString("last_sim_operator", simOperator).apply()
            
        } catch (e: Exception) {
            // Log error
        }
    }

    private fun checkDebuggingAttempts() {
        try {
            val debuggingEnabled = android.provider.Settings.Global.getInt(
                contentResolver,
                android.provider.Settings.Global.ADB_ENABLED,
                0
            ) == 1
            
            if (debuggingEnabled) {
                addThreatDetection("USB debugging enabled - potential security risk")
            }
            
        } catch (e: Exception) {
            // Log error
        }
    }

    private fun startNetworkMonitoring() {
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                // Log network changes
                serviceScope.launch {
                    checkNetworkSecurity(network)
                }
            }
            
            override fun onLost(network: Network) {
                super.onLost(network)
                // Network disconnected
            }
        }
        
        val networkRequest = NetworkRequest.Builder().build()
        connectivityManager.registerNetworkCallback(networkRequest, networkCallback!!)
    }

    private suspend fun checkNetworkSecurity(network: Network) {
        withContext(Dispatchers.IO) {
            try {
                val capabilities = connectivityManager.getNetworkCapabilities(network)
                capabilities?.let {
                    if (it.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)) {
                        // Check WiFi security
                        if (!it.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_TRUSTED)) {
                            addThreatDetection("Connected to untrusted WiFi network")
                            sendSecurityAlert("Insecure Network", 
                                "You've connected to an untrusted WiFi network")
                        }
                    }
                }
            } catch (e: Exception) {
                // Log error
            }
        }
    }

    private fun startSensorMonitoring() {
        // Monitor device sensors for unusual movements that might indicate tampering
        sensorListener = object : SensorEventListener {
            private var lastAccelerometerReading = FloatArray(3)
            private var lastGyroscopeReading = FloatArray(3)
            private var unusualMovementCount = 0
            
            override fun onSensorChanged(event: SensorEvent?) {
                event?.let {
                    when (it.sensor.type) {
                        Sensor.TYPE_ACCELEROMETER -> {
                            // Detect unusual acceleration patterns
                            val deltaX = Math.abs(it.values[0] - lastAccelerometerReading[0])
                            val deltaY = Math.abs(it.values[1] - lastAccelerometerReading[1])
                            val deltaZ = Math.abs(it.values[2] - lastAccelerometerReading[2])
                            
                            if (deltaX > 15 || deltaY > 15 || deltaZ > 15) {
                                unusualMovementCount++
                                if (unusualMovementCount > 5) {
                                    addThreatDetection("Unusual device movement detected - possible tampering")
                                    unusualMovementCount = 0
                                }
                            }
                            
                            System.arraycopy(it.values, 0, lastAccelerometerReading, 0, 3)
                        }
                        
                        Sensor.TYPE_GYROSCOPE -> {
                            // Monitor rotation patterns
                            System.arraycopy(it.values, 0, lastGyroscopeReading, 0, 3)
                        }
                    }
                }
            }
            
            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
        }
        
        accelerometer?.let { 
            sensorManager.registerListener(sensorListener, it, SensorManager.SENSOR_DELAY_NORMAL)
        }
        gyroscope?.let { 
            sensorManager.registerListener(sensorListener, it, SensorManager.SENSOR_DELAY_NORMAL)
        }
    }

    private fun schedulePeriodicScans() {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()
        
        val periodicScanRequest = PeriodicWorkRequestBuilder<SecurityScanWorker>(
            15, TimeUnit.MINUTES // Run every 15 minutes
        )
            .setConstraints(constraints)
            .build()
        
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "security_scan",
            ExistingPeriodicWorkPolicy.REPLACE,
            periodicScanRequest
        )
    }

    private fun isSuspiciousApp(packageName: String, appName: String): Boolean {
        val suspiciousKeywords = listOf(
            "spy", "keylogger", "tracker", "monitor", "hack", "crack",
            "stealth", "hidden", "invisible", "stalker", "malware"
        )
        
        return suspiciousKeywords.any { keyword ->
            packageName.contains(keyword, ignoreCase = true) || 
            appName.contains(keyword, ignoreCase = true)
        }
    }

    private fun isSuspiciousPackage(packageName: String): Boolean {
        val knownMalwarePackages = listOf(
            "com.android.systemui.hack",
            "com.spy.app",
            "com.keylogger.app",
            "com.malware.test"
        )
        
        return knownMalwarePackages.contains(packageName) || 
               isSuspiciousApp(packageName, packageName)
    }

    private fun addThreatDetection(threat: String) {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
        detectedThreats.add("[$timestamp] $threat")
        
        // Keep only last 50 threats to prevent memory issues
        if (detectedThreats.size > 50) {
            detectedThreats.removeAt(0)
        }
    }

    private fun sendSecurityAlert(title: String, message: String) {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_security_alert)
            .setContentTitle(title)
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setColor(Color.RED)
            .build()
        
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(System.currentTimeMillis().toInt(), notification)
    }

    private fun updateNotification() {
        val threatCount = detectedThreats.size
        val status = if (threatCount == 0) {
            "Device secure - No threats detected"
        } else {
            "⚠️ $threatCount security issues detected"
        }
        
        val notification = createNotification(status)
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    private fun createNotification(status: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Security Guard")
            .setContentText(status)
            .setSmallIcon(R.drawable.ic_security)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Security Monitoring",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Security monitoring service notifications"
            }
            
            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        isMonitoring = false
        serviceScope.cancel()
        
        // Unregister callbacks
        networkCallback?.let { connectivityManager.unregisterNetworkCallback(it) }
        sensorListener?.let { sensorManager.unregisterListener(it) }
        
        // Cancel work
        WorkManager.getInstance(this).cancelUniqueWork("security_scan")
    }

    override fun onBind(intent: Intent?): IBinder? = null
}

// Worker class for periodic security scans
class SecurityScanWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    
    override suspend fun doWork(): Result {
        return try {
            // Perform comprehensive security scan
            performDeepSecurityScan()
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }
    
    private suspend fun performDeepSecurityScan() {
        withContext(Dispatchers.IO) {
            // Implement deep security scanning logic here
            // This could include:
            // - Full app scan
            // - Network traffic analysis
            // - File system integrity checks
            // - Registry/settings validation
        }
    }
}