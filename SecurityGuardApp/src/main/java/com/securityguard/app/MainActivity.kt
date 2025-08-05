package com.securityguard.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.securityguard.app.services.SecurityMonitoringService
import com.securityguard.app.ui.theme.SecurityGuardTheme
import com.securityguard.app.viewmodels.SecurityViewModel

class MainActivity : ComponentActivity() {

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.values.all { it }
        if (allGranted) {
            startSecurityService()
        }
    }

    private val requiredPermissions = arrayOf(
        Manifest.permission.CAMERA,
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.ACCESS_COARSE_LOCATION,
        Manifest.permission.READ_PHONE_STATE,
        Manifest.permission.ACCESS_NETWORK_STATE,
        Manifest.permission.ACCESS_WIFI_STATE
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        checkAndRequestPermissions()
        
        setContent {
            SecurityGuardTheme {
                SecurityGuardApp()
            }
        }
    }

    private fun checkAndRequestPermissions() {
        val missingPermissions = requiredPermissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missingPermissions.isNotEmpty()) {
            permissionLauncher.launch(missingPermissions.toTypedArray())
        } else {
            startSecurityService()
        }
    }

    private fun startSecurityService() {
        val serviceIntent = Intent(this, SecurityMonitoringService::class.java)
        startForegroundService(serviceIntent)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityGuardApp() {
    val navController = rememberNavController()
    val securityViewModel: SecurityViewModel = viewModel()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        "Security Guard",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    titleContentColor = MaterialTheme.colorScheme.onPrimary
                )
            )
        }
    ) { paddingValues ->
        NavHost(
            navController = navController,
            startDestination = "dashboard",
            modifier = Modifier.padding(paddingValues)
        ) {
            composable("dashboard") {
                DashboardScreen(navController, securityViewModel)
            }
            composable("threats") {
                ThreatMonitoringScreen(securityViewModel)
            }
            composable("network") {
                NetworkMonitoringScreen(securityViewModel)
            }
            composable("permissions") {
                PermissionAuditScreen(securityViewModel)
            }
            composable("intruder") {
                IntruderDetectionScreen(securityViewModel)
            }
            composable("settings") {
                SettingsScreen(securityViewModel)
            }
        }
    }
}

@Composable
fun DashboardScreen(
    navController: NavHostController,
    viewModel: SecurityViewModel
) {
    val securityStatus by viewModel.securityStatus.collectAsState()
    val threats by viewModel.recentThreats.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        // Security Status Card
        SecurityStatusCard(securityStatus)
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Quick Actions
        Text(
            text = "Security Features",
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        
        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            val features = listOf(
                SecurityFeature("Threat Detection", Icons.Default.Security, "threats", "Monitor for malware and suspicious apps"),
                SecurityFeature("Network Monitor", Icons.Default.NetworkCheck, "network", "Track network connections and data"),
                SecurityFeature("App Permissions", Icons.Default.Apps, "permissions", "Audit app permissions and privacy"),
                SecurityFeature("Intruder Detection", Icons.Default.PhotoCamera, "intruder", "Capture unauthorized access attempts"),
                SecurityFeature("Settings", Icons.Default.Settings, "settings", "Configure security preferences")
            )
            
            items(features) { feature ->
                SecurityFeatureCard(
                    feature = feature,
                    onClick = { navController.navigate(feature.route) }
                )
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Recent Threats
        if (threats.isNotEmpty()) {
            Text(
                text = "Recent Threats (${threats.size})",
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color.Red
            )
            
            LazyColumn {
                items(threats.take(3)) { threat ->
                    ThreatItem(threat)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityStatusCard(status: SecurityStatus) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (status.isSecure) Color.Green.copy(alpha = 0.1f) else Color.Red.copy(alpha = 0.1f)
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = if (status.isSecure) Icons.Default.CheckCircle else Icons.Default.Warning,
                    contentDescription = null,
                    tint = if (status.isSecure) Color.Green else Color.Red,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (status.isSecure) "Device Secure" else "Security Issues Detected",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (status.isSecure) Color.Green else Color.Red
                )
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Text(
                text = "Last scan: ${status.lastScanTime}",
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            if (!status.isSecure) {
                Text(
                    text = "${status.threatCount} threats detected",
                    fontSize = 14.sp,
                    color = Color.Red,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityFeatureCard(
    feature: SecurityFeature,
    onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = feature.icon,
                contentDescription = null,
                modifier = Modifier.size(24.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            
            Spacer(modifier = Modifier.width(16.dp))
            
            Column(
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = feature.title,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = feature.description,
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun ThreatItem(threat: SecurityThreat) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Red.copy(alpha = 0.1f)
        )
    ) {
        Column(
            modifier = Modifier.padding(12.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Default.Warning,
                    contentDescription = null,
                    tint = Color.Red,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = threat.type,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp
                )
            }
            Text(
                text = threat.description,
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = threat.timestamp,
                fontSize = 10.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// Other screen composables (ThreatMonitoringScreen, NetworkMonitoringScreen, etc.)
// These would be implemented in separate files for better organization

@Composable
fun ThreatMonitoringScreen(viewModel: SecurityViewModel) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "Threat Detection",
            fontSize = 24.sp,
            fontWeight = FontWeight.Bold
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(
            onClick = { viewModel.scanForThreats() },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Start Security Scan")
        }
        
        // Threat list would be implemented here
    }
}

@Composable
fun NetworkMonitoringScreen(viewModel: SecurityViewModel) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "Network Monitoring",
            fontSize = 24.sp,
            fontWeight = FontWeight.Bold
        )
        
        // Network monitoring UI would be implemented here
    }
}

@Composable
fun PermissionAuditScreen(viewModel: SecurityViewModel) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "App Permissions Audit",
            fontSize = 24.sp,
            fontWeight = FontWeight.Bold
        )
        
        // Permission audit UI would be implemented here
    }
}

@Composable
fun IntruderDetectionScreen(viewModel: SecurityViewModel) {
    val context = LocalContext.current
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "Intruder Detection",
            fontSize = 24.sp,
            fontWeight = FontWeight.Bold
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(
            onClick = { 
                // Enable intruder detection
                viewModel.enableIntruderDetection()
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Enable Intruder Detection")
        }
        
        // Intruder detection settings and logs would be implemented here
    }
}

@Composable
fun SettingsScreen(viewModel: SecurityViewModel) {
    val context = LocalContext.current
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "Security Settings",
            fontSize = 24.sp,
            fontWeight = FontWeight.Bold
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Button(
            onClick = {
                val intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
                context.startActivity(intent)
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Grant Usage Access Permission")
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Button(
            onClick = {
                val intent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION)
                context.startActivity(intent)
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Grant Overlay Permission")
        }
        
        // Additional settings would be implemented here
    }
}

// Data classes
data class SecurityFeature(
    val title: String,
    val icon: ImageVector,
    val route: String,
    val description: String
)

data class SecurityStatus(
    val isSecure: Boolean = true,
    val lastScanTime: String = "Never",
    val threatCount: Int = 0
)

data class SecurityThreat(
    val type: String,
    val description: String,
    val timestamp: String,
    val severity: String = "High"
)