package com.example.impc

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.example.impc.ui.protocol.ProtocolLogic
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.math.BigInteger

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(color = Color(0xFFF0F2F5)) {
                    ProtocolDemoScreen()
                }
            }
        }
    }
}

@Composable
fun ProtocolDemoScreen() {
    val scope = rememberCoroutineScope()
    val logs = remember { mutableStateListOf<Pair<String, Color>>() }
    var step by remember { mutableIntStateOf(0) }
    var isRunning by remember { mutableStateOf(false) }

    // Inicialización de la lógica del protocolo
    val logic = remember { ProtocolLogic() }
    val idu = "usuario@ejemplo.com"
    val pw = "password123"
    // ds es la clave privada del servidor
    val ds = remember { BigInteger("1234567890123456789012345678901234567890") }
    // qs es la clave pública del servidor (qs = ds * P)
    val qs = remember { logic.spec.g.multiply(ds) }
    
    // Preparar el parámetro L para que el servidor pueda recuperar el IDu correctamente
    val h1ds = logic.h2(ds.toString())
    val h2IDuPW = logic.h2(idu + pw)
    val l = logic.xor(h1ds, h2IDuPW)

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Demo: Protocolo 2PAKE", style = MaterialTheme.typography.headlineSmall)
        Text("Simulación visual de intercambio de claves ECC", style = MaterialTheme.typography.bodySmall)

        Spacer(modifier = Modifier.height(16.dp))

        // Monitor de logs (Simula la red)
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(Color.Black, RoundedCornerShape(8.dp))
                .padding(8.dp)
        ) {
            items(logs) { log ->
                Text(
                    text = "> ${log.first}",
                    color = log.second,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Botón de ejecución
        Button(
            onClick = {
                isRunning = true
                logs.clear()
                scope.launch {
                    // PASO 1: CLIENTE
                    logs.add("USUARIO: Generando r_u aleatorio..." to Color.Cyan)
                    val msg1 = logic.step1User(idu, pw, l, qs)
                    delay(800)
                    
                    logs.add("USUARIO: Calculando CID_u (Identidad Enmascarada)..." to Color.Cyan)
                    delay(800)
                    
                    logs.add("USUARIO -> SERVIDOR: {Auth_u, CID_u, R_u}" to Color.Yellow)
                    step = 1

                    // PASO 2: SERVIDOR
                    delay(1200)
                    logs.add("SERVIDOR: Verificando Auth_u y recuperando ID_u..." to Color.Green)
                    val msg2 = logic.step2Server(msg1, ds)
                    delay(800)
                    
                    if (msg2 != null) {
                        logs.add("SERVIDOR: Generando r_s y punto R_s..." to Color.Green)
                        logs.add("SERVIDOR -> USUARIO: {Auth_s, R_s}" to Color.Yellow)
                        step = 2

                        // PASO 3: FINALIZACIÓN
                        delay(1200)
                        logs.add("USUARIO: Verificando autenticidad del servidor..." to Color.Cyan)
                        delay(800)
                        
                        logs.add("SISTEMA: ¡Clave de Sesión (SK) acordada!" to Color.Magenta)
                        logs.add("SISTEMA: Ahora puedes descifrar el PDF." to Color.White)
                        step = 3
                    } else {
                        logs.add("ERROR: El protocolo falló en la verificación." to Color.Red)
                    }
                    
                    isRunning = false
                }
            },
            enabled = !isRunning,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.Send, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Iniciar Protocolo")
        }

        // Simulación de "Archivo Descifrado"
        AnimatedVisibility(visible = step == 3) {
            Card(
                modifier = Modifier.padding(top = 16.dp).fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = Color(0xFF4CAF50))
                    Spacer(Modifier.width(12.dp))
                    Text("PDF Descifrado: 'Reporte_Medico.pdf'", style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}
