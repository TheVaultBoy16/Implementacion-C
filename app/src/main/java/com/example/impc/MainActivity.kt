package com.example.impc

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.impc.ui.protocol.ProtocolLogic
import java.math.BigInteger

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    ProtocolUI()
                }
            }
        }
    }
}

@Composable
fun ProtocolUI() {
    val protocol = remember { ProtocolLogic() }
    val logs = remember { mutableStateListOf<String>() }

    // Datos de prueba (Fase de Registro previa)
    val idu = "usuario123"
    val pw = "password123"
    val ds = BigInteger("123456789") // Clave privada servidor
    val qs = protocol.spec.g.multiply(ds) // Clave pública servidor
    val l = protocol.xor(protocol.h2(ds.toString()), protocol.h2(idu + pw)) // l

    Column(modifier = Modifier.padding(16.dp)) {
        Text("2PAKE Protocol Demo", style = MaterialTheme.typography.headlineMedium)

        Button(
            onClick = {
                logs.clear()
                logs.add("Iniciando Autenticación...")

                // Mensaje 1: Usuario -> Servidor
                val msg1 = protocol.step1User(idu, pw, l, qs)
                logs.add("U -> S: {Auth_u, CID_u, R_u}")

                // Mensaje 2: Servidor -> Usuario
                val msg2 = protocol.step2Server(msg1, ds)
                if (msg2 != null) {
                    logs.add("Servidor autenticó a Usuario")
                    logs.add("S -> U: {Auth_s, R_s}")

                    // Finalización en Usuario
                    logs.add("Usuario autenticó a Servidor")
                    logs.add("Clave de Sesión (SK) establecida")
                } else {
                    logs.add("Error de autenticación")
                }
            },
            modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)
        ) {
            Text("Ejecutar Intercambio de Claves")
        }

        Divider()

        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(logs) { log ->
                Text(log, modifier = Modifier.padding(vertical = 4.dp))
            }
        }
    }
}