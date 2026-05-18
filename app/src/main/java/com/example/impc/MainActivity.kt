package com.example.impc

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
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
                Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFFF4F6F9)) {
                    ProtocolStrictScreen()
                }
            }
        }
    }
}

@Composable
fun ProtocolStrictScreen() {
    val protocol = remember { ProtocolLogic() }
    val scope = rememberCoroutineScope()
    val logs = remember { mutableStateListOf<Pair<String, Color>>() }
    var isRunning by remember { mutableStateOf(false) }

    // Parámetros de la fase de registro según el artículo
    val idu = "usuario_movil"
    val pw = "mi_password_seguro"

    val ds = remember { BigInteger(256, java.security.SecureRandom()).mod(protocol.spec.n) }
    val qs = remember { protocol.P.multiply(ds) }

    // l = H1(ds) ⊕ H2(IDu || PW) en formato binario puro (ByteArray)
    val l = remember {
        val h1ds = protocol.hashToBytes(ds.toString())
        val h2IduPw = protocol.hashToBytes(idu + pw)
        protocol.xorBytes(h1ds, h2IduPw)
    }

    Column(modifier = Modifier.padding(16.dp)) {
        Text("Handshake Mutuo 2PAKE", style = MaterialTheme.typography.headlineSmall)
        Text("Cálculos reales sobre curvas elípticas usando bytes puros", style = MaterialTheme.typography.bodySmall)
        Spacer(modifier = Modifier.height(12.dp))

        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(Color(0xFF1C1C1E), RoundedCornerShape(8.dp))
                .padding(12.dp)
        ) {
            items(logs) { log ->
                Text(
                    text = log.first,
                    color = log.second,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(vertical = 2.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = {
                isRunning = true
                logs.clear()
                scope.launch {
                    try {
                        logs.add(" --- INICIANDO HANDSHAKE MATEMÁTICO ---" to Color.White)
                        delay(400)

                        // =========================================================================
                        // PARTE 1: USUARIO (U)
                        // =========================================================================
                        logs.add("\n[U] Elige aleatorio ru ∈ Zn*" to Color.Cyan)
                        val ru = BigInteger(256, java.security.SecureRandom()).mod(protocol.spec.n)

                        logs.add("[U] Calcula Ru = ru * P" to Color.Cyan)
                        val Ru = protocol.P.multiply(ru)

                        logs.add("[U] Calcula R = ru * Qs" to Color.Cyan)
                        val R = qs.multiply(ru)

                        val h2IduPw = protocol.hashToBytes(idu + pw)

                        // l ⊕ H2(IDu || PW)
                        val lXorH2 = protocol.xorBytes(l, h2IduPw)

                        // CIDu = IDu ⊕ l ⊕ H2(IDu || PW)

                        logs.add("[U] Calcula CIDu = IDu ⊕ l ⊕ H2(IDu || PW)" to Color.Cyan)
                        val cidu = protocol.xorBytes(idu.toByteArray(Charsets.UTF_8), lXorH2)

                        // Authu = H2(IDu || R || l ⊕ H2(IDu || PW))
                        logs.add("[U] Calcula Authu = H2(IDu || R || l ⊕ H2(IDu || PW))" to Color.Cyan)
                        val authu = protocol.hashToBytes(idu, R, lXorH2)

                        logs.add(" [U -> S]: Enviado Msg 1. CIDu = ${protocol.bytesToHex(cidu).take(10)}..." to Color.Yellow)
                        delay(800)

                        // =========================================================================
                        // PARTE 2: SERVIDOR (S)
                        // =========================================================================
                        logs.add("\n[S] Procesando Mensaje 1..." to Color.Green)
                        val h1ds = protocol.hashToBytes(ds.toString())

                        // El servidor recupera la identidad real haciendo: IDu = CIDu ⊕ H1(ds)
                        // Matemáticamente: CIDu ⊕ H1(ds) = IDu ⊕ H1(ds) ⊕ H2(IDu||PW) ⊕ H1(ds) = IDu ⊕ H2(IDu||PW)
                        // Por lo tanto, para extraer el IDu plano, hacemos XOR con (l ⊕ H2(IDu||PW)) que equivale a H1(ds)
                        val iduBytesRecuperados = protocol.xorBytes(cidu, h1ds)
                        val iduRecuperado = String(iduBytesRecuperados, Charsets.UTF_8).trim { it <= ' ' }
                        logs.add("[S] Identidad recuperada del cliente: '$iduRecuperado'" to Color.Green)

                        val rStar = Ru.multiply(ds) // R* = ds * Ru

                        // El servidor calcula de forma independiente el valor de l ⊕ H2(IDu || PW) usando el IDu que acaba de recuperar
                        val sH2IduPw = protocol.hashToBytes(iduRecuperado + pw)
                        val sLXorH2 = protocol.xorBytes(l, sH2IduPw)

                        // Auth_u* = H2(IDu || R* || H1(ds))
                        logs.add("[S] Calcula Auth_u* = H2(IDu || R* || H1(ds))" to Color.Green)
                        val authuStar = protocol.hashToBytes(iduRecuperado, rStar, sLXorH2)

                        logs.add("[S] Comparando hashes de autenticación..." to Color.Green)
                        if (protocol.bytesToHex(authuStar) != protocol.bytesToHex(authu)) {
                            logs.add(" [S] Error: ¡Auth_u* no coincide con Auth_u! Abortando." to Color.Red)
                            isRunning = false
                            return@launch
                        }
                        logs.add(" [S] ¡Auth_u Validado con éxito!" to Color.Green)

                        logs.add("[S] Generando SKs..." to Color.Green)
                        val rs = BigInteger(256, java.security.SecureRandom()).mod(protocol.spec.n)
                        val Rs = protocol.P.multiply(rs)
                        val sks = Ru.multiply(rs)

                        // Auths = H2(IDu || R* || SKs)
                        val auths = protocol.hashToBytes(iduRecuperado, rStar, sks.getEncoded(false))

                        logs.add(" [S -> U]: Enviado Msg 2. {Auth_s, R_s}" to Color.Yellow)
                        delay(800)

                        // =========================================================================
                        // PARTE 3: USUARIO (U)
                        // =========================================================================
                        logs.add("\n[U] Procesando Mensaje 2..." to Color.Cyan)
                        val sku = Rs.multiply(ru)

                        // Auth_s* = H2(IDu || R || SKu)
                        logs.add("[U] Calcula Auth_s* = H2(IDu || R || SKu)" to Color.Cyan)
                        val authsStar = protocol.hashToBytes(idu, R, sku.getEncoded(false))

                        if (protocol.bytesToHex(authsStar) != protocol.bytesToHex(auths)) {
                            logs.add(" [U] Error: Servidor no es auténtico." to Color.Red)
                            isRunning = false
                            return@launch
                        }
                        logs.add(" [U] ¡Servidor verificado exitosamente!" to Color.Cyan)

                        logs.add("[U] Generando SKu..." to Color.Cyan)
                        val skUsuario = protocol.kdf(idu + protocol.bytesToHex(sku.getEncoded(false)))
                        logs.add("[U]  SK Acordada (Móvil): ${protocol.bytesToHex(skUsuario).take(16)}..." to Color.Cyan)

                        // Auth_us = H2(R || SKu)
                        val authus = protocol.hashToBytes("", R, sku.getEncoded(false))

                        logs.add(" [U -> S]: Enviando Msg 3 de Confirmación Final {Auth_us}" to Color.Yellow)
                        delay(800)

                        // =========================================================================
                        // PARTE 4: SERVIDOR (S)
                        // =========================================================================
                        logs.add("\n[S] Procesando Mensaje 3..." to Color.Green)
                        // Auth_us* = H2(R* || SKs)
                        val authusStar = protocol.hashToBytes("", rStar, sks.getEncoded(false))

                        if (protocol.bytesToHex(authusStar) != protocol.bytesToHex(authus)) {
                            logs.add(" [S] Error: Confirmación final inválida." to Color.Red)
                            isRunning = false
                            return@launch
                        }

                        logs.add(" [S] ¡Confirmación final aceptada!" to Color.Green)
                        val skServidor = protocol.kdf(iduRecuperado + protocol.bytesToHex(sks.getEncoded(false)))
                        logs.add("[S]  SK Acordada (Servidor): ${protocol.bytesToHex(skServidor).take(16)}..." to Color.Green)

                        delay(400)
                        logs.add("\n [SISTEMA] ¡Intercambio completado y verificado en ambas partes!" to Color.Magenta)

                    } catch (e: Exception) {
                        logs.add(" EXCEPCIÓN: ${e.message}" to Color.Red)
                        e.printStackTrace()
                    } finally {
                        isRunning = false
                    }
                }
            },
            enabled = !isRunning,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(if (isRunning) "Calculando ECC..." else "Correr Protocolo Completo")
        }
    }
}
