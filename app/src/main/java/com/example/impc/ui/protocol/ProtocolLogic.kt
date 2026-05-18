package com.example.impc.ui.protocol

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.MessageDigest

class ProtocolLogic {
    val spec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
    val P: ECPoint = spec.g

    // Retorna el hash directamente en bytes para poder operar con él de forma segura
    fun hashToBytes(data: String, point: ECPoint? = null, extraBytes: ByteArray? = null): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        if (data.isNotEmpty()) {
            digest.update(data.toByteArray(Charsets.UTF_8))
        }
        point?.let {
            // getEncoded(false) nos da los bytes del punto normalizados (idénticos en cliente y servidor)
            digest.update(it.getEncoded(false))
        }
        extraBytes?.let {
            digest.update(it)
        }
        return digest.digest()
    }

    // Convierte bytes a una cadena legible Hexadecimal (solo para mostrar en los logs)
    fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // Operación XOR nativa y segura entre arreglos de bytes de cualquier tamaño
    fun xorBytes(a: ByteArray, b: ByteArray): ByteArray {
        val len = maxOf(a.size, b.size)
        val res = ByteArray(len)
        for (i in 0 until len) {
            val byteA = if (i < a.size) a[i].toInt() else 0
            val byteB = if (i < b.size) b[i].toInt() else 0
            res[i] = (byteA xor byteB).toByte()
        }
        return res
    }

    fun kdf(data: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("KDF_SALT_".toByteArray(Charsets.UTF_8))
        digest.update(data.toByteArray(Charsets.UTF_8))
        return digest.digest()
    }
}