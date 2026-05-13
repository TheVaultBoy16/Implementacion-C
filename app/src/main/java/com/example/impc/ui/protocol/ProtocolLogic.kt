package com.example.impc.ui.protocol

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.MessageDigest

class ProtocolLogic {
    val spec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
    private val P = spec.g

    // Hash H2 (SHA-256) [cite: 75]
    fun h2(data: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(data.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // Operación XOR para strings [cite: 79]
    fun xor(a: String, b: String): String {
        val aBytes = a.toByteArray()
        val bBytes = b.toByteArray()
        val res = ByteArray(minOf(aBytes.size, bBytes.size))
        for (i in res.indices) res[i] = (aBytes[i].toInt() xor bBytes[i].toInt()).toByte()
        return res.decodeToString()
    }

    // Paso 1: Usuario genera solicitud [cite: 90]
    fun step1User(idu: String, pw: String, l: String, qs: ECPoint): Map<String, Any> {
        val ru = BigInteger(256, java.security.SecureRandom()).mod(spec.n)
        val Ru = P.multiply(ru) // Ru = ru * P [cite: 95]
        val R = qs.multiply(ru)  // R = ru * Qs [cite: 96]

        val h2IDuPW = h2(idu + pw)
        val cidu = xor(idu, xor(l, h2IDuPW)) // CIDu [cite: 97]
        val authu = h2(idu + R.toString() + xor(l, h2IDuPW)) // Authu [cite: 98]

        return mapOf("auth_u" to authu, "cid_u" to cidu, "ru" to Ru, "internal_ru" to ru, "R" to R)
    }

    // Paso 2 y 3: Servidor procesa y responde [cite: 105, 112, 113]
    fun step2Server(msg1: Map<String, Any>, ds: BigInteger): Map<String, Any>? {
        val cidu = msg1["cid_u"] as String
        val ruPoint = msg1["ru"] as ECPoint
        val h1ds = h2(ds.toString()) // Simulación H1(ds) [cite: 105]

        val idu = xor(cidu, h1ds) // Recupera IDu [cite: 105]
        val rStar = ruPoint.multiply(ds) // R* = ds * Ru [cite: 106]

        val rs = BigInteger(256, java.security.SecureRandom()).mod(spec.n)
        val Rs = P.multiply(rs) // Rs = rs * P [cite: 111]
        val sks = ruPoint.multiply(rs) // SKs = rs * Ru [cite: 112]

        val auths = h2(idu + rStar.toString() + sks.toString()) // Auths [cite: 113]

        return mapOf("auth_s" to auths, "rs" to Rs, "idu" to idu, "sks" to sks)
    }
}