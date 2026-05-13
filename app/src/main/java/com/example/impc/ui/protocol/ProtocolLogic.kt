package com.example.impc.ui.protocol

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.MessageDigest

class ProtocolLogic {
    val spec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
    private val P = spec.g

    // Hash H2 (SHA-256)
    fun h2(data: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(data.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // Operación XOR para strings
    fun xor(a: String, b: String): String {
        val aBytes = a.toByteArray()
        val bBytes = b.toByteArray()
        val res = ByteArray(minOf(aBytes.size, bBytes.size))
        for (i in res.indices) res[i] = (aBytes[i].toInt() xor bBytes[i].toInt()).toByte()
        return res.decodeToString()
    }

    // Paso 1: Usuario genera solicitud
    fun step1User(idu: String, pw: String, l: String, qs: ECPoint): Map<String, Any> {
        val ru = BigInteger(256, java.security.SecureRandom()).mod(spec.n)
        val Ru = P.multiply(ru) // Ru = ru * P
        val R = qs.multiply(ru)  // R = ru * Qs

        val h2IDuPW = h2(idu + pw)
        val cidu = xor(idu, xor(l, h2IDuPW)) // CIDu
        val authu = h2(idu + R.toString() + xor(l, h2IDuPW)) // Authu

        return mapOf("auth_u" to authu, "cid_u" to cidu, "ru" to Ru, "internal_ru" to ru, "R" to R)
    }

    // Paso 2 y 3: Servidor procesa y responde a la solicitud
    fun step2Server(msg1: Map<String, Any>, ds: BigInteger): Map<String, Any>? {
        val cidu = msg1["cid_u"] as String
        val ruPoint = msg1["ru"] as ECPoint
        val h1ds = h2(ds.toString()) // Simulación H1(ds)

        val idu = xor(cidu, h1ds) // Recupera IDu
        val rStar = ruPoint.multiply(ds) // R* = ds * Ru

        val rs = BigInteger(256, java.security.SecureRandom()).mod(spec.n)
        val Rs = P.multiply(rs) // Rs = rs * P
        val sks = ruPoint.multiply(rs) // SKs = rs * Ru

        val auths = h2(idu + rStar.toString() + sks.toString()) // Auths

        return mapOf("auth_s" to auths, "rs" to Rs, "idu" to idu, "sks" to sks)
    }
}