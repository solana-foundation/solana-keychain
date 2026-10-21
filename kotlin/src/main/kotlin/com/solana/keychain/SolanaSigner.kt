package com.solana.keychain

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.util.Base64

private const val SIGNATURE_LENGTH = 64
private const val PUBKEY_LENGTH = 32
private const val BLOCKHASH_LENGTH = 32
private const val VERSION_PREFIX = 0x80

interface SolanaSigner {
    val address: String

    fun signMessage(message: ByteArray): ByteArray

    fun isAvailable(): Boolean
}

interface TransactionSigner : SolanaSigner {
    fun signTransaction(transaction: ByteArray): SignedTransaction
}

class SignedTransaction(
    val encodedTransaction: String,
    val signature: ByteArray,
    val isComplete: Boolean,
)

enum class SignerErrorCode(
    val value: String,
    val message: String,
) {
    INVALID_PRIVATE_KEY("SIGNER_INVALID_PRIVATE_KEY", "Invalid private key format"),
    IO_ERROR("SIGNER_IO_ERROR", "IO error"),
    SERIALIZATION_ERROR("SIGNER_SERIALIZATION_ERROR", "Serialization error"),
    SIGNING_FAILED("SIGNER_SIGNING_FAILED", "Signing failed"),
}

class SignerError(
    val code: SignerErrorCode,
    val detail: String,
) : Exception(code.message)

object Base58 {
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private val BASE = BigInteger.valueOf(58)

    fun encode(bytes: ByteArray): String {
        val digits = StringBuilder()
        var n = BigInteger(1, bytes)
        while (n.signum() > 0) {
            val (quotient, remainder) = n.divideAndRemainder(BASE)
            digits.append(ALPHABET[remainder.toInt()])
            n = quotient
        }
        repeat(bytes.takeWhile { it == 0.toByte() }.size) { digits.append('1') }
        return digits.reverse().toString()
    }

    fun decode(text: String): ByteArray? {
        var n = BigInteger.ZERO
        for (char in text) {
            val digit = ALPHABET.indexOf(char)
            if (digit < 0) return null
            n = n * BASE + digit.toBigInteger()
        }
        return ByteArray(text.takeWhile { it == '1' }.length) + n.toByteArray().dropWhile { it == 0.toByte() }
    }
}

fun signWireTransaction(
    transaction: ByteArray,
    pubkey: ByteArray,
    sign: (ByteArray) -> ByteArray,
): SignedTransaction {
    val reader = WireReader(transaction)
    val signatures = MutableList(reader.compactU16()) { reader.take(SIGNATURE_LENGTH) }
    val messageStart = reader.position
    val prefix = reader.byte()
    val versioned = prefix == VERSION_PREFIX
    val numRequired =
        when {
            (prefix and VERSION_PREFIX) == 0 -> prefix
            versioned -> reader.byte()
            else -> throw SignerError(SignerErrorCode.SERIALIZATION_ERROR, "unsupported transaction version")
        }
    reader.take(2)
    val accountKeys = List(reader.compactU16()) { reader.take(PUBKEY_LENGTH) }
    reader.skipMessageBody(versioned)
    val position = accountKeys.take(numRequired).indexOfFirst { it.contentEquals(pubkey) }
    if (accountKeys.size < numRequired || position < 0) {
        throw SignerError(SignerErrorCode.SIGNING_FAILED, "pubkey is not a required signer of the transaction")
    }
    if (signatures.size > numRequired) {
        throw SignerError(SignerErrorCode.SERIALIZATION_ERROR, "transaction has more signatures than the message requires")
    }
    val message = transaction.copyOfRange(messageStart, transaction.size)
    val signature = sign(message)
    while (signatures.size < numRequired) signatures += ByteArray(SIGNATURE_LENGTH)
    signatures[position] = signature
    val wire = signatures.fold(encodeCompactU16(signatures.size)) { acc, slot -> acc + slot } + message
    val isComplete = signatures.take(numRequired).none { slot -> slot.all { it == 0.toByte() } }
    return SignedTransaction(Base64.getEncoder().encodeToString(wire), signature, isComplete)
}

private class WireReader(
    private val bytes: ByteArray,
) {
    var position = 0
        private set

    fun take(length: Int): ByteArray {
        if (length > bytes.size - position) {
            throw SignerError(SignerErrorCode.SERIALIZATION_ERROR, "transaction is truncated")
        }
        return bytes.copyOfRange(position, position + length).also { position += length }
    }

    fun byte(): Int = take(1)[0].toInt() and 0xff

    fun skipMessageBody(versioned: Boolean) {
        take(BLOCKHASH_LENGTH)
        repeat(compactU16()) {
            byte()
            take(compactU16())
            take(compactU16())
        }
        if (versioned) {
            repeat(compactU16()) {
                take(PUBKEY_LENGTH)
                take(compactU16())
                take(compactU16())
            }
        }
        if (position != bytes.size) {
            throw SignerError(SignerErrorCode.SERIALIZATION_ERROR, "transaction has trailing bytes")
        }
    }

    // Canonical shortvec only: no trailing zero byte, and the third byte carries at most 2 bits.
    fun compactU16(): Int {
        var value = 0
        for (index in 0..2) {
            val byte = byte()
            if (index > 0 && byte == 0) {
                throw SignerError(SignerErrorCode.SERIALIZATION_ERROR, "compact-u16 is not canonical")
            }
            if (index == 2 && byte > 0x03) {
                throw SignerError(SignerErrorCode.SERIALIZATION_ERROR, "compact-u16 overflows")
            }
            value = value or ((byte and 0x7f) shl (7 * index))
            if ((byte and 0x80) == 0) return value
        }
        throw SignerError(SignerErrorCode.SERIALIZATION_ERROR, "compact-u16 overflows")
    }
}

private fun encodeCompactU16(value: Int): ByteArray {
    val out = ByteArrayOutputStream()
    var rest = value
    while (rest >= 0x80) {
        out.write((rest and 0x7f) or 0x80)
        rest = rest shr 7
    }
    out.write(rest)
    return out.toByteArray()
}
