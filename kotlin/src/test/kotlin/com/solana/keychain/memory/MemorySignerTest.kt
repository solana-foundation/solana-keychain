package com.solana.keychain.memory

import com.solana.keychain.Base58
import com.solana.keychain.SignerError
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.File
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

private const val ADDRESS = "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj"
private const val MESSAGE_B64 =
    "AQABA3m1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkIVL40Zt5HSRFMkLhXy6rbLfP+" +
        "ntqXtMAl5YOBpiB2xIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJAQICAAEMAgAAAEBCDwAAAAAA"
private const val SIGNED_TX_B64 =
    "AQUSPyADYLJarC6XLNhwmO1ZNP7/MECEKnIrOtFcIShPQX3yXWFNn9ftJEhqvrA0W01eyrBk8Pojgs+jRn23Nw4B" +
        "AAEDebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQhUvjRm3kdJEUyQuFfLqtst8/6e2pe0w" +
        "CXlg4GmIHbEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkBAgIAAQwCAAAAQEIPAAAAAAA="

private val CANONICAL_KEYPAIR_BYTES =
    listOf(
        41,
        99,
        180,
        88,
        51,
        57,
        48,
        80,
        61,
        63,
        219,
        75,
        176,
        49,
        116,
        254,
        227,
        176,
        196,
        204,
        122,
        47,
        166,
        133,
        155,
        252,
        217,
        0,
        253,
        17,
        49,
        143,
        47,
        94,
        121,
        167,
        195,
        136,
        72,
        22,
        157,
        48,
        77,
        88,
        63,
        96,
        57,
        122,
        181,
        243,
        236,
        188,
        241,
        134,
        174,
        224,
        100,
        246,
        17,
        170,
        104,
        17,
        151,
        48,
    ).map(Int::toByte).toByteArray()
private const val GOLDEN_PUBKEY = "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR"
private const val GOLDEN_MESSAGE_B64 =
    "AQABAy9eeafDiEgWnTBNWD9gOXq18+y88Yau4GT2EapoEZcwAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC" +
        "AgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAAQICAAEMAgAAAEBCDwAAAAAA"
private const val GOLDEN_SIGNED_TX_B64 =
    "AaynSvis6Ib7Ryu0FHtVWQEOaHwqjVtlBUmx5dS8lnDzYlucZlaLBuiwHh2yKYxh9BpT4SnIu2Lkp+dmBFf9Igc" +
        "BAAEDL155p8OISBadME1YP2A5erXz7Lzxhq7gZPYRqmgRlzACAgICAgICAgICAgICAgICAgICAgICAgICAgICAg" +
        "ICAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        "AAABAgIAAQwCAAAAQEIPAAAAAAA="

private val seed = ByteArray(32) { (it + 1).toByte() }
private val publicKey = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
private val keypair = seed + publicKey
private val u8Array = keypair.joinToString(",", "[", "]") { (it.toInt() and 0xff).toString() }
private val unsigned = byteArrayOf(1) + ByteArray(64) + Base64.getDecoder().decode(MESSAGE_B64)
private val lookupTableMessage =
    byteArrayOf(0x80.toByte(), 1, 0, 0, 1) + publicKey + ByteArray(32) + byteArrayOf(0, 1) + ByteArray(32) { 5 } +
        byteArrayOf(1, 0, 1, 1)
private val lookupTableTx = byteArrayOf(0) + lookupTableMessage

private fun keypairFile(contents: String) =
    File.createTempFile("keypair", ".json").apply {
        deleteOnExit()
        writeText(contents)
    }

private fun assertRefused(
    code: String,
    block: () -> Unit,
) = assertEquals(code, assertFailsWith<SignerError> { block() }.code.value)

private fun verifies(
    signature: ByteArray,
    message: ByteArray,
    pubkey: ByteArray,
) = Ed25519Signer().run {
    init(false, Ed25519PublicKeyParameters(pubkey, 0))
    update(message, 0, message.size)
    verifySignature(signature)
}

class MemorySignerTest {
    @Test
    fun `reproduces the Go golden signed transaction`() {
        val signer = MemorySigner.fromBytes(seed)
        val signed = signer.signTransaction(unsigned)
        assertEquals(ADDRESS, signer.address)
        assertEquals(SIGNED_TX_B64, signed.encodedTransaction)
        assertTrue(signed.isComplete)
    }

    @Test
    fun `every key source gives the same address`() {
        val signers =
            listOf(
                MemorySigner.fromBytes(seed),
                MemorySigner.fromBytes(keypair),
                MemorySigner.fromPrivateKeyString(Base58.encode(keypair)),
                MemorySigner.fromPrivateKeyString(" $u8Array\n"),
                MemorySigner.fromKeypairFile(keypairFile(u8Array).path),
            )
        signers.forEach { assertEquals(ADDRESS, it.address) }
    }

    @Test
    fun `invalid keys are refused`() {
        val mismatched = keypair.copyOf().also { it[63] = (it[63] + 1).toByte() }
        val invalid =
            listOf<() -> Unit>(
                { MemorySigner.fromBytes(mismatched) },
                { MemorySigner.fromBytes(ByteArray(48)) },
                { MemorySigner.fromPrivateKeyString(Base58.encode(seed)) },
                { MemorySigner.fromPrivateKeyString("0OIl") },
                { MemorySigner.fromPrivateKeyString("[]") },
                { MemorySigner.fromPrivateKeyString(u8Array.replaceFirst("[1,", "[256,")) },
                { MemorySigner.fromPrivateKeyString(u8Array.replaceFirst("[1,", "[1.0,")) },
            )
        invalid.forEach { assertRefused("SIGNER_INVALID_PRIVATE_KEY", it) }
    }

    @Test
    fun `keypair file failures are refused`() {
        val missing = File.createTempFile("missing", ".json").apply { delete() }
        assertRefused("SIGNER_IO_ERROR") { MemorySigner.fromKeypairFile(missing.path) }
        assertRefused("SIGNER_INVALID_PRIVATE_KEY") {
            MemorySigner.fromKeypairFile(keypairFile(Base58.encode(keypair)).path)
        }
    }

    @Test
    fun `transactions the signer cannot sign are refused`() {
        val signer = MemorySigner.fromBytes(seed)
        val tooFewKeys = unsigned.copyOf().also { it[65] = 4 }
        val v1 = byteArrayOf(0, 0x81.toByte()) + unsigned.copyOfRange(66, unsigned.size)
        assertRefused("SIGNER_SIGNING_FAILED") { MemorySigner.fromBytes(ByteArray(32) { 9 }).signTransaction(unsigned) }
        assertRefused("SIGNER_SIGNING_FAILED") { signer.signTransaction(tooFewKeys) }
        assertRefused("SIGNER_SERIALIZATION_ERROR") { signer.signTransaction(v1) }
        assertRefused("SIGNER_SERIALIZATION_ERROR") { signer.signTransaction(unsigned.copyOf(100)) }
    }

    @Test
    fun `truncated or overlong messages are refused`() {
        val signer = MemorySigner.fromBytes(seed)
        val v0 = byteArrayOf(0, 0x80.toByte(), 1, 0, 0, 1) + publicKey + ByteArray(32) + byteArrayOf(0, 0)
        assertRefused("SIGNER_SERIALIZATION_ERROR") { signer.signTransaction(unsigned.copyOf(unsigned.size - 1)) }
        assertRefused("SIGNER_SERIALIZATION_ERROR") { signer.signTransaction(v0.copyOf(v0.size - 1)) }
        assertRefused("SIGNER_SERIALIZATION_ERROR") { signer.signTransaction(unsigned + byteArrayOf(0)) }
    }

    @Test
    fun `non-canonical lengths and extra signature slots are refused`() {
        val signer = MemorySigner.fromBytes(seed)
        val message = unsigned.copyOfRange(65, unsigned.size)
        assertRefused("SIGNER_SERIALIZATION_ERROR") { signer.signTransaction(byteArrayOf(0x81.toByte(), 0) + ByteArray(64) + message) }
        assertRefused("SIGNER_SERIALIZATION_ERROR") { signer.signTransaction(byteArrayOf(0x80.toByte(), 0x80.toByte(), 0x04) + message) }
        assertRefused("SIGNER_SERIALIZATION_ERROR") { signer.signTransaction(byteArrayOf(2) + ByteArray(128) + message) }
    }

    @Test
    fun `v0 with a lookup table signs`() {
        val signed = MemorySigner.fromBytes(seed).signTransaction(lookupTableTx)
        assertTrue(verifies(signed.signature, lookupTableMessage, publicKey))
        assertTrue(signed.isComplete)
    }

    @Test
    fun `truncated lookup table lists are refused`() {
        val signer = MemorySigner.fromBytes(seed)
        assertRefused("SIGNER_SERIALIZATION_ERROR") { signer.signTransaction(lookupTableTx.copyOf(lookupTableTx.size - 3)) }
        assertRefused("SIGNER_SERIALIZATION_ERROR") { signer.signTransaction(lookupTableTx.copyOf(lookupTableTx.size - 1)) }
    }

    @Test
    fun `a second signer leaves slot 0 zero and the transaction partial`() {
        val signer = MemorySigner.fromBytes(seed)
        val message = byteArrayOf(0x80.toByte(), 2, 0, 0, 2) + ByteArray(32) { 7 } + publicKey + ByteArray(32) + byteArrayOf(0, 0)
        val signed = signer.signTransaction(byteArrayOf(0) + message)
        val wire = Base64.getDecoder().decode(signed.encodedTransaction)
        assertContentEquals(byteArrayOf(2) + ByteArray(64), wire.copyOf(65))
        assertTrue(verifies(wire.copyOfRange(65, 129), message, publicKey))
        assertContentEquals(message, wire.copyOfRange(129, wire.size))
        assertFalse(signed.isComplete)
    }

    @Test
    fun `a second signer keeps the first signature`() {
        val otherSeed = ByteArray(32) { (it + 33).toByte() }
        val otherKey = Ed25519PrivateKeyParameters(otherSeed, 0).generatePublicKey().encoded
        val message = byteArrayOf(0x80.toByte(), 2, 0, 0, 2) + otherKey + publicKey + ByteArray(32) + byteArrayOf(0, 0)
        val first = MemorySigner.fromBytes(seed).signTransaction(byteArrayOf(0) + message)
        assertFalse(first.isComplete)
        val second = MemorySigner.fromBytes(otherSeed).signTransaction(Base64.getDecoder().decode(first.encodedTransaction))
        val wire = Base64.getDecoder().decode(second.encodedTransaction)
        assertEquals(2, wire[0].toInt())
        assertContentEquals(first.signature, wire.copyOfRange(65, 129))
        assertTrue(verifies(wire.copyOfRange(1, 65), message, otherKey))
        assertTrue(verifies(wire.copyOfRange(65, 129), message, publicKey))
        assertTrue(second.isComplete)
    }

    @Test
    fun `errors and the signer render no detail or key material`() {
        val error = assertFailsWith<SignerError> { MemorySigner.fromBytes(ByteArray(31)) }
        assertEquals("Invalid private key format", error.message)
        assertFalse(error.detail in error.toString())
        assertEquals("MemorySigner(address=$ADDRESS)", MemorySigner.fromBytes(seed).toString())
    }

    @Test
    fun `signMessage verifies against the derived pubkey`() {
        val message = "solana-keychain".toByteArray()
        assertTrue(verifies(MemorySigner.fromBytes(seed).signMessage(message), message, publicKey))
    }

    @Test
    fun `legacy golden parity vectors`() {
        val signer = MemorySigner.fromBytes(CANONICAL_KEYPAIR_BYTES)
        val message = Base64.getDecoder().decode(GOLDEN_MESSAGE_B64)
        val signed = signer.signTransaction(byteArrayOf(1) + ByteArray(64) + message)
        assertEquals(GOLDEN_PUBKEY, signer.address)
        assertTrue(signed.isComplete)
        assertEquals(GOLDEN_SIGNED_TX_B64, signed.encodedTransaction)
        assertTrue(verifies(signed.signature, message, CANONICAL_KEYPAIR_BYTES.copyOfRange(32, 64)))
    }
}
