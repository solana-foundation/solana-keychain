package com.solana.keychain.memory

import com.solana.keychain.Base58
import com.solana.keychain.SignedTransaction
import com.solana.keychain.SignerError
import com.solana.keychain.SignerErrorCode
import com.solana.keychain.TransactionSigner
import com.solana.keychain.signWireTransaction
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.File
import java.io.IOException

private const val SEED_LENGTH = 32
private const val KEYPAIR_LENGTH = 64

class MemorySigner private constructor(
    seed: ByteArray,
) : TransactionSigner {
    private val privateKey = Ed25519PrivateKeyParameters(seed, 0)
    private val publicKey = privateKey.generatePublicKey().encoded
    override val address: String = Base58.encode(publicKey)

    override fun signMessage(message: ByteArray): ByteArray =
        Ed25519Signer().run {
            init(true, privateKey)
            update(message, 0, message.size)
            generateSignature()
        }

    override fun signTransaction(transaction: ByteArray): SignedTransaction = signWireTransaction(transaction, publicKey, ::signMessage)

    override fun isAvailable(): Boolean = true

    override fun toString(): String = "MemorySigner(address=$address)"

    companion object {
        fun fromBytes(privateKey: ByteArray): MemorySigner {
            if (privateKey.size != SEED_LENGTH && privateKey.size != KEYPAIR_LENGTH) {
                throw invalidKey("private key must be 32 (seed) or 64 (seed‖pubkey) bytes")
            }
            val signer = MemorySigner(privateKey.copyOf(SEED_LENGTH))
            val publicHalf = privateKey.copyOfRange(SEED_LENGTH, privateKey.size)
            if (privateKey.size == KEYPAIR_LENGTH && !signer.publicKey.contentEquals(publicHalf)) {
                throw invalidKey("public key half does not match the key derived from the seed")
            }
            return signer
        }

        fun fromPrivateKeyString(privateKey: String): MemorySigner {
            val trimmed = privateKey.trim()
            return fromKeypairBytes(if (trimmed.startsWith("[")) parseU8Array(trimmed) else Base58.decode(trimmed))
        }

        fun fromKeypairFile(path: String): MemorySigner {
            val contents =
                try {
                    File(path).readText()
                } catch (e: IOException) {
                    throw SignerError(SignerErrorCode.IO_ERROR, "failed to read keypair file")
                }
            return fromKeypairBytes(parseU8Array(contents.trim()))
        }

        private fun fromKeypairBytes(bytes: ByteArray?): MemorySigner =
            fromBytes(bytes?.takeIf { it.size == KEYPAIR_LENGTH } ?: throw invalidKey("private key must decode to 64 bytes"))

        private fun parseU8Array(text: String): ByteArray? {
            if (!text.startsWith("[") || !text.endsWith("]")) return null
            return text
                .substring(1, text.length - 1)
                .split(",")
                .map {
                    it
                        .trim()
                        .toIntOrNull()
                        ?.takeIf { value -> value in 0..255 }
                        ?.toByte() ?: return null
                }.toByteArray()
        }
    }
}

private fun invalidKey(detail: String) = SignerError(SignerErrorCode.INVALID_PRIVATE_KEY, detail)
