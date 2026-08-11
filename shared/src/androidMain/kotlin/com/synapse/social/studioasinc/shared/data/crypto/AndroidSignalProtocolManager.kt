package com.synapse.social.studioasinc.shared.data.crypto

import android.content.Context
import android.util.Base64
import com.synapse.social.studioasinc.shared.data.crypto.models.EncryptedMessage
import com.synapse.social.studioasinc.shared.data.crypto.models.PreKeyBundle
import com.synapse.social.studioasinc.shared.data.crypto.models.SignalIdentityKeys
import com.synapse.social.studioasinc.shared.data.crypto.models.SignalOneTimePreKey
import com.synapse.social.studioasinc.shared.data.crypto.store.AndroidSignalStore
import com.synapse.social.studioasinc.shared.util.Logger
import org.whispersystems.libsignal.IdentityKey
import org.whispersystems.libsignal.IdentityKeyPair
import org.whispersystems.libsignal.SessionBuilder
import org.whispersystems.libsignal.SessionCipher
import org.whispersystems.libsignal.SignalProtocolAddress
import org.whispersystems.libsignal.protocol.CiphertextMessage
import org.whispersystems.libsignal.protocol.PreKeySignalMessage
import org.whispersystems.libsignal.protocol.SignalMessage
import org.whispersystems.libsignal.state.PreKeyRecord
import org.whispersystems.libsignal.util.KeyHelper
import org.whispersystems.libsignal.ecc.Curve
import org.whispersystems.libsignal.state.SignedPreKeyRecord
import org.whispersystems.libsignal.state.PreKeyBundle as SignalNativePreKeyBundle

class AndroidSignalProtocolManager(
    context: Context
) : SignalProtocolManager {

    private val store = AndroidSignalStore(context)

    private companion object {
        const val DEVICE_ID = 1
        const val TAG = "E2EE"
    }

    // ============================================================
    // Identity + Signed PreKey
    // ============================================================

    override suspend fun generateIdentityAndKeys(): SignalIdentityKeys {

        val identityKeyPair: IdentityKeyPair
        val registrationId: Int

        if (store.hasIdentity()) {

            Logger.d(
                "E2EE_INIT: Reusing existing identity key pair",
                tag = TAG
            )

            identityKeyPair = store.identityKeyPair
            registrationId = store.getLocalRegistrationId()

        } else {

            Logger.d(
                "E2EE_INIT: Generating new identity key pair",
                tag = TAG
            )

            identityKeyPair =
                KeyHelper.generateIdentityKeyPair()

            registrationId =
                KeyHelper.generateRegistrationId(false)

            store.storeLocalIdentity(
                identityKeyPair,
                registrationId
            )
        }

        /*
         * Generate a new Signed PreKey.
         *
         * The ID is generated from the current time to avoid
         * constantly overwriting the same local SignedPreKey.
         */
        val signedPreKeyId =
            (System.currentTimeMillis() / 1000L % 0x00FFFFFFL)
                .toInt()

        val signedPreKey =
            KeyHelper.generateSignedPreKey(
                identityKeyPair,
                signedPreKeyId
            )

        store.storeSignedPreKey(
            signedPreKey.id,
            signedPreKey
        )

        Logger.d(
            "E2EE_INIT: Identity ready. " +
                    "registrationId=$registrationId " +
                    "signedPreKeyId=${signedPreKey.id}",
            tag = TAG
        )

        return SignalIdentityKeys(
            registrationId = registrationId,

            identityKey =
                Base64.encodeToString(
                    identityKeyPair.publicKey.serialize(),
                    Base64.NO_WRAP
                ),

            signedPreKeyId =
                signedPreKey.id,

            signedPreKey =
                Base64.encodeToString(
                    signedPreKey.keyPair.publicKey.serialize(),
                    Base64.NO_WRAP
                ),

            signedPreKeySignature =
                Base64.encodeToString(
                    signedPreKey.signature,
                    Base64.NO_WRAP
                )
        )
    }

    // ============================================================
    // One-Time PreKeys
    // ============================================================

    override suspend fun generateOneTimePreKeys(
        startId: Int,
        count: Int
    ): List<SignalOneTimePreKey> {

        require(startId >= 0) {
            "startId must be >= 0"
        }

        require(count > 0) {
            "count must be > 0"
        }

        Logger.d(
            "E2EE_INIT: Generating $count one-time pre-keys " +
                    "starting from ID $startId",
            tag = TAG
        )

        val preKeys =
            KeyHelper.generatePreKeys(
                startId,
                count
            )

        val resultList =
            mutableListOf<SignalOneTimePreKey>()

        for (preKey in preKeys) {

            store.storePreKey(
                preKey.id,
                preKey
            )

            resultList.add(
                SignalOneTimePreKey(
                    keyId = preKey.id,

                    publicKey =
                        Base64.encodeToString(
                            preKey.keyPair.publicKey.serialize(),
                            Base64.NO_WRAP
                        )
                )
            )
        }

        Logger.d(
            "E2EE_INIT: Generated and stored " +
                    "${resultList.size} one-time pre-keys",
            tag = TAG
        )

        return resultList
    }

    // ============================================================
    // Session Establishment
    // ============================================================

    override suspend fun processPreKeyBundle(
        userId: String,
        bundle: PreKeyBundle
    ) {

        require(userId.isNotBlank()) {
            "Recipient userId cannot be empty"
        }

        Logger.d(
            "E2EE_SESSION: Processing pre-key bundle for user $userId",
            tag = TAG
        )

        val address =
            SignalProtocolAddress(
                userId,
                DEVICE_ID
            )

        /*
         * Decode recipient identity key.
         */
        val identityKeyBytes =
            try {
                Base64.decode(
                    bundle.identityKey,
                    Base64.DEFAULT
                )
            } catch (e: Exception) {

                throw IllegalStateException(
                    "Invalid recipient identity key",
                    e
                )
            }

        /*
         * Decode signed pre-key.
         */
        val signedPreKeyBytes =
            try {
                Base64.decode(
                    bundle.signedPreKeyPublic,
                    Base64.DEFAULT
                )
            } catch (e: Exception) {

                throw IllegalStateException(
                    "Invalid recipient signed pre-key",
                    e
                )
            }

        /*
         * Decode signed pre-key signature.
         */
        val signedPreKeySignature =
            try {
                Base64.decode(
                    bundle.signedPreKeySignature,
                    Base64.DEFAULT
                )
            } catch (e: Exception) {

                throw IllegalStateException(
                    "Invalid recipient signed pre-key signature",
                    e
                )
            }

        /*
         * One-Time PreKey is optional.
         *
         * Signal allows a bundle without a one-time pre-key.
         */
        val preKeyPublic =
            if (
                bundle.preKeyId != null &&
                !bundle.preKeyPublic.isNullOrBlank()
            ) {

                try {

                    Curve.decodePoint(
                        Base64.decode(
                            bundle.preKeyPublic,
                            Base64.DEFAULT
                        ),
                        0
                    )

                } catch (e: Exception) {

                    throw IllegalStateException(
                        "Invalid recipient one-time pre-key",
                        e
                    )
                }

            } else {
                null
            }

        val signedPreKeyPublic =
            try {

                Curve.decodePoint(
                    signedPreKeyBytes,
                    0
                )

            } catch (e: Exception) {

                throw IllegalStateException(
                    "Failed to decode recipient signed pre-key",
                    e
                )
            }

        val identityKey =
            try {

                IdentityKey(
                    identityKeyBytes,
                    0
                )

            } catch (e: Exception) {

                throw IllegalStateException(
                    "Failed to decode recipient identity key",
                    e
                )
            }

        /*
         * Build the native libsignal PreKeyBundle.
         *
         * If there is no One-Time PreKey, -1 is used as the ID
         * and the public key remains null.
         */
        val nativeBundle =
            SignalNativePreKeyBundle(
                bundle.registrationId,
                bundle.deviceId,
                bundle.preKeyId ?: -1,
                preKeyPublic,
                bundle.signedPreKeyId,
                signedPreKeyPublic,
                signedPreKeySignature,
                identityKey
            )

        try {

            val sessionBuilder =
                SessionBuilder(
                    store,
                    address
                )

            sessionBuilder.process(
                nativeBundle
            )

            Logger.d(
                "E2EE_SESSION: Successfully established " +
                        "session for user $userId",
                tag = TAG
            )

        } catch (e: Exception) {

            Logger.d(
                "E2EE_SESSION: Failed to establish session " +
                        "for user $userId: ${e.message}",
                tag = TAG
            )

            throw IllegalStateException(
                "Failed to establish E2EE session for $userId",
                e
            )
        }
    }

    // ============================================================
    // Session Checks
    // ============================================================

    override suspend fun hasSession(
        userId: String
    ): Boolean {

        val address =
            SignalProtocolAddress(
                userId,
                DEVICE_ID
            )

        return store.containsSession(
            address
        )
    }

    // ============================================================
    // Delete Session
    // ============================================================

    override suspend fun deleteSession(
        userId: String
    ) {

        Logger.d(
            "E2EE_SESSION: Deleting session for user $userId",
            tag = TAG
        )

        val address =
            SignalProtocolAddress(
                userId,
                DEVICE_ID
            )

        store.deleteSession(
            address
        )

        Logger.d(
            "E2EE_SESSION: Session deleted for user $userId",
            tag = TAG
        )
    }

    // ============================================================
    // Delete All Sessions
    // ============================================================

    override suspend fun deleteAllSessions() {

        Logger.d(
            "E2EE_SESSION: Deleting all sessions",
            tag = TAG
        )

        /*
         * AndroidSignalStore must implement:
         *
         * deleteAllSessions(null)
         *
         * as "delete every session".
         */
        store.deleteAllSessions(null)

        Logger.d(
            "E2EE_SESSION: All sessions deleted",
            tag = TAG
        )
    }

    // ============================================================
    // Delete Remote Identity
    // ============================================================

    override suspend fun deleteIdentity(
        userId: String
    ) {

        Logger.d(
            "E2EE_SESSION: Deleting identity for user $userId",
            tag = TAG
        )

        val address =
            SignalProtocolAddress(
                userId,
                DEVICE_ID
            )

        store.deleteIdentity(
            address
        )

        Logger.d(
            "E2EE_SESSION: Identity deleted for user $userId",
            tag = TAG
        )
    }

    // ============================================================
    // Encrypt
    // ============================================================

    override suspend fun encryptMessage(
        recipientId: String,
        message: ByteArray
    ): EncryptedMessage {

        require(recipientId.isNotBlank()) {
            "Recipient ID cannot be empty"
        }

        require(message.isNotEmpty()) {
            "Message cannot be empty"
        }

        Logger.d(
            "E2EE_ENCRYPT: Encrypting message for recipient $recipientId",
            tag = TAG
        )

        val address =
            SignalProtocolAddress(
                recipientId,
                DEVICE_ID
            )

        /*
         * SessionCipher will use the existing session.
         *
         * A session MUST normally be established first using
         * processPreKeyBundle().
         */
        if (!store.containsSession(address)) {

            Logger.d(
                "E2EE_ENCRYPT: No session found for $recipientId",
                tag = TAG
            )

            throw IllegalStateException(
                "No E2EE session exists for recipient $recipientId"
            )
        }

        try {

            val sessionCipher =
                SessionCipher(
                    store,
                    address
                )

            val ciphertextMessage =
                sessionCipher.encrypt(
                    message
                )

            Logger.d(
                "E2EE_ENCRYPT: Successfully encrypted message " +
                        "(recipient=$recipientId, " +
                        "type=${ciphertextMessage.type})",
                tag = TAG
            )

            return EncryptedMessage(
                type = ciphertextMessage.type,

                body =
                    Base64.encodeToString(
                        ciphertextMessage.serialize(),
                        Base64.NO_WRAP
                    ),

                registrationId =
                    store.getLocalRegistrationId()
            )

        } catch (e: Exception) {

            Logger.d(
                "E2EE_ENCRYPT: Encryption failed for " +
                        "$recipientId: ${e.message}",
                tag = TAG
            )

            throw IllegalStateException(
                "Failed to encrypt message for recipient $recipientId",
                e
            )
        }
    }

    // ============================================================
    // Decrypt
    // ============================================================

    override suspend fun decryptMessage(
        senderId: String,
        message: EncryptedMessage
    ): ByteArray {

        require(senderId.isNotBlank()) {
            "Sender ID cannot be empty"
        }

        require(message.body.isNotBlank()) {
            "Encrypted message body cannot be empty"
        }

        Logger.d(
            "E2EE_DECRYPT: Decrypting message from sender $senderId " +
                    "(type=${message.type})",
            tag = TAG
        )

        val address =
            SignalProtocolAddress(
                senderId,
                DEVICE_ID
            )

        val sessionCipher =
            SessionCipher(
                store,
                address
            )

        val decodedBody =
            try {

                Base64.decode(
                    message.body,
                    Base64.DEFAULT
                )

            } catch (e: Exception) {

                throw IllegalStateException(
                    "Invalid encrypted message Base64",
                    e
                )
            }

        try {

            val decrypted =
                if (
                    message.type ==
                    CiphertextMessage.PREKEY_TYPE
                ) {

                    sessionCipher.decrypt(
                        PreKeySignalMessage(
                            decodedBody
                        )
                    )

                } else {

                    sessionCipher.decrypt(
                        SignalMessage(
                            decodedBody
                        )
                    )
                }

            Logger.d(
                "E2EE_DECRYPT: Successfully decrypted message " +
                        "from $senderId",
                tag = TAG
            )

            return decrypted

        } catch (e: Exception) {

            Logger.d(
                "E2EE_DECRYPT: Failed to decrypt message " +
                        "from $senderId: ${e.message}",
                tag = TAG
            )

            throw IllegalStateException(
                "Failed to decrypt message from $senderId",
                e
            )
        }
    }

    // ============================================================
    // Local Registration ID
    // ============================================================

    override suspend fun getLocalRegistrationId(): Int {

        return store.getLocalRegistrationId()
    }

    // ============================================================
    // Local Identity Key
    // ============================================================

    override suspend fun getLocalIdentityKey(): String {

        return Base64.encodeToString(
            store.identityKeyPair.publicKey.serialize(),
            Base64.NO_WRAP
        )
    }

    // ============================================================
    // Key Rotation
    // ============================================================

    override suspend fun checkKeyRotationNeeded(
        thresholdDays: Int
    ): Boolean {

        return store.checkKeyRotationNeeded(
            thresholdDays
        )
    }

    // ============================================================
    // Has Identity
    // ============================================================

    override suspend fun hasIdentity(): Boolean {

        return store.hasIdentity()
    }
}
