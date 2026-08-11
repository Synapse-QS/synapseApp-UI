package com.synapse.social.studioasinc.shared.data.repository

import com.synapse.social.studioasinc.shared.data.crypto.SignalProtocolManager
import com.synapse.social.studioasinc.shared.data.crypto.models.EncryptedMessage
import com.synapse.social.studioasinc.shared.data.crypto.models.PreKeyBundle
import com.synapse.social.studioasinc.shared.data.datasource.SupabaseChatDataSource
import com.synapse.social.studioasinc.shared.data.dto.chat.MessageDto
import com.synapse.social.studioasinc.shared.data.local.database.CachedMessageDao
import com.synapse.social.studioasinc.shared.util.Logger
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Centralizes E2EE logic for chat messages.
 */
internal class ChatEncryptionHelper(
    private val signalProtocolManager: SignalProtocolManager?,
    private val dataSource: SupabaseChatDataSource,
    private val cachedMessageDao: CachedMessageDao?
) {

    /**
     * Decrypted-message memory cache.
     */
    val decryptedMessageCache =
        mutableMapOf<String, String>()

    // ============================================================
    // JSON / CONTENT HELPERS
    // ============================================================

    private fun extractContent(
        jsonString: String
    ): Pair<String, String?> {

        return try {

            val jsonPayload =
                Json.parseToJsonElement(
                    jsonString
                ).jsonObject

            val content =
                jsonPayload["content"]
                    ?.jsonPrimitive
                    ?.content
                    ?: jsonString

            val mediaUrl =
                jsonPayload["mediaUrl"]
                    ?.jsonPrimitive
                    ?.content

            Pair(
                content,
                mediaUrl
            )

        } catch (_: Exception) {

            Pair(
                jsonString,
                null
            )
        }
    }

    // ============================================================
    // DECRYPT MESSAGE
    // ============================================================

    suspend fun MessageDto.decryptIfNecessary(
        currentUserId: String
    ): MessageDto {

        val messageId =
            this.id
                ?: return this

        // --------------------------------------------------------
        // 1. Memory cache
        // --------------------------------------------------------

        decryptedMessageCache[
            messageId
        ]?.let { cached ->

            Logger.d(
                "E2EE_DECRYPT: Found message $messageId in memory cache",
                tag = "E2EE"
            )

            val (
                content,
                mediaUrl
            ) = extractContent(cached)

            return this.copy(
                content = content,
                mediaUrl =
                    mediaUrl
                        ?: this.mediaUrl
            )
        }

        // --------------------------------------------------------
        // 2. Local database cache
        // --------------------------------------------------------

        val dbCached =
            try {

                cachedMessageDao
                    ?.getMessages(
                        chatId ?: "",
                        200
                    )
                    ?.find {
                        it.id == messageId
                    }

            } catch (_: Exception) {

                null
            }

        val placeholders =
            setOf(
                "Message is encrypted",
                "🔒 Encrypted message",
                "🔒 You sent an encrypted message",
                "🔒 You sent an encrypted message (Copy)"
            )

        if (
            dbCached != null &&
            dbCached.content !in placeholders &&
            dbCached.content.isNotBlank()
        ) {

            Logger.d(
                "E2EE_DECRYPT: Found message $messageId in DB cache",
                tag = "E2EE"
            )

            decryptedMessageCache[
                messageId
            ] = dbCached.content

            return this.copy(
                content = dbCached.content,
                mediaUrl =
                    dbCached.mediaUrl
                        ?: this.mediaUrl
            )
        }

        // --------------------------------------------------------
        // 3. Try to parse encrypted payload
        // --------------------------------------------------------

        try {

            val jsonElement =
                Json.parseToJsonElement(
                    this.content
                ).jsonObject

            val looksLikeEncryptedPayload =
                jsonElement.values
                    .firstOrNull()
                    ?.let {

                        it is kotlinx.serialization.json.JsonObject &&
                                it.containsKey("type") &&
                                it.containsKey("body")

                    }
                    == true

            if (!looksLikeEncryptedPayload) {
                return this
            }

            val manager =
                signalProtocolManager
                    ?: return this.copy(
                        content =
                            if (
                                this.senderId ==
                                currentUserId
                            ) {
                                "🔒 You sent an encrypted message"
                            } else {
                                "🔒 Encrypted message"
                            }
                    )

            val myPayloadElement =
                jsonElement[
                    currentUserId
                ]

            if (myPayloadElement == null) {

                Logger.w(
                    "E2EE_DECRYPT: No encrypted payload found for current user $currentUserId",
                    tag = "E2EE"
                )

                return this.copy(
                    content =
                        if (
                            this.senderId ==
                            currentUserId
                        ) {
                            "🔒 You sent an encrypted message"
                        } else {
                            "🔒 Encrypted message"
                        }
                )
            }

            val myPayload =
                Json.decodeFromJsonElement(
                    EncryptedMessage.serializer(),
                    myPayloadElement
                )

            try {

                val decryptedBytes =
                    manager.decryptMessage(
                        senderId = this.senderId,
                        message = myPayload
                    )

                val decryptedContent =
                    decryptedBytes.decodeToString()

                Logger.d(
                    "E2EE_DECRYPT: Successfully decrypted message $messageId",
                    tag = "E2EE"
                )

                decryptedMessageCache[
                    messageId
                ] = decryptedContent

                val (
                    content,
                    mediaUrl
                ) = extractContent(
                    decryptedContent
                )

                try {

                    cachedMessageDao
                        ?.updateContent(
                            messageId,
                            content
                        )

                } catch (_: Exception) {
                }

                return this.copy(
                    content = content,
                    mediaUrl =
                        mediaUrl
                            ?: this.mediaUrl
                )

            } catch (decryptError: Exception) {

                Logger.e(
                    "E2EE_DECRYPT: Signal decryption failed for message $messageId",
                    tag = "E2EE",
                    throwable = decryptError
                )
            }

            return this.copy(
                content =
                    if (
                        this.senderId ==
                        currentUserId
                    ) {
                        "🔒 You sent an encrypted message"
                    } else {
                        "🔒 Encrypted message"
                    }
            )

        } catch (_: Exception) {

            /*
             * Not encrypted JSON.
             * Treat it as plaintext.
             */
            return this
        }
    }

    // ============================================================
    // ENSURE SESSION
    // ============================================================

    /**
     * Makes sure a Signal session exists for the specified user.
     *
     * IMPORTANT:
     *
     * A session existing locally does NOT necessarily mean
     * that the session is valid.
     *
     * This method can optionally force a session rebuild.
     */
    suspend fun ensureSession(
        userId: String,
        forceRebuild: Boolean = false
    ) {

        val manager =
            signalProtocolManager
                ?: throw IllegalStateException(
                    "SignalProtocolManager is null"
                )

        if (userId.isBlank()) {

            throw IllegalArgumentException(
                "Cannot establish E2EE session for empty user ID"
            )
        }

        // --------------------------------------------------------
        // Existing valid-looking session
        // --------------------------------------------------------

        if (
            manager.hasSession(userId) &&
            !forceRebuild
        ) {

            Logger.d(
                "E2EE_SESSION: Session already exists for user $userId",
                tag = "E2EE"
            )

            return
        }

        // --------------------------------------------------------
        // Force rebuild
        // --------------------------------------------------------

        if (forceRebuild) {

            Logger.w(
                "E2EE_SESSION: Force rebuilding session for user $userId",
                tag = "E2EE"
            )

            try {

                manager.deleteSession(
                    userId
                )

            } catch (e: Exception) {

                Logger.w(
                    "E2EE_SESSION: Failed to delete old session: ${e.message}",
                    tag = "E2EE"
                )
            }
        }

        // --------------------------------------------------------
        // Fetch remote bundle
        // --------------------------------------------------------

        Logger.d(
            "E2EE_SESSION: Fetching public key bundle for $userId",
            tag = "E2EE"
        )

        val keyDto =
            dataSource.getUserPublicKey(
                userId
            )

        if (keyDto == null) {

            Logger.e(
                "E2EE_SESSION: Public key bundle not found for $userId",
                tag = "E2EE"
            )

            throw IllegalStateException(
                "Recipient hasn't enabled E2EE"
            )
        }

        // --------------------------------------------------------
        // Decode bundle
        // --------------------------------------------------------

        val bundle =
            try {

                Json.decodeFromString<PreKeyBundle>(
                    keyDto.publicKey
                )

            } catch (e: Exception) {

                Logger.e(
                    "E2EE_SESSION: Invalid public key bundle for $userId",
                    tag = "E2EE",
                    throwable = e
                )

                throw IllegalStateException(
                    "Recipient has an invalid E2EE key bundle",
                    e
                )
            }

        // --------------------------------------------------------
        // Validate bundle
        // --------------------------------------------------------

        if (bundle.identityKey.isBlank()) {

            throw IllegalStateException(
                "Recipient identity key is missing"
            )
        }

        if (bundle.signedPreKeyPublic.isBlank()) {

            throw IllegalStateException(
                "Recipient signed pre-key is missing"
            )
        }

        if (bundle.signedPreKeySignature.isBlank()) {

            throw IllegalStateException(
                "Recipient signed pre-key signature is missing"
            )
        }

        if (bundle.registrationId <= 0) {

            throw IllegalStateException(
                "Recipient registration ID is invalid"
            )
        }

        // --------------------------------------------------------
        // Process Signal bundle
        // --------------------------------------------------------

        try {

            Logger.d(
                "E2EE_SESSION: Processing bundle for user $userId " +
                        "(registrationId=${bundle.registrationId}, " +
                        "deviceId=${bundle.deviceId}, " +
                        "preKeyId=${bundle.preKeyId}, " +
                        "signedPreKeyId=${bundle.signedPreKeyId})",
                tag = "E2EE"
            )

            manager.processPreKeyBundle(
                userId,
                bundle
            )

            if (!manager.hasSession(userId)) {

                throw IllegalStateException(
                    "Signal session was not created"
                )
            }

            Logger.d(
                "E2EE_SESSION: Session established successfully for $userId",
                tag = "E2EE"
            )

        } catch (e: Exception) {

            Logger.e(
                "E2EE_SESSION: Failed to establish session for $userId",
                tag = "E2EE",
                throwable = e
            )

            throw e
        }
    }

    // ============================================================
    // INITIALIZE E2EE
    // ============================================================

    suspend fun initializeE2EE(
        currentUserId: String?
    ): Result<Unit> {

        return try {

            val manager =
                signalProtocolManager
                    ?: return Result.failure(
                        IllegalStateException(
                            "SignalProtocolManager is null, E2EE not available"
                        )
                    )

            if (currentUserId.isNullOrBlank()) {

                return Result.failure(
                    IllegalStateException(
                        "User not authenticated, cannot initialize E2EE"
                    )
                )
            }

            Logger.d(
                "E2EE_INIT: Starting E2EE initialization for $currentUserId",
                tag = "E2EE"
            )

            // ----------------------------------------------------
            // Local keys
            // ----------------------------------------------------

            val hasLocalKeys =
                manager.hasIdentity()

            // ----------------------------------------------------
            // Remote keys
            // ----------------------------------------------------

            val remoteKeyDto =
                try {

                    dataSource.getUserPublicKey(
                        currentUserId
                    )

                } catch (e: Exception) {

                    Logger.w(
                        "E2EE_INIT: Failed to fetch remote keys: ${e.message}",
                        tag = "E2EE"
                    )

                    null
                }

            val hasRemoteKeys =
                remoteKeyDto != null

            // ----------------------------------------------------
            // Identity comparison
            // ----------------------------------------------------

            var isIdentityMismatch =
                false

            if (
                hasLocalKeys &&
                hasRemoteKeys &&
                remoteKeyDto != null
            ) {

                try {

                    val localIdentity =
                        manager.getLocalIdentityKey()

                    val remoteBundle =
                        Json.decodeFromString<PreKeyBundle>(
                            remoteKeyDto.publicKey
                        )

                    if (
                        localIdentity !=
                        remoteBundle.identityKey
                    ) {

                        Logger.w(
                            "E2EE_INIT: Identity mismatch detected",
                            tag = "E2EE"
                        )

                        isIdentityMismatch =
                            true
                    }

                } catch (e: Exception) {

                    Logger.e(
                        "E2EE_INIT: Failed to compare identities",
                        tag = "E2EE",
                        throwable = e
                    )
                }
            }

            Logger.d(
                "E2EE_INIT: " +
                        "hasLocalKeys=$hasLocalKeys, " +
                        "hasRemoteKeys=$hasRemoteKeys, " +
                        "mismatch=$isIdentityMismatch",
                tag = "E2EE"
            )

            // ====================================================
            // CASE 1
            // Both local and remote exist and identity matches
            // ====================================================

            if (
                hasLocalKeys &&
                hasRemoteKeys &&
                !isIdentityMismatch
            ) {

                val registrationId =
                    manager.getLocalRegistrationId()

                Logger.d(
                    "E2EE_INIT: E2EE already initialized " +
                            "(registrationId=$registrationId)",
                    tag = "E2EE"
                )

                if (
                    manager.checkKeyRotationNeeded()
                ) {

                    Logger.w(
                        "E2EE_INIT: Key rotation recommended",
                        tag = "E2EE"
                    )
                }

                return Result.success(Unit)
            }

            // ====================================================
            // CASE 2
            // Local keys exist but remote is missing/mismatched
            // ====================================================

            if (
                hasLocalKeys &&
                (!hasRemoteKeys || isIdentityMismatch)
            ) {

                if (isIdentityMismatch) {

                    Logger.w(
                        "E2EE_INIT: Identity mismatch. " +
                                "Clearing local sessions.",
                        tag = "E2EE"
                    )

                    manager.deleteAllSessions()
                }

                Logger.d(
                    "E2EE_INIT: Building local E2EE bundle",
                    tag = "E2EE"
                )

                val bundle =
                    buildBundleFromLocalKeys()

                val bundleString =
                    Json.encodeToString(
                        bundle
                    )

                dataSource.uploadUserPublicKey(
                    bundleString
                )

                Logger.d(
                    "E2EE_INIT: E2EE bundle uploaded successfully",
                    tag = "E2EE"
                )

                return Result.success(Unit)
            }

            // ====================================================
            // CASE 3
            // No local identity
            // ====================================================

            Logger.d(
                "E2EE_INIT: Generating new E2EE identity",
                tag = "E2EE"
            )

            val identity =
                manager.generateIdentityAndKeys()

            Logger.d(
                "E2EE_INIT: Identity generated " +
                        "(registrationId=${identity.registrationId})",
                tag = "E2EE"
            )

            /*
             * IMPORTANT:
             *
             * Do not keep blindly using 1..100 forever.
             *
             * This is still compatible with your current API,
             * but the backend should eventually allocate/track
             * One-Time PreKey IDs properly.
             */
            val preKeys =
                manager.generateOneTimePreKeys(
                    startId = 1,
                    count = 100
                )

            if (preKeys.isEmpty()) {

                throw IllegalStateException(
                    "Failed to generate one-time pre-keys"
                )
            }

            Logger.d(
                "E2EE_INIT: Generated ${preKeys.size} one-time pre-keys",
                tag = "E2EE"
            )

            val firstPreKey =
                preKeys.first()

            val bundle =
                PreKeyBundle(
                    registrationId =
                        identity.registrationId,

                    deviceId = 1,

                    preKeyId =
                        firstPreKey.keyId,

                    preKeyPublic =
                        firstPreKey.publicKey,

                    signedPreKeyId =
                        identity.signedPreKeyId,

                    signedPreKeyPublic =
                        identity.signedPreKey,

                    signedPreKeySignature =
                        identity.signedPreKeySignature,

                    identityKey =
                        identity.identityKey
                )

            val bundleString =
                Json.encodeToString(
                    bundle
                )

            Logger.d(
                "E2EE_INIT: Uploading E2EE bundle",
                tag = "E2EE"
            )

            dataSource.uploadUserPublicKey(
                bundleString
            )

            Logger.d(
                "E2EE_INIT: E2EE initialization completed",
                tag = "E2EE"
            )

            Result.success(Unit)

        } catch (e: Exception) {

            Logger.e(
                "E2EE_INIT: Initialization failed: ${e.message}",
                tag = "E2EE",
                throwable = e
            )

            Result.failure(
                e
            )
        }
    }

    // ============================================================
    // BUILD LOCAL BUNDLE
    // ============================================================

    private suspend fun buildBundleFromLocalKeys():
        PreKeyBundle {

        val manager =
            signalProtocolManager
                ?: throw IllegalStateException(
                    "SignalProtocolManager is null"
                )

        val registrationId =
            manager.getLocalRegistrationId()

        val identityKey =
            manager.getLocalIdentityKey()

        /*
         * Generate a fresh batch of One-Time PreKeys.
         *
         * NOTE:
         * Your current API does not expose the next unused ID,
         * so this remains compatible with your current project.
         */
        val preKeys =
            manager.generateOneTimePreKeys(
                startId = 1,
                count = 100
            )

        if (preKeys.isEmpty()) {

            throw IllegalStateException(
                "Failed to generate one-time pre-keys"
            )
        }

        /*
         * generateIdentityAndKeys() reuses the existing
         * IdentityKeyPair and creates a fresh SignedPreKey.
         */
        val identity =
            manager.generateIdentityAndKeys()

        val firstPreKey =
            preKeys.first()

        return PreKeyBundle(

            registrationId =
                registrationId,

            deviceId =
                1,

            preKeyId =
                firstPreKey.keyId,

            preKeyPublic =
                firstPreKey.publicKey,

            signedPreKeyId =
                identity.signedPreKeyId,

            signedPreKeyPublic =
                identity.signedPreKey,

            signedPreKeySignature =
                identity.signedPreKeySignature,

            identityKey =
                identityKey
        )
    }
}
