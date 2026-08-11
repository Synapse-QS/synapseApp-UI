package com.synapse.social.studioasinc.shared.domain.usecase.chat

import com.synapse.social.studioasinc.shared.data.crypto.SignalProtocolManager
import com.synapse.social.studioasinc.shared.data.crypto.models.EncryptedMessage
import com.synapse.social.studioasinc.shared.domain.model.chat.Message
import com.synapse.social.studioasinc.shared.domain.repository.ChatRepository
import io.github.aakira.napier.Napier
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.put
import kotlinx.serialization.json.buildJsonObject

/**
 * UseCase responsible for sending messages with End-to-End Encryption (E2EE).
 *
 * Plaintext is NEVER sent when E2EE is enabled.
 *
 * If an existing Signal session is invalid or corrupted, the use case
 * deletes/rebuilds the session once and retries encryption.
 */
class SendMessageUseCase(
    private val repository: ChatRepository,
    private val signalProtocolManager: SignalProtocolManager? = null
) {

    /**
     * Executes the message sending flow.
     */
    suspend operator fun invoke(
        chatId: String,
        content: String,
        mediaUrl: String? = null,
        messageType: String = "text",
        expiresAt: String? = null,
        replyToId: String? = null
    ): Result<Message> {

        val currentUserId =
            repository.getCurrentUserId()
                ?: return Result.failure(
                    Exception("Not logged in")
                )

        // ============================================================
        // E2EE MUST BE AVAILABLE
        // ============================================================

        if (signalProtocolManager == null) {

            Napier.e(
                "E2EE_ENCRYPT: SignalProtocolManager is null. " +
                        "Plaintext sending is disabled.",
                tag = "E2EE"
            )

            return Result.failure(
                Exception(
                    "End-to-End Encryption is not available. " +
                            "Message was not sent."
                )
            )
        }

        return try {

            // ========================================================
            // GET PARTICIPANTS
            // ========================================================

            val groupMembers =
                repository
                    .getParticipantIds(chatId)
                    .getOrElse {

                        return Result.failure(
                            Exception(
                                "Failed to fetch participants for encryption"
                            )
                        )
                    }

            // --------------------------------------------------------
            // Exclude current user
            // --------------------------------------------------------

            var otherParticipants =
                groupMembers.filter {
                    it != currentUserId
                }

            // --------------------------------------------------------
            // Self-chat
            // --------------------------------------------------------

            if (
                otherParticipants.isEmpty() &&
                groupMembers.isNotEmpty()
            ) {

                otherParticipants =
                    groupMembers
            }

            if (otherParticipants.isEmpty()) {

                return Result.failure(
                    Exception(
                        "Chat $chatId has no other participants " +
                                "to encrypt for"
                    )
                )
            }

            // ========================================================
            // BUILD PLAINTEXT PAYLOAD
            // ========================================================

            /*
             * This exists ONLY in memory.
             *
             * It will NEVER be passed to repository.sendMessage()
             * as senderPlaintext.
             */

            val jsonPayload =
                buildJsonObject {

                    put(
                        "content",
                        content
                    )

                    if (mediaUrl != null) {

                        put(
                            "mediaUrl",
                            mediaUrl
                        )
                    }
                }.toString()

            val contentBytes =
                jsonPayload.encodeToByteArray()

            // ========================================================
            // ENCRYPT FOR ALL PARTICIPANTS
            // ========================================================

            val payloadMap:
                    Map<String, JsonElement> = coroutineScope {

                otherParticipants
                    .map { userId ->

                        async {

                            encryptForRecipient(
                                userId = userId,
                                contentBytes = contentBytes
                            )
                        }
                    }
                    .awaitAll()
                    .filterNotNull()
                    .toMap()
            }

            // ========================================================
            // NEVER SEND PARTIAL ENCRYPTION
            // ========================================================

            if (
                payloadMap.size !=
                otherParticipants.size
            ) {

                Napier.e(
                    "E2EE_ENCRYPT: Encryption failed for " +
                            "${otherParticipants.size - payloadMap.size} " +
                            "recipient(s). Message NOT sent.",
                    tag = "E2EE"
                )

                return Result.failure(
                    Exception(
                        "Encryption failed for one or more recipients. " +
                                "Message was not sent."
                    )
                )
            }

            // ========================================================
            // BUILD ENCRYPTED JSON
            // ========================================================

            val encryptedPayload =
                JsonObject(
                    payloadMap
                ).toString()

            Napier.d(
                "E2EE_ENCRYPT: Message encrypted successfully " +
                        "for ${payloadMap.size} recipient(s)",
                tag = "E2EE"
            )

            // ========================================================
            // SEND ONLY CIPHERTEXT
            // ========================================================

            /*
             * IMPORTANT:
             *
             * senderPlaintext MUST be null.
             *
             * Passing jsonPayload here would store/send plaintext
             * somewhere in the repository/database.
             */

            repository.sendMessage(
                chatId = chatId,
                content = encryptedPayload,
                mediaUrl = null,
                messageType = messageType,
                expiresAt = expiresAt,
                replyToId = replyToId,
                senderPlaintext = null
            )

        } catch (e: Exception) {

            Napier.e(
                "E2EE_ENCRYPT: Failed: ${e.message}",
                tag = "E2EE",
                throwable = e
            )

            Result.failure(
                Exception(
                    "Encryption Error: ${
                        e.message ?: "Unknown error"
                    }",
                    e
                )
            )
        }
    }

    // ================================================================
    // ENCRYPT FOR ONE RECIPIENT
    // ================================================================

    /**
     * Encrypts the message for a single recipient.
     *
     * First attempt:
     *
     *     Existing session -> encrypt
     *
     * If that fails:
     *
     *     Delete/rebuild session -> encrypt again
     *
     * Only one retry is performed.
     */
    private suspend fun encryptForRecipient(
        userId: String,
        contentBytes: ByteArray
    ): Pair<String, JsonElement>? {

        // ============================================================
        // FIRST ATTEMPT
        // ============================================================

        try {

            Napier.d(
                "E2EE_ENCRYPT: Establishing session with $userId",
                tag = "E2EE"
            )

            repository.ensureSession(
                userId
            )

            val encrypted =
                signalProtocolManager!!.encryptMessage(
                    recipientId = userId,
                    message = contentBytes
                )

            Napier.d(
                "E2EE_ENCRYPT: Successfully encrypted for $userId",
                tag = "E2EE"
            )

            return userId to
                    Json.encodeToJsonElement(
                        EncryptedMessage.serializer(),
                        encrypted
                    )

        } catch (firstError: Exception) {

            Napier.w(
                "E2EE_ENCRYPT: First encryption attempt failed " +
                        "for $userId: ${firstError.message}",
                tag = "E2EE"
            )

            // ========================================================
            // SESSION REBUILD
            // ========================================================

            try {

                Napier.w(
                    "E2EE_ENCRYPT: Rebuilding Signal session for $userId",
                    tag = "E2EE"
                )

                /*
                 * Delete the existing local session.
                 *
                 * This is important when the local Double Ratchet
                 * state is no longer compatible with the recipient.
                 */

                signalProtocolManager!!.deleteSession(
                    userId
                )

                /*
                 * Fetch the recipient's current PreKeyBundle
                 * and establish a completely new session.
                 *
                 * repository.ensureSession() will see that there
                 * is no session and fetch the latest remote bundle.
                 */

                repository.ensureSession(
                    userId
                )

                // ====================================================
                // RETRY ENCRYPTION
                // ====================================================

                val encrypted =
                    signalProtocolManager!!.encryptMessage(
                        recipientId = userId,
                        message = contentBytes
                    )

                Napier.d(
                    "E2EE_ENCRYPT: Session rebuilt and encryption " +
                            "succeeded for $userId",
                    tag = "E2EE"
                )

                return userId to
                        Json.encodeToJsonElement(
                            EncryptedMessage.serializer(),
                            encrypted
                        )

            } catch (secondError: Exception) {

                Napier.e(
                    "E2EE_ENCRYPT: Encryption failed after " +
                            "session rebuild for $userId: " +
                            "${secondError.message}",
                    tag = "E2EE",
                    throwable = secondError
                )

                return null
            }
        }
    }
}
