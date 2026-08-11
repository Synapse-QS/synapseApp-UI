package com.synapse.social.studioasinc.shared.data.crypto.store

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.whispersystems.libsignal.IdentityKey
import org.whispersystems.libsignal.IdentityKeyPair
import org.whispersystems.libsignal.SignalProtocolAddress
import org.whispersystems.libsignal.state.IdentityKeyStore
import org.whispersystems.libsignal.state.PreKeyRecord
import org.whispersystems.libsignal.state.PreKeyStore
import org.whispersystems.libsignal.state.SessionRecord
import org.whispersystems.libsignal.state.SessionStore
import org.whispersystems.libsignal.state.SignedPreKeyRecord
import org.whispersystems.libsignal.state.SignedPreKeyStore
import org.whispersystems.libsignal.state.SignalProtocolStore
import java.io.IOException

class AndroidSignalStore(
    context: Context,
    private val sharedPreferences: SharedPreferences? = null
) : SignalProtocolStore {

    private val prefs: SharedPreferences by lazy {
        sharedPreferences ?: try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            EncryptedSharedPreferences.create(
                context,
                "signal_secure_store",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            throw RuntimeException(
                "Failed to initialize encrypted Signal storage",
                e
            )
        }
    }

    // ============================================================
    // Helpers
    // ============================================================

    private fun SharedPreferences.Editor.commitOrThrow(
        errorMessage: String
    ) {
        if (!commit()) {
            throw IOException(errorMessage)
        }
    }

    private fun encode(bytes: ByteArray): String {
        return Base64.encodeToString(
            bytes,
            Base64.NO_WRAP
        )
    }

    private fun decode(value: String): ByteArray {
        return Base64.decode(
            value,
            Base64.DEFAULT
        )
    }

    // ============================================================
    // IdentityKeyStore
    // ============================================================

    override fun getIdentityKeyPair(): IdentityKeyPair {

        val encoded =
            prefs.getString(
                "identity_key_pair",
                null
            ) ?: throw IOException(
                "No identity key pair"
            )

        return try {
            IdentityKeyPair(
                decode(encoded)
            )
        } catch (e: Exception) {
            throw IOException(
                "Failed to decode identity key pair",
                e
            )
        }
    }

    override fun getLocalRegistrationId(): Int {

        val registrationId =
            prefs.getInt(
                "registration_id",
                0
            )

        if (registrationId == 0) {
            throw IOException(
                "No local registration ID"
            )
        }

        return registrationId
    }

    override fun saveIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey
    ): Boolean {

        val key =
            "identity_${address.name}_${address.deviceId}"

        val existing =
            prefs.getString(
                key,
                null
            )

        if (existing != null) {

            val existingKey =
                try {
                    IdentityKey(
                        decode(existing),
                        0
                    )
                } catch (e: Exception) {
                    null
                }

            if (existingKey != null &&
                existingKey == identityKey
            ) {
                return false
            }
        }

        prefs.edit()
            .putString(
                key,
                encode(identityKey.serialize())
            )
            .commitOrThrow(
                "Failed to save identity key"
            )

        return true
    }

    override fun isTrustedIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
        direction: IdentityKeyStore.Direction?
    ): Boolean {

        val key =
            "identity_${address.name}_${address.deviceId}"

        val existing =
            prefs.getString(
                key,
                null
            )

        /*
         * Trust On First Use.
         *
         * If we don't know this identity yet,
         * Signal is allowed to save it.
         */
        if (existing == null) {
            return true
        }

        return try {

            val existingKey =
                IdentityKey(
                    decode(existing),
                    0
                )

            existingKey == identityKey

        } catch (e: Exception) {

            false
        }
    }

    override fun getIdentity(
        address: SignalProtocolAddress
    ): IdentityKey? {

        val key =
            "identity_${address.name}_${address.deviceId}"

        val existing =
            prefs.getString(
                key,
                null
            ) ?: return null

        return try {

            IdentityKey(
                decode(existing),
                0
            )

        } catch (e: Exception) {

            null
        }
    }

    fun saveIdentityKeyPair(
        identityKeyPair: IdentityKeyPair
    ) {

        prefs.edit()
            .putString(
                "identity_key_pair",
                encode(
                    identityKeyPair.serialize()
                )
            )
            .commitOrThrow(
                "Failed to save identity key pair"
            )
    }

    fun saveLocalRegistrationId(
        registrationId: Int
    ) {

        require(registrationId > 0) {
            "Registration ID must be greater than zero"
        }

        prefs.edit()
            .putInt(
                "registration_id",
                registrationId
            )
            .commitOrThrow(
                "Failed to save registration ID"
            )
    }

    // ============================================================
    // PreKeyStore
    // ============================================================

    override fun loadPreKey(
        preKeyId: Int
    ): PreKeyRecord {

        val key =
            "prekey_$preKeyId"

        val encoded =
            prefs.getString(
                key,
                null
            ) ?: throw IOException(
                "No such prekey: $preKeyId"
            )

        return try {

            PreKeyRecord(
                decode(encoded)
            )

        } catch (e: Exception) {

            throw IOException(
                "Failed to load prekey: $preKeyId",
                e
            )
        }
    }

    override fun storePreKey(
        preKeyId: Int,
        record: PreKeyRecord
    ) {

        val key =
            "prekey_$preKeyId"

        prefs.edit()
            .putString(
                key,
                encode(record.serialize())
            )
            .commitOrThrow(
                "Failed to store prekey: $preKeyId"
            )
    }

    override fun containsPreKey(
        preKeyId: Int
    ): Boolean {

        return prefs.contains(
            "prekey_$preKeyId"
        )
    }

    override fun removePreKey(
        preKeyId: Int
    ) {

        prefs.edit()
            .remove(
                "prekey_$preKeyId"
            )
            .commitOrThrow(
                "Failed to remove prekey: $preKeyId"
            )
    }

    // ============================================================
    // SignedPreKeyStore
    // ============================================================

    private companion object {
        const val SIGNED_PRE_KEY_IDS =
            "signed_prekey_ids"
    }

    override fun loadSignedPreKey(
        signedPreKeyId: Int
    ): SignedPreKeyRecord {

        val key =
            "signed_prekey_$signedPreKeyId"

        val encoded =
            prefs.getString(
                key,
                null
            ) ?: throw IOException(
                "No such signed prekey: $signedPreKeyId"
            )

        return try {

            SignedPreKeyRecord(
                decode(encoded)
            )

        } catch (e: Exception) {

            throw IOException(
                "Failed to load signed prekey: $signedPreKeyId",
                e
            )
        }
    }

    override fun loadSignedPreKeys():
        MutableList<SignedPreKeyRecord> {

        val ids =
            prefs.getStringSet(
                SIGNED_PRE_KEY_IDS,
                emptySet()
            ) ?: emptySet()

        val result =
            mutableListOf<SignedPreKeyRecord>()

        for (idString in ids) {

            val id =
                idString.toIntOrNull()
                    ?: continue

            try {

                result.add(
                    loadSignedPreKey(id)
                )

            } catch (_: Exception) {
                // Ignore invalid/stale entries.
            }
        }

        return result
    }

    override fun storeSignedPreKey(
        signedPreKeyId: Int,
        record: SignedPreKeyRecord
    ) {

        val key =
            "signed_prekey_$signedPreKeyId"

        val ids =
            prefs.getStringSet(
                SIGNED_PRE_KEY_IDS,
                emptySet()
            )
                ?.toMutableSet()
                ?: mutableSetOf()

        ids.add(
            signedPreKeyId.toString()
        )

        prefs.edit()
            .putString(
                key,
                encode(record.serialize())
            )
            .putStringSet(
                SIGNED_PRE_KEY_IDS,
                ids
            )
            .putInt(
                "last_signed_prekey_id",
                signedPreKeyId
            )
            .commitOrThrow(
                "Failed to store signed prekey: $signedPreKeyId"
            )
    }

    override fun containsSignedPreKey(
        signedPreKeyId: Int
    ): Boolean {

        return prefs.contains(
            "signed_prekey_$signedPreKeyId"
        )
    }

    override fun removeSignedPreKey(
        signedPreKeyId: Int
    ) {

        val key =
            "signed_prekey_$signedPreKeyId"

        val ids =
            prefs.getStringSet(
                SIGNED_PRE_KEY_IDS,
                emptySet()
            )
                ?.toMutableSet()
                ?: mutableSetOf()

        ids.remove(
            signedPreKeyId.toString()
        )

        prefs.edit()
            .remove(key)
            .putStringSet(
                SIGNED_PRE_KEY_IDS,
                ids
            )
            .commitOrThrow(
                "Failed to remove signed prekey: $signedPreKeyId"
            )
    }

    // ============================================================
    // SessionStore
    // ============================================================

    override fun loadSession(
        address: SignalProtocolAddress
    ): SessionRecord {

        val key =
            "session_${address.name}_${address.deviceId}"

        val encoded =
            prefs.getString(
                key,
                null
            )

        if (encoded == null) {
            return SessionRecord()
        }

        return try {

            SessionRecord(
                decode(encoded)
            )

        } catch (e: Exception) {

            /*
             * Corrupted session.
             *
             * Return an empty SessionRecord so the caller can
             * establish a new session.
             */
            SessionRecord()
        }
    }

    override fun getSubDeviceSessions(
        name: String?
    ): MutableList<Int> {

        val result =
            mutableListOf<Int>()

        if (name == null) {
            return result
        }

        val prefix =
            "session_${name}_"

        for (key in prefs.all.keys) {

            if (!key.startsWith(prefix)) {
                continue
            }

            val deviceId =
                key.removePrefix(prefix)
                    .toIntOrNull()

            if (deviceId != null) {
                result.add(deviceId)
            }
        }

        return result
            .distinct()
            .sorted()
            .toMutableList()
    }

    override fun storeSession(
        address: SignalProtocolAddress,
        record: SessionRecord
    ) {

        val key =
            "session_${address.name}_${address.deviceId}"

        prefs.edit()
            .putString(
                key,
                encode(record.serialize())
            )
            .commitOrThrow(
                "Failed to store session"
            )
    }

    override fun containsSession(
        address: SignalProtocolAddress
    ): Boolean {

        return prefs.contains(
            "session_${address.name}_${address.deviceId}"
        )
    }

    override fun deleteSession(
        address: SignalProtocolAddress
    ) {

        val key =
            "session_${address.name}_${address.deviceId}"

        prefs.edit()
            .remove(key)
            .commitOrThrow(
                "Failed to delete session"
            )
    }

    override fun deleteAllSessions(
        name: String?
    ) {

        val editor =
            prefs.edit()

        var deletedCount =
            0

        val prefix =
            "session_"

        for (key in prefs.all.keys) {

            if (!key.startsWith(prefix)) {
                continue
            }

            if (name == null) {

                editor.remove(key)
                deletedCount++

            } else {

                val expectedPrefix =
                    "session_${name}_"

                if (key.startsWith(expectedPrefix)) {

                    editor.remove(key)
                    deletedCount++
                }
            }
        }

        if (deletedCount > 0) {

            editor.commitOrThrow(
                "Failed to delete sessions"
            )
        }
    }

    // ============================================================
    // Identity Convenience
    // ============================================================

    fun deleteIdentity(
        address: SignalProtocolAddress
    ) {

        val key =
            "identity_${address.name}_${address.deviceId}"

        prefs.edit()
            .remove(key)
            .commitOrThrow(
                "Failed to delete identity key"
            )
    }

    // ============================================================
    // Signed PreKey Helpers
    // ============================================================

    fun getLastSignedPreKeyId(): Int {

        return prefs.getInt(
            "last_signed_prekey_id",
            0
        )
    }

    fun setLastSignedPreKeyId(
        id: Int
    ) {

        prefs.edit()
            .putInt(
                "last_signed_prekey_id",
                id
            )
            .commitOrThrow(
                "Failed to save last signed prekey ID"
            )
    }

    // ============================================================
    // Identity Helpers
    // ============================================================

    @get:JvmName("identityKeyPairHelper")
    val identityKeyPair: IdentityKeyPair
        get() = getIdentityKeyPair()

    fun hasIdentity(): Boolean {

        return prefs.contains(
            "identity_key_pair"
        ) &&
                prefs.getInt(
                    "registration_id",
                    0
                ) != 0
    }

    fun storeLocalIdentity(
        identityKeyPair: IdentityKeyPair,
        registrationId: Int
    ) {

        require(registrationId > 0) {
            "Registration ID must be greater than zero"
        }

        prefs.edit()
            .putString(
                "identity_key_pair",
                encode(
                    identityKeyPair.serialize()
                )
            )
            .putInt(
                "registration_id",
                registrationId
            )
            .putLong(
                "last_key_rotation",
                System.currentTimeMillis()
            )
            .commitOrThrow(
                "Failed to save local identity"
            )
    }

    // ============================================================
    // Key Rotation
    // ============================================================

    fun checkKeyRotationNeeded(
        thresholdDays: Int = 30
    ): Boolean {

        val lastRotation =
            prefs.getLong(
                "last_key_rotation",
                0L
            )

        if (lastRotation == 0L) {
            return false
        }

        val daysSinceRotation =
            (
                System.currentTimeMillis() -
                        lastRotation
                ) /
                    (1000L * 60L * 60L * 24L)

        return daysSinceRotation >= thresholdDays
    }
}
