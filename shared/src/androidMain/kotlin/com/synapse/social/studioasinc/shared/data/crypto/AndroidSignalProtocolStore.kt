package com.synapse.social.studioasinc.shared.data.crypto

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
import org.whispersystems.libsignal.state.SignalProtocolStore
import org.whispersystems.libsignal.state.SignedPreKeyRecord
import org.whispersystems.libsignal.state.SignedPreKeyStore

class AndroidSignalProtocolStore(context: Context) : SignalProtocolStore {

    private val prefs: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        EncryptedSharedPreferences.create(
            context,
            "signal_store_secure",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    // ============================================================
    // IdentityKeyStore
    // ============================================================

    override fun getIdentityKeyPair(): IdentityKeyPair {
        val serialized = prefs.getString("identity_key_pair", null)
            ?: throw IllegalStateException("IdentityKeyPair not generated")

        return IdentityKeyPair(
            Base64.decode(serialized, Base64.DEFAULT)
        )
    }

    override fun getLocalRegistrationId(): Int {
        val id = prefs.getInt("local_registration_id", -1)

        if (id == -1) {
            throw IllegalStateException(
                "Local registration ID not found"
            )
        }

        return id
    }

    override fun saveIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey
    ): Boolean {

        val key = "identity_${address.name}_${address.deviceId}"

        prefs.edit()
            .putString(
                key,
                Base64.encodeToString(
                    identityKey.serialize(),
                    Base64.NO_WRAP
                )
            )
            .apply()

        return true
    }

    override fun isTrustedIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
        direction: IdentityKeyStore.Direction
    ): Boolean {

        val key = "identity_${address.name}_${address.deviceId}"

        val existing = prefs.getString(key, null)

        // Trust On First Use
        if (existing == null) {
            return true
        }

        return try {

            val existingKey = IdentityKey(
                Base64.decode(existing, Base64.DEFAULT),
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

        val key = "identity_${address.name}_${address.deviceId}"

        val existing = prefs.getString(key, null)
            ?: return null

        return try {

            IdentityKey(
                Base64.decode(existing, Base64.DEFAULT),
                0
            )

        } catch (e: Exception) {

            null
        }
    }

    /**
     * Stores the local IdentityKeyPair and Registration ID.
     */
    fun storeLocalIdentity(
        identityKeyPair: IdentityKeyPair,
        registrationId: Int
    ) {

        prefs.edit()
            .putString(
                "identity_key_pair",
                Base64.encodeToString(
                    identityKeyPair.serialize(),
                    Base64.NO_WRAP
                )
            )
            .putInt(
                "local_registration_id",
                registrationId
            )
            .putLong(
                "last_key_rotation",
                System.currentTimeMillis()
            )
            .apply()
    }

    fun hasIdentity(): Boolean {

        return prefs.contains("identity_key_pair") &&
                prefs.contains("local_registration_id")
    }

    fun getLastKeyRotation(): Long {

        return prefs.getLong(
            "last_key_rotation",
            0L
        )
    }

    fun checkKeyRotationNeeded(
        thresholdDays: Int = 30
    ): Boolean {

        val lastRotation = getLastKeyRotation()

        if (lastRotation == 0L) {
            return false
        }

        val daysSinceRotation =
            (System.currentTimeMillis() - lastRotation) /
                    (1000L * 60L * 60L * 24L)

        return daysSinceRotation >= thresholdDays
    }

    // ============================================================
    // PreKeyStore
    // ============================================================

    override fun loadPreKey(
        preKeyId: Int
    ): PreKeyRecord {

        val key = "prekey_$preKeyId"

        val serialized = prefs.getString(
            key,
            null
        ) ?: throw IllegalStateException(
            "No prekey found for ID: $preKeyId"
        )

        return try {

            PreKeyRecord(
                Base64.decode(
                    serialized,
                    Base64.DEFAULT
                )
            )

        } catch (e: Exception) {

            throw IllegalStateException(
                "Failed to load prekey: $preKeyId",
                e
            )
        }
    }

    override fun storePreKey(
        preKeyId: Int,
        record: PreKeyRecord
    ) {

        val key = "prekey_$preKeyId"

        prefs.edit()
            .putString(
                key,
                Base64.encodeToString(
                    record.serialize(),
                    Base64.NO_WRAP
                )
            )
            .apply()
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
            .remove("prekey_$preKeyId")
            .apply()
    }

    // ============================================================
    // SessionStore
    // ============================================================

    override fun loadSession(
        address: SignalProtocolAddress
    ): SessionRecord {

        val key =
            "session_${address.name}_${address.deviceId}"

        val serialized = prefs.getString(
            key,
            null
        )

        if (serialized == null) {
            return SessionRecord()
        }

        return try {

            SessionRecord(
                Base64.decode(
                    serialized,
                    Base64.DEFAULT
                )
            )

        } catch (e: Exception) {

            // If the stored session is corrupted,
            // return an empty record so it can be rebuilt.
            SessionRecord()
        }
    }

    override fun getSubDeviceSessions(
        name: String
    ): List<Int> {

        val prefix = "session_${name}_"

        return prefs.all.keys
            .asSequence()
            .filter {
                it.startsWith(prefix)
            }
            .mapNotNull { key ->

                val deviceIdString =
                    key.removePrefix(prefix)

                deviceIdString.toIntOrNull()
            }
            .distinct()
            .sorted()
            .toList()
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
                Base64.encodeToString(
                    record.serialize(),
                    Base64.NO_WRAP
                )
            )
            .apply()
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

        prefs.edit()
            .remove(
                "session_${address.name}_${address.deviceId}"
            )
            .apply()
    }

    /**
     * Deletes ALL sessions belonging to the specified user.
     *
     * Example:
     *
     * session_user123_1
     * session_user123_2
     * session_user123_3
     *
     * will all be deleted.
     */
    override fun deleteAllSessions(
        name: String
    ) {

        val prefix = "session_${name}_"

        val editor = prefs.edit()

        prefs.all.keys
            .filter {
                it.startsWith(prefix)
            }
            .forEach { key ->
                editor.remove(key)
            }

        editor.apply()
    }

    // ============================================================
    // SignedPreKeyStore
    // ============================================================

    override fun loadSignedPreKey(
        signedPreKeyId: Int
    ): SignedPreKeyRecord {

        val key =
            "signedprekey_$signedPreKeyId"

        val serialized = prefs.getString(
            key,
            null
        ) ?: throw IllegalStateException(
            "No signed prekey found for ID: $signedPreKeyId"
        )

        return try {

            SignedPreKeyRecord(
                Base64.decode(
                    serialized,
                    Base64.DEFAULT
                )
            )

        } catch (e: Exception) {

            throw IllegalStateException(
                "Failed to load signed prekey: $signedPreKeyId",
                e
            )
        }
    }

    /**
     * Returns all SignedPreKeyRecords currently stored locally.
     */
    override fun loadSignedPreKeys(): List<SignedPreKeyRecord> {

        return prefs.all.keys
            .asSequence()
            .filter {
                it.startsWith("signedprekey_")
            }
            .mapNotNull { key ->

                try {

                    val serialized =
                        prefs.getString(
                            key,
                            null
                        ) ?: return@mapNotNull null

                    SignedPreKeyRecord(
                        Base64.decode(
                            serialized,
                            Base64.DEFAULT
                        )
                    )

                } catch (e: Exception) {

                    null
                }
            }
            .toList()
    }

    override fun storeSignedPreKey(
        signedPreKeyId: Int,
        record: SignedPreKeyRecord
    ) {

        val key =
            "signedprekey_$signedPreKeyId"

        prefs.edit()
            .putString(
                key,
                Base64.encodeToString(
                    record.serialize(),
                    Base64.NO_WRAP
                )
            )
            .apply()
    }

    override fun containsSignedPreKey(
        signedPreKeyId: Int
    ): Boolean {

        return prefs.contains(
            "signedprekey_$signedPreKeyId"
        )
    }

    override fun removeSignedPreKey(
        signedPreKeyId: Int
    ) {

        prefs.edit()
            .remove(
                "signedprekey_$signedPreKeyId"
            )
            .apply()
    }
}
