# Offline Messaging via DHT Storage — Design Specification

**Status:** Draft  
**Issue:** [#885](https://github.com/TokTok/c-toxcore/issues/885)  
**Author:** Design sketch, July 2026

---

## 1. Overview

This document specifies a distributed store-and-forward mechanism for delivering messages
to offline peers using Tox's existing DHT infrastructure. The design extends the DHT with
`STORE` and `FIND_VALUE` RPCs (analogous to Kademlia/BEP-44), allowing encrypted messages
to persist in the DHT until the recipient retrieves them.

### 1.1 Design Goals

| Goal | Rationale |
|------|-----------|
| Fully decentralized | No relay servers, no central authority |
| End-to-end encrypted | DHT nodes cannot read stored messages |
| Sender-authenticated | Recipient can verify who sent each message |
| Bounded resource usage | DHT nodes enforce per-peer storage limits |
| Backward compatible | Existing DHT nodes ignore unknown packet types |
| Replay resistant | Duplicate messages are detected and dropped |

### 1.2 Non-Goals

- **File transfers**: This design covers text messages only (up to `TOX_MAX_MESSAGE_LENGTH`).
  File transfer offline storage requires a separate mechanism (out of scope).
- **Group chat offline messages**: NGC group messages are out of scope for the initial
  implementation. The mechanism can be extended later.
- **Perfect forward secrecy for stored messages**: Messages are encrypted with the
  recipient's long-term key. Compromise of that key reveals all stored messages.
  This is a known limitation shared by most offline messaging systems.

---

## 2. DHT Protocol Extensions

### 2.1 New Packet Types

Two new RPCs are added to the DHT packet type namespace:

```c
#define NET_PACKET_DHT_STORE      0x22  // Store a value at a key
#define NET_PACKET_DHT_FIND_VALUE 0x23  // Query for values at a key
```

These are sent as lossy DHT packets (same transport as `SEND_NODES`).

### 2.2 STORE Packet Format

```
[1 byte]  packet_type = 0x22
[32 bytes] dht_key        — the key to store under
[1 byte]  flags           — bit 0: needs_ack, bits 1-7: reserved
[2 bytes] data_length     — length of the stored data
[data_length bytes] data  — the encrypted message envelope
[24 bytes] nonce          — crypto_box nonce for this packet
[16 bytes] MAC            — Poly1305 MAC
```

The `dht_key` is `SHA256(recipient_pubkey || "tox-offline-msg-v1" || sequence_number)`.

#### Semantics

- A node receiving `STORE` for key `K` stores `(K, data, sender_ip, expiration_time)`
  in its local storage table.
- If `needs_ack` is set, the node responds with a `STORE_ACK` (reusing the same packet
  type with `flags & 0x01 == 0` and `data_length == 0`).
- The storing node re-publishes the value to its closest neighbours every
  `STORE_REPUBLISH_INTERVAL` (default: 1 hour).
- Storage expires after `STORE_TTL` (default: 7 days) unless refreshed.

### 2.3 FIND_VALUE Packet Format

```
[1 byte]  packet_type = 0x23
[32 bytes] dht_key        — the key to query
[1 byte]  flags           — reserved, must be 0
[2 bytes] reserved        — must be 0
[24 bytes] nonce
[16 bytes] MAC
```

#### Response: VALUE Packet

```
[1 byte]  packet_type = 0x23  (same type, response flag in crypto layer)
[32 bytes] dht_key
[1 byte]  flags           — bit 0: has_more (more values available)
[2 bytes] data_length
[data_length bytes] data  — one stored value
[24 bytes] nonce
[16 bytes] MAC
```

If multiple values exist for the key, the node sends the newest one first and sets
`has_more`. The recipient should iterate with increasing `sequence_number` until
no more values are returned.

#### Semantics

- If the node has values stored for `dht_key`, it returns the most recent.
- If the node does NOT have the key but knows closer nodes, it returns a `SEND_NODES`
  response with the K closest nodes to the key (standard DHT routing behavior).
- The querier follows the node list toward the key, issuing `FIND_VALUE` at each step,
  until values are found or the closest nodes are exhausted.

### 2.4 DHT Node Storage Limits

Each DHT node allocates a fixed storage pool:

```c
#define DHT_OFFLINE_MSG_MAX_TOTAL_SIZE  (10 * 1024 * 1024)  // 10 MB total
#define DHT_OFFLINE_MSG_MAX_PER_PEER    (1 * 1024 * 1024)   // 1 MB per recipient
#define DHT_OFFLINE_MSG_MAX_PER_KEY     100                  // max 100 messages per key
#define DHT_OFFLINE_MSG_TTL             (7 * 24 * 60 * 60)   // 7 days
```

Eviction policy: when the pool is full, the oldest entries (by `expiration_time`)
are evicted first. Entries past their TTL are evicted regardless of pool pressure.

---

## 3. Message Envelope Format

Each offline message is serialized into an **envelope** before encryption:

### 3.1 Plaintext Envelope (before encryption)

```
Offset  Size   Field
------  ----   -----
0       1      version (0x01)
1       32     sender_public_key
33      32     recipient_public_key
65      8      message_id (monotonic counter for this sender→recipient pair)
73      8      sent_timestamp (unix time in milliseconds)
81      1      message_type (0 = normal, 1 = action)
82      2      message_length       (network byte order)
84      N      message_data
84+N    64     ed25519_signature(version || sender_pk || recipient_pk || message_id || timestamp || msg_type || msg_length || msg_data)
```

### 3.2 Encryption

The plaintext envelope is encrypted using `crypto_box` (XSalsa20-Poly1305):

```
nonce = random_bytes(24)
ciphertext = crypto_box(plaintext_envelope, nonce, recipient_pk, sender_sk)
```

The `crypto_box` nonce is prepended to the ciphertext before storage:

```
Stored blob = nonce[24] || ciphertext[plaintext_len + 16]
```

### 3.3 Decryption and Verification

On retrieval, the recipient:
1. Extracts the 24-byte nonce from the front of the stored blob
2. Decrypts using `crypto_box_open(ciphertext, nonce, sender_pk, recipient_sk)`
3. Parses the plaintext envelope
4. Verifies the Ed25519 signature using `sender_public_key`
5. Checks `message_id` against previously seen IDs (replay protection)
6. Delivers `(sender_pk, message_id, timestamp, type, message_data)` to the application

### 3.4 Message ID Scheme

The `message_id` is a monotonically increasing counter per sender→recipient direction,
combined with a random component to prevent enumeration:

```c
message_id = (last_counter++ << 16) | (random_bytes(2) & 0xFFFF)
```

The recipient tracks the highest `message_id` received from each friend. Messages with
`message_id <= last_seen_id` are duplicates and discarded. The random low bits prevent
an attacker from enumerating how many messages have been sent.

---

## 4. Operational Flow

### 4.1 Sending (Sender Online, Recipient May Be Offline)

```
tox_friend_send_offline_message(tox, friend_number, type, msg, len)
    │
    ├─ 1. Try direct delivery (existing tox_friend_send_message path)
    │     └─ If delivered and ACKed → return OK (fast path)
    │
    ├─ 2. Build envelope: sign + encrypt
    │
    ├─ 3. For seq_num in 0..N until a free slot is found:
    │     dht_key = SHA256(recipient_pk || "tox-offline-msg-v1" || seq_num)
    │     Send STORE to K=8 closest DHT nodes for dht_key
    │     Wait for at least Q=3 STORE_ACKs (quorum)
    │
    ├─ 4. If quorum reached → return message_id
    │     If quorum failed → retry with next seq_num (max 3 attempts)
    │
    └─ 5. Return error if all attempts fail
```

### 4.2 Receiving (Recipient Comes Online)

```
tox_iterate() triggers automatically, or app calls:
tox_friend_query_offline_messages(tox)
    │
    ├─ 1. For each friend in friendlist:
    │     For seq_num starting from last_retrieved_seq_num:
    │       dht_key = SHA256(my_pk || "tox-offline-msg-v1" || seq_num)
    │       Fire FIND_VALUE toward dht_key
    │       │
    │       ├─ If value found:
    │       │   decrypt → verify → deliver via callback
    │       │   seq_num++, continue
    │       │
    │       └─ If no value after trying closest K nodes:
    │           break (no more messages for this friend)
    │
    └─ 2. Optionally: DELETE retrieved messages from DHT
          (fire-and-forget, best effort)
```

### 4.3 Automatic Polling

After coming online, `tox_iterate()` automatically triggers a background poll for
offline messages. The polling is staggered across friends to avoid flooding the
network with simultaneous FIND_VALUE requests. Default poll interval: 30 seconds
after connection established, then every 5 minutes.

### 4.4 Message Deletion

After successful delivery, the recipient sends a STORE packet with `data_length = 0`
(empty value) to the same DHT key. Nodes interpret this as a deletion request and
remove the entry for that key. This is best-effort — nodes may not honor it, and
the entry will expire naturally after TTL.

---

## 5. Public API

### 5.1 Sending

```c
typedef enum Tox_Err_Friend_Send_Offline_Message {
    TOX_ERR_FRIEND_SEND_OFFLINE_MESSAGE_OK,
    TOX_ERR_FRIEND_SEND_OFFLINE_MESSAGE_FRIEND_NOT_FOUND,
    TOX_ERR_FRIEND_SEND_OFFLINE_MESSAGE_FRIEND_NOT_CONNECTED,
    TOX_ERR_FRIEND_SEND_OFFLINE_MESSAGE_TOO_LONG,
    TOX_ERR_FRIEND_SEND_OFFLINE_MESSAGE_SENDQ,
    TOX_ERR_FRIEND_SEND_OFFLINE_MESSAGE_STORE_FAILED,
    TOX_ERR_FRIEND_SEND_OFFLINE_MESSAGE_NULL,
} Tox_Err_Friend_Send_Offline_Message;

/**
 * Send a message to a friend that will be stored in the DHT if the friend is
 * offline. If the friend is online, the message is delivered directly (same as
 * tox_friend_send_message).
 *
 * @param message_id On success, set to the unique message identifier.
 * @return true on success.
 */
bool tox_friend_send_offline_message(
    Tox *tox, uint32_t friend_number,
    Tox_Message_Type type, const uint8_t *message, size_t length,
    uint64_t *message_id,
    Tox_Err_Friend_Send_Offline_Message *error);
```

### 5.2 Receiving

```c
/**
 * @param message_id Unique message identifier for deduplication.
 * @param sent_timestamp Unix timestamp (milliseconds) when the message was sent.
 * @param type Message type (normal or action).
 * @param message The message data.
 * @param length Length of the message data.
 */
typedef void tox_friend_offline_message_cb(
    Tox *tox, uint32_t friend_number, uint64_t message_id,
    uint64_t sent_timestamp, Tox_Message_Type type,
    const uint8_t *message, size_t length, void *user_data);

void tox_callback_friend_offline_message(
    Tox *tox, tox_friend_offline_message_cb *callback);

/**
 * Manually trigger a poll for offline messages. Messages are delivered
 * via the tox_friend_offline_message_cb callback.
 *
 * Normally offline message polling happens automatically in tox_iterate(),
 * but this allows the application to request an immediate check.
 */
void tox_friend_query_offline_messages(Tox *tox);
```

### 5.3 Options

```c
/**
 * Offline messaging configuration. Set on Tox_Options before creating
 * a Tox instance.
 */
typedef enum Tox_Offline_Messaging_Mode {
    /** Offline messaging disabled. Messages are only delivered online. */
    TOX_OFFLINE_MESSAGING_DISABLED,
    /** Store messages in DHT when friend is offline (default). */
    TOX_OFFLINE_MESSAGING_DHT,
} Tox_Offline_Messaging_Mode;

void tox_options_set_offline_messaging_mode(
    Tox_Options *options, Tox_Offline_Messaging_Mode mode);

/**
 * Enable or disable storing offline messages for OTHER peers on this node.
 * When enabled (default), this node participates as a DHT storage node.
 * Disable on mobile/battery-constrained devices.
 */
void tox_options_set_dht_store_enabled(
    Tox_Options *options, bool enabled);

/**
 * Maximum storage (in bytes) this node allocates for offline messages
 * from other peers. Default: 10 MB. 0 = unlimited (not recommended).
 */
void tox_options_set_dht_store_max_size(
    Tox_Options *options, size_t max_size);
```

---

## 6. Security Analysis

### 6.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| DHT node reads stored message | Encryption with recipient's public key (crypto_box) |
| Attacker forges message from Alice | Ed25519 signature on plaintext envelope |
| Attacker replays old message | message_id deduplication on recipient side |
| Attacker floods Bob's mailbox | Per-recipient storage limits (100 msgs / 1MB) |
| Attacker fills DHT node storage | Per-node total cap (10MB), per-recipient cap |
| Attacker surrounds Bob's key (Sybil) | K=8 replication, query all K nodes |
| DHT node drops store silently | STORE_ACK + quorum (Q=3 of K=8) required |
| Passive traffic analysis | Future: padding, decoy traffic (not in v1) |

### 6.2 Known Limitations

1. **Metadata exposure**: DHT nodes can observe which public keys are receiving
   messages, and at what frequency. This cannot be fully mitigated without
   onion-routing the STORE/FIND_VALUE requests (future work).

2. **Long-term key compromise**: If the recipient's secret key is compromised,
   all stored but unretrieved messages can be decrypted. There is no perfect
   forward secrecy for stored messages because the sender cannot know which
   ephemeral keys the recipient will use when they come online.

3. **Storage node selection**: Nodes self-select for storage by being close to
   the DHT key. A determined attacker can position nodes near a target key to
   censor messages. This is the same Sybil resistance problem as the core DHT.

---

## 7. Implementation Plan

### Phase 1: DHT Storage Layer (~500 lines)

Files: `toxcore/DHT_store.c`, `toxcore/DHT_store.h`

- Storage data structure (hash table, per-key linked list of values)
- STORE / FIND_VALUE packet handlers
- TTL-based eviction timer
- Per-peer and total storage quota enforcement
- Integration with existing DHT packet dispatch

### Phase 2: Message Envelope (~300 lines)

Files: `toxcore/offline_msg.c`, `toxcore/offline_msg.h`

- Envelope serialization/deserialization
- Encryption/decryption with crypto_box
- Ed25519 signing and verification
- Message ID tracking per friend

### Phase 3: Public API (~200 lines)

Files: `toxcore/tox.h`, `toxcore/tox.c`, `toxcore/Messenger.c`

- `tox_friend_send_offline_message` implementation
- `tox_callback_friend_offline_message` registration
- Automatic polling in `do_messenger` / `tox_iterate`
- Tox_Options configuration fields

### Phase 4: Testing (~400 lines)

Files: `auto_tests/offline_msg_test.c`, `toxcore/offline_msg_test.cc`

- Unit tests for envelope crypto
- Scenario tests: send offline, bring recipient online, verify delivery
- Fuzzing: malformed STORE/FIND_VALUE packets
- Storage limit enforcement tests

### Estimated Total: ~1,400 lines new code, ~300 lines modified

---

## 8. Open Questions

1. **Should offline messages be opt-in per friend?** Could add
   `tox_friend_set_offline_messaging(tox, friend_number, true)` to enable
   store-and-forward for specific friends only.

2. **Should STORE nodes be compensated?** The design assumes altruistic storage.
   Future versions could add a proof-of-storage mechanism or tie storage
   eligibility to bootstrap node trust.

3. **Should messages be padded to a fixed size?** Fixed-size envelopes would
   prevent traffic analysis based on message length, at the cost of bandwidth.
   v1 could use unpadded messages; v2 could add optional padding.

4. **Should the sender re-store periodically?** If the sender is online and
   the message hasn't been retrieved yet, refreshing the TTL would improve
   reliability at the cost of sender bandwidth.

---

## Appendix A: DHT Key Derivation Detail

```c
#define OFFLINE_MSG_DOMAIN_SEPARATOR "tox-offline-msg-v1"

// DHT key for a specific message from sender to recipient:
// crypto_hash_sha256(recipient_pk || OFFLINE_MSG_DOMAIN_SEPARATOR || be64(seq_num))
void derive_offline_msg_dht_key(
    uint8_t dht_key[CRYPTO_SHA256_SIZE],
    const uint8_t recipient_pk[CRYPTO_PUBLIC_KEY_SIZE],
    uint64_t sequence_number)
{
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    crypto_hash_sha256_update(&state, recipient_pk, CRYPTO_PUBLIC_KEY_SIZE);
    crypto_hash_sha256_update(&state,
        (const uint8_t *)OFFLINE_MSG_DOMAIN_SEPARATOR,
        sizeof(OFFLINE_MSG_DOMAIN_SEPARATOR) - 1);
    uint8_t seq_be[8];
    host_to_lendian_bytes64(seq_be, sequence_number);
    crypto_hash_sha256_update(&state, seq_be, sizeof(seq_be));
    crypto_hash_sha256_final(&state, dht_key);
}
```

## Appendix B: Comparison with Alternatives

| Approach | Pros | Cons |
|----------|------|------|
| **DHT Storage (this design)** | Fully decentralized, no infrastructure | New DHT code, Sybil risk |
| **Personal relay server** | Simple, reliable | Requires always-on device, not for everyone |
| **TCP relay extension** | Reuses existing infrastructure | Centralizes storage on bootstrap/TCP nodes |
| **Blockchain** | Immutable, censorship-resistant | Massive overhead, public ledger |
| **Status quo (no offline)** | Zero complexity | Users miss messages |

---

## Appendix C: Multi-Device Support

### C.1 The Problem

Tox currently has no multi-device support. Each device is a completely separate Tox
instance with its own public/secret key pair. "Alice's phone" and "Alice's laptop" are
two different Tox IDs — Bob must add both as separate friends.

For offline messaging to work across devices, we need an identity layer that binds
multiple devices to a single user.

### C.2 Identity Architecture

```
                        ┌──────────────────────────┐
    Tox ID (master)     │  Alice's Master Key Pair  │   One per user
    = pubkey_hash       │  (Ed25519 sign + X25519)  │   Stable, long-term
                        └──────┬───────────┬───────┘
                               │           │
                    ┌──────────┴──┐  ┌─────┴──────────┐
    Device Subkeys  │ Phone       │  │ Laptop          │  One per device
    (per-device)    │ sub_sk, pk  │  │ sub_sk, pk      │  Rotatable
                    └──────┬──────┘  └─────┬───────────┘
                           │              │
                    ┌──────┴──────┐ ┌─────┴───────────┐
    Tox Instance    │ tox_new()   │ │ tox_new()        │  Existing code
    (transport)     │ DHT,TCP,... │ │ DHT,TCP,...      │  Unchanged
                    └─────────────┘ └──────────────────┘
```

**Key principles:**
- The **master key** is the Tox ID. Friends add this once, not per-device.
- The master secret key is never used directly for transport — only for signing
  device certificates and decrypting the message index.
- Each device has its own **subkey** signed by the master key.
- Transport (DHT, TCP, friend connections) uses the device subkey, same as today.
- The master key can decrypt a **message index** that tells any device where to find
  pending messages.

### C.3 Device Lifecycle

#### Registration (device comes online)

```
New device:
  1. Generate device subkey pair
  2. Create device certificate:
       cert = {
         device_pubkey,
         device_name: "Alice's Phone",
         created: timestamp,
         expires: timestamp + 90days
       }
  3. Sign cert with master secret key → signed_cert
  4. Announce to DHT:
       STORE(hash(master_pk || "devices"), signed_cert)
  5. Existing devices see the announcement, send message history
```

#### Discovery (sender looks up recipient's devices)

```
Alice wants to send to Bob:
  1. FIND_VALUE(hash(Bob_master_pk || "devices"))
  2. Returns list of signed device certificates
  3. Verify each cert's signature against Bob's master key
  4. Filter: only devices seen in last 30 days (active)
  5. Result: [phone_pk, laptop_pk]
```

### C.4 Offline Message Flow (Multi-Device)

```
SCENARIO: Alice (phone) → Bob (all devices offline)
─────────────────────────────────────────────────────

ALICE'S PHONE:
  1. Discover Bob's devices via DHT:
       FIND_VALUE(hash(Bob_master_pk || "devices"))
       → [bob_phone_pk, bob_laptop_pk, bob_desktop_pk]

  2. Generate a random Message Encryption Key (MEK):
       mek = random_bytes(32)

  3. Encrypt the message ONCE with MEK:
       ciphertext = encrypt_symmetric(plaintext, mek)

  4. For EACH of Bob's active devices:
       envelope = {
         sender_master_pk: Alice_master_pk,
         sender_device_pk: Alice_phone_pk,
         recipient_master_pk: Bob_master_pk,
         recipient_device_pk: bob_device_pk,  ← specific device
         message_id,
         timestamp,
         mek_encrypted: crypto_box(mek, device_pk, alice_phone_sk),
         ciphertext
       }
       full_envelope = sign(envelope, alice_phone_sk)
       dht_key = hash(bob_device_pk || "offline-msg-v1" || seq_num)
       STORE(dht_key, full_envelope)

  5. Also update Bob's message index:
       index_entry = {
         message_id,
         sender_master_pk,
         timestamp,
         status: "pending"
       }
       index_key = hash(Bob_master_pk || "msg-index" || seq_num)
       STORE(index_key, encrypt(index_entry, Bob_master_pk))
         ↑ encrypted for master key so ANY device can read the index

BOB'S PHONE (first device to come online):
  1. Check message index:
       FIND_VALUE(hash(my_master_pk || "msg-index" || 0))
       → finds index_entry pointing to message_id X

  2. Fetch the actual message:
       FIND_VALUE(hash(my_device_pk || "offline-msg-v1" || seq))
       → gets envelope encrypted for this device

  3. Decrypt:
       mek = crypto_box_open(mek_encrypted, alice_phone_pk, my_device_sk)
       plaintext = decrypt_symmetric(ciphertext, mek)

  4. Deliver to app via callback

  5. Mark as delivered in message index:
       STORE(index_key, encrypt({message_id, status: "delivered"}, master_pk))

  6. Forward to sibling devices (when they come online):
       For each sibling device:
         send_direct(peer_to_peer_msg: {message_id, mek, ciphertext})

BOB'S LAPTOP (comes online later):
  1. Check message index → finds message_id X already delivered to phone
  2. Option A: Phone is still online → phone forwards via direct peer message
  3. Option B: Phone is offline → laptop fetches independently from DHT
       FIND_VALUE(hash(laptop_pk || "offline-msg-v1" || seq))
       (Alice stored a copy for each device)
  4. Decrypt with laptop's device subkey, deliver
```

### C.5 Message Index

The **message index** is a per-user, master-key-encrypted log stored in the DHT:

```
Index key: SHA256(master_pk || "msg-index-v1" || block_number)

Each index block (encrypted for master key):
  [2 bytes]  entry_count
  For each entry:
    [8 bytes]  message_id
    [32 bytes] sender_master_pk
    [8 bytes]  timestamp
    [1 byte]   status (0=pending, 1=delivered, 2=read)
    [32 bytes] message_dht_key_hash  ← where to find the actual message
```

The index is the **single source of truth** for "what messages exist for this user".
Any device can read it (has access to the master secret key). Devices update it
atomically via STORE with a version number to prevent conflicts.

### C.6 Cross-Device Sync (Non-Offline)

When two devices are online simultaneously, they sync directly via the existing
friend connection mechanism. Each device maintains a `last_sync_timestamp` per
sibling device and pushes any new messages received since that timestamp.

```
Device A → Device B (peer-to-peer sync message):
  [2 bytes]  message_count
  For each message:
    [8 bytes]  message_id
    [32 bytes] sender_master_pk
    [8 bytes]  timestamp
    [32 bytes] mek           ← encrypted for device B's subkey
    [N bytes]  ciphertext    ← same ciphertext, encrypted with MEK
```

### C.7 Revised Public API

```c
/**
 * Multi-device identity management.
 */

/* Create a new device subkey signed by the master key.
 * Returns the device certificate that should be announced to the DHT. */
bool tox_identity_add_device(
    Tox *tox,
    const uint8_t *device_name, size_t name_length,
    uint8_t *device_certificate,  /* output */
    Tox_Err_Identity_Add_Device *error);

/* Query a friend's active devices. */
typedef void tox_friend_devices_cb(
    Tox *tox, uint32_t friend_number,
    const uint8_t *device_pubkey,           /* one per callback */
    const uint8_t *device_name, size_t name_length,
    uint64_t last_seen,
    void *user_data);

void tox_callback_friend_devices(
    Tox *tox, tox_friend_devices_cb *callback);

void tox_friend_query_devices(
    Tox *tox, uint32_t friend_number);

/* Send to ALL of a friend's devices (the normal case). */
bool tox_friend_send_message_all_devices(
    Tox *tox, uint32_t friend_number,
    Tox_Message_Type type,
    const uint8_t *message, size_t length,
    uint64_t *message_id,
    Tox_Err_Friend_Send_Message *error);

/* Send to a SPECIFIC device (for targeted messages like "log out device"). */
bool tox_friend_send_message_to_device(
    Tox *tox, uint32_t friend_number,
    const uint8_t *device_pubkey,
    Tox_Message_Type type,
    const uint8_t *message, size_t length,
    uint64_t *message_id,
    Tox_Err_Friend_Send_Message *error);
```

### C.8 Implementation Impact

Multi-device support roughly **doubles** the scope of the offline messaging project:

| Component | Single-Device | + Multi-Device |
|-----------|:---:|:---:|
| Identity management | — | ~400 lines |
| Device discovery (announce/query) | — | ~300 lines |
| Message index (master-key encrypted log) | — | ~300 lines |
| N-recipient encryption (MEK pattern) | ~100 lines | ~200 lines |
| Cross-device sync protocol | — | ~400 lines |
| DHT storage (STORE/FIND_VALUE) | ~500 lines | same |
| Public API | ~200 lines | ~300 lines |
| Tests | ~400 lines | ~800 lines |
| **Total** | **~1,400** | **~2,700** |

### C.9 Migration Path

Existing Tox users have single-device IDs. A migration path:

1. **Phase 1**: Single-device offline messaging (Appendix A design).
   Existing Tox IDs work as-is. No identity changes.

2. **Phase 2**: Add master key concept. Existing secret keys become master keys.
   Users can add device subkeys. Old IDs continue working (master key IS the
   device key for the first device). New devices get subkeys.

3. **Phase 3**: Friend discovery migrates from device keys to master keys.
   `tox_friend_add` accepts a master key. Under the hood, it discovers devices
   and establishes per-device connections.

4. **Phase 4**: Message sync and history across devices. The message index
   becomes the canonical log. Offline messages are delivered to all devices.