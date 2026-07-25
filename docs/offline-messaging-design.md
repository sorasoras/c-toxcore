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