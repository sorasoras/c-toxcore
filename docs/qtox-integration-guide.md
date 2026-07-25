# qTox Integration Guide for Enhanced c-toxcore

This document describes how to integrate the new c-toxcore features from the
`merge-all-prs` branch into qTox.

## 1. Build Setup

Update qTox's toxcore submodule/dependency to point to the enhanced c-toxcore:

```cmake
# In CMakeLists.txt or vcpkg.json:
# Point to sorasoras/c-toxcore merge-all-prs branch
```

## 2. Offline Messaging (DHT Store-and-Forward)

### Current qTox State
qTox has "faux offline messages" — it queues messages locally and sends them
when the friend comes online. This works only if qTox stays running.

### Integration Plan

**a) Add offline message callback registration** — `src/core/core.cpp`:

In the `Core::makeToxCore()` factory, after `tox_new()`, add:

```cpp
// Register offline message callback
tox_callback_friend_offline_message(tox, onFriendOfflineMessage);
```

**b) Add the callback handler** — `src/core/core.cpp`:

```cpp
static void onFriendOfflineMessage(Tox *tox, uint32_t friend_number,
    uint64_t message_id, uint64_t sent_timestamp, Tox_Message_Type type,
    const uint8_t *message, size_t length, void *user_data)
{
    Core *core = static_cast<Core *>(user_data);
    // Delivered same as online messages
    emit core->friendMessageReceived(friend_number, message_id,
        sent_timestamp, type, message, length);
}
```

**c) Modify sendMessage to use offline fallback** — `src/core/core.cpp`:

```cpp
bool Core::sendMessageWithType(uint32_t friendId, const QString& message,
    Tox_Message_Type type, ReceiptNum& receipt)
{
    // ... existing online send logic ...
    
    // If friend is offline, use offline message storage
    if (!isFriendOnline(friendId)) {
        uint64_t msg_id;
        Tox_Err_Friend_Send_Offline_Message err;
        bool ok = tox_friend_send_offline_message(tox, friendId, type,
            (const uint8_t*)msgData.constData(), msgData.size(),
            &msg_id, &err);
        if (ok) {
            receipt = ReceiptNum{msg_id};
            return true;
        }
    }
    
    // ... existing online path ...
}
```

**d) Poll for offline messages in the timer loop** — `src/core/core.cpp`:

In the main iterate timer callback:

```cpp
void Core::process() {
    // ... existing tox_iterate call ...
    
    // Poll for offline messages every 30 seconds
    static QElapsedTimer offlinePollTimer;
    if (!offlinePollTimer.isValid() || offlinePollTimer.elapsed() > 30000) {
        offlinePollTimer.restart();
        tox_friend_query_offline_messages(tox);
    }
}
```

## 3. Multi-Device Identity

### New UI Elements Needed
- Device management dialog (link/unlink devices)
- Device list display in friend info panel
- Device picker when sending messages

### Integration

**a) Link device from settings** — `src/widget/settings/`:

```cpp
// In device management page:
void DeviceSettingsWidget::onLinkDevice() {
    char name[65];
    // Get device name from user input
    uint8_t pubkey[TOX_PUBLIC_KEY_SIZE];
    uint8_t seckey[TOX_SECRET_KEY_SIZE];
    Tox_Err_Link_Device err;
    
    if (tox_self_link_device(core->getTox(), name, strlen(name),
            pubkey, seckey, &err)) {
        // Store device seckey in profile for the other device to use
        profile->addLinkedDevice(name, pubkey, seckey);
    }
}
```

**b) Display friend's devices** — `src/widget/friendwidget/`:

```cpp
// In friend info panel:
uint8_t deviceCount = tox_friend_get_device_count(core->getTox(), friendId);
for (uint8_t i = 0; i < deviceCount; i++) {
    uint8_t devicePk[TOX_PUBLIC_KEY_SIZE];
    char deviceName[65];
    tox_friend_get_device_pubkey(core->getTox(), friendId, i, devicePk);
    size_t nameLen = tox_friend_get_device_name(core->getTox(), friendId, i, deviceName);
    // Display: deviceName (online/offline status)
}
```

**c) Send to specific device** — optional enhancement:

```cpp
// When user picks a specific device:
tox_friend_send_message_to_device(core->getTox(), friendId, type,
    devicePubkey, msgData, msgLen, &err);
```

## 4. Message Timestamps

### API Change
`tox_friend_message_cb` now includes `uint64_t timestamp` as the 3rd parameter.

### qTox Changes

**a) Update callback signature** — `src/core/core.cpp`:

```cpp
// OLD:
static void onFriendMessage(Tox *tox, uint32_t friendNumber, 
    Tox_Message_Type type, const uint8_t *message, size_t length, void *userData);

// NEW:
static void onFriendMessage(Tox *tox, uint32_t friendNumber,
    uint64_t timestamp, Tox_Message_Type type,
    const uint8_t *message, size_t length, void *userData);
```

**b) Forward timestamp to UI** — `src/core/core.cpp`:

```cpp
emit core->friendMessageReceived(friendNumber, timestamp, type, bytes, len);
```

**c) Display timestamp in chat log** — Timestamp from sender perspective,
useful for messages received when both were offline.

## 5. Event Rate Limiting

### Integration

In `Core::process()` or the iterate timer, set the limit:

```cpp
void Core::process() {
    Tox_Iterate_Options *opts = tox_iterate_options_new(nullptr);
    tox_iterate_options_set_max_events_per_iterate(opts, 100);  // Cap at 100 events
    
    Tox_Err_Events_Iterate err;
    Tox_Events *events = tox_events_iterate(tox, opts, &err);
    
    if (err == TOX_ERR_EVENTS_ITERATE_LIMIT_REACHED) {
        qWarning() << "Event limit reached, some events dropped";
    }
    
    tox_iterate_options_free(opts);
    // ... dispatch events ...
}
```

## 6. POW Anti-Spam

### Integration

In settings or profile creation:

```cpp
// Enable POW for friend requests (difficulty 20 = ~1ms to compute)
tox_self_set_pow_difficulty(core->getTox(), 20);
```

For user-facing setting (slider 0-24):

```cpp
void SettingsWidget::onPowDifficultyChanged(int value) {
    tox_self_set_pow_difficulty(core->getTox(), (uint8_t)value);
}
```

## 7. Updated tox_events.h Accessor

For timestamp in friend message events:

```cpp
const Tox_Event_Friend_Message *friendMsg = tox_event_get_friend_message(event);
uint64_t sentTimestamp = tox_event_friend_message_get_sent_timestamp(friendMsg);
```

## 8. Thread Safety Notes

- All tox API calls must be made from the same thread (qTox uses a dedicated
  core thread with a `QRecursiveMutex`)
- The offline message callback fires from `tox_iterate()` — same thread safety
  as existing friend message callbacks
- Multi-device link/unlink operations should be done from the core thread
  while holding the mutex

## 9. Migration Path

1. **Phase 1**: Update toxcore dependency, fix API breakage (timestamp parameter)
2. **Phase 2**: Add offline messaging send fallback + receive callback
3. **Phase 3**: Add multi-device management UI
4. **Phase 4**: Event rate limiting for DoS protection
5. **Phase 5**: Optional POW and other enhancements