# PC203 / IPC360 — Local, cloud-free access

Reverse-engineering notes and tools to receive, **decrypt and use the video stream
of the cloud-only Chinese IP camera PC203 / PD203L-Y1** (puwell / mossturbo platform,
"IPC360" / "showmo" app) **entirely on your LAN** — no vendor app, no cloud — and feed
it into an NVR such as [Frigate](https://frigate.video/).

> The camera encrypts its H.264 stream with a custom DES and only talks its own
> binary protocol over TCP. This repo documents that protocol and ships a small
> Python receiver that connects locally, decrypts the stream and re-serves it as
> plain **RTSP**.

---

## ⚠️ Scope & ethics

This is for **using a camera you own**, on **your own network**. It contains no
credentials and no copyrighted vendor binary. You extract the one vendor library
you need **from your own installed app**. Don't use this to access devices or
accounts that aren't yours.

---

## What works

- ✅ Local connection + handshake (no cloud)
- ✅ Full H.264 1080p main stream decrypted in real time
- ✅ Re-served as RTSP → viewable in VLC, usable in Frigate
- ✅ Key generator: regenerate the DES keys from `(username, MAC, deviceID)`
- ✅ PTZ command identified (pan/tilt)
- ◻️ Audio (G.711) — present in the stream, not yet wired
- ◻️ Pure-python DES (receiver currently runs the vendor DES via a tiny emulator)

---

## Architecture

```
camera (192.168.0.x:23456)
      │   cc dd ee ff  binary protocol over TCP
      ▼
pc203_receiver.py     connect → 2-phase handshake → reassemble frames
      │               → decrypt first 1024 B of each slice → H.264 Annex-B on stdout
      ▼
ffmpeg -f h264 -i -  -c copy -f rtsp → mediamtx (RTSP server)
      ▼
Frigate / VLC   rtsp://bridge:8600/pc203
```

---

## 1. The transport protocol

Every message starts with magic `cc dd ee ff` and a 20-byte header:

| offset | size | field                                   |
|-------:|-----:|-----------------------------------------|
| 0      | 4    | magic `cc dd ee ff`                     |
| 4      | 2    | type (LE)                               |
| 6      | 2    | pad                                     |
| 8      | 4    | device token / channel id (LE)          |
| 12     | 4    | **total message length** (LE)           |
| 16     | 4    | pad / flags                             |
| 20     | …    | payload (`total − 20` bytes)            |

Message types seen:

| type     | meaning                                   |
|----------|-------------------------------------------|
| `0x9c41` | client hello / connect request            |
| `0x9c42` | hello ack (both directions)               |
| `0x9c4d` | sub-request                               |
| `0x9c4e` | session confirm (camera → client)         |
| `0x9c4f` | (part of phone handshake, not required)   |
| `0x9c45` | **video** (H.264)                         |
| `0x4f7f` | periodic status                           |
| `0x4f77` | **PTZ move** (pan/tilt)                   |
| `0x0001` | keepalive (20-byte, empty payload)        |
| `0x03`   | audio (G.711)                             |

**Video sub-header** (inside a `0x9c45` message, absolute offsets): frame number @ 32,
fragment counter @ 36, inner payload length @ 44 (2 B), video data @ 48. One video
frame is split across many fragments with the same frame number.

### The local handshake (this is the part that took longest)

It is **request/response**, not fire-and-forget. The video only starts after the
client answers the camera's `0x9c4e` with its own `0x9c42` ×3:

```
client → 0x9c41 ×3, 0x9c4d
camera → 0x9c42 ×3, 0x9c4e
client → 0x9c42 ×3           ← the trigger
camera → 0x4f7f ×3, then 0x9c45 video …
```

The session ids are **derived, not random**: `session1` (little-endian) equals the
camera **deviceID** (e.g. deviceID `1234567890` → `0x499602D2` → bytes `d2029649`).
They are stable across sessions, so the receiver can reuse them.

---

## 2. The encryption scheme

Only the **first 1024 bytes (two 512-byte blocks) of each coded slice** (NAL type 1 or 5)
are encrypted, starting at the slice start-code. **The rest of the slice is plaintext.**
(That single fact is the whole trick — decrypting the whole slice corrupts it.)

Within each 512-byte block, 8 chunks of 16 bytes are encrypted, at offsets:

```
[80, 112, 144, 208, 240, 304, 336, 400]
```

Of each 16-byte chunk, only the **8 even-position bytes** are DES-decrypted; the odd
bytes are untouched. The key for chunk `ci` (0..7) is `B[ci]`, reset every 512-byte block.

The DES is a **custom variant** (modified S-box/permutation tables), so the receiver runs
the real routine from the vendor library through a tiny Unicorn emulator rather than a
stock DES.

---

## 3. Key derivation

The 8 keys `B0..B7` are an 8-char sliding window (step 4) over a 36-char **keystring**:

```
B[i] = keystring[4*i : 4*i+8]       # i = 0..7
```

The keystring is produced by a **3-stage chain** of the vendor function
`pw_seEncryption(in1, in2)` (internally: MD5 + base32hex formatting, 20-char output):

```
seed = username + deviceID
s1   = pw_seEncryption(seed, "default_ori")
s2   = pw_seEncryption(s1,   "pro_final")
s3   = pw_seEncryption(s2,   "extention")
keystring = s2 + s3[:16]            # 36 chars
```

(The same chain with `username + MAC` yields a second keystring used for other features.)

`pc203_keygen.py` implements this. Example:

```
$ python3 pc203_keygen.py <username> <deviceID> --mac <MAC>
Keystring VIDEO (da username+deviceID): XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Chiavi DES B0..B7: ['XXXXXXXX', 'XXXXXXXX', ...]
```

### Getting your username / MAC / deviceID

The `username` is **not** necessarily your email — the app uses a short account token
(e.g. for an email like `alice_x@example.com` it may be `alice`). The robust, universal
way to get the exact values is a 30-second Frida hook:

1. Root phone with `frida-server` running, matching your `frida` tools version.
2. `frida -U -f com.ipc360 -l hook_keys.js`
3. Open the camera live view in the app. You'll see:
   ```
   KEYCALL in1="<username><MAC>" in2="<username><deviceID>" OUT="…"
   ```
4. Read your `username`, `MAC` and `deviceID` straight out of `in1`/`in2`.

---

## 4. Running it

### Requirements (on the host that will receive/serve, e.g. a small Linux box on the LAN)

```bash
sudo apt install -y ffmpeg python3-pip
pip install --break-system-packages unicorn pyelftools capstone
```

### Extract the vendor library from YOUR app

Pull `libpwnativenetsdk.so` out of your own IPC360 APK and place it at
`lib_so/libpwnativenetsdk.so`:

```bash
unzip -o ipc360.apk -d ipc360_x
# pick the armeabi-v7a (32-bit ARM) build
cp ipc360_x/lib/armeabi-v7a/libpwnativenetsdk.so lib_so/
```

### Configure your camera identity + keystring

The receiver needs your device token, deviceID, session2 and the video keystring.
Set them as environment variables (or pass `--token/--deviceid/--sess2`):

```bash
export PC203_TOKEN=<4-byte hex token>        # e.g. header[8:12] from a capture
export PC203_DEVICEID=<deviceID decimal>     # becomes session1
export PC203_SESS2=<4-byte hex session2>
export PC203_KEYSTRING=$(python3 pc203_keygen.py <username> <deviceID> | awk '/VIDEO/{print $NF}')
```

### Test reception

```bash
python3 pc203_receiver.py --host <CAMERA_IP> >/dev/null 2>receiver.log &
tail -f receiver.log        # expect: "frame emessi: 50, 100, …"
```

### Serve as RTSP (mediamtx)

```bash
# mediamtx.yml: rtspAddress: :8600 ; rtmp/hls/webrtc/srt/api: no ; paths: { pc203: }
./mediamtx mediamtx.yml &
python3 pc203_receiver.py --host <CAMERA_IP> 2>receiver.log | \
  ffmpeg -nostdin -fflags +genpts -r 15 -f h264 -i - -c copy \
         -rtsp_transport tcp -f rtsp rtsp://127.0.0.1:8600/pc203
```

Verify: `ffplay -rtsp_transport tcp rtsp://<HOST>:8600/pc203`

`systemd/` contains two units (`mediamtx-pc203.service`, `pc203-stream.service`) that run
this on boot and auto-restart.

### Frigate

```yaml
cameras:
  pc203:
    ffmpeg:
      inputs:
        - path: rtsp://<HOST>:8600/pc203
          roles: [detect, record]
    detect: { width: 1920, height: 1080, fps: 5 }
```

> If Frigate's built-in go2rtc already uses `:8554`/`:8555`, keep mediamtx on a free port
> (e.g. `:8600`) as above.

---

## 5. PTZ (experimental)

Pan/tilt is a `0x4f77` control message: the payload carries two signed little-endian
int32 — `int[3]` = pan (X), `int[4]` = tilt (Y), small relative deltas, sign = direction;
`int[0] = 1` is the "move" mode. Wiring this into the receiver is on the TODO list.

---

## Files

| file                 | what                                                        |
|----------------------|-------------------------------------------------------------|
| `pc203_receiver.py`  | connect → handshake → reassemble → decrypt → H.264 on stdout |
| `pc203_decrypt.py`   | the selective-DES slice decryptor                           |
| `pc203_keygen.py`    | regenerate DES keys from `(username, MAC, deviceID)`        |
| `emu_se.py`          | runs vendor `pw_seEncryption` via Unicorn                   |
| `emu.py`, `loader.py`| minimal ARM loader/emulator for the vendor `.so`           |
| `hook_keys.js`       | Frida hook to read your identity inputs                     |
| `systemd/`           | service units for mediamtx + the receiver pipeline          |

You supply `lib_so/libpwnativenetsdk.so` yourself (from your own app).

---

## Credits

Reverse-engineered from packet captures and the vendor library by the owner of the
camera, for local/offline use. Shared so others with the same hardware can free it
from the cloud.
