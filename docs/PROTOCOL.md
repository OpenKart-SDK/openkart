Protocol notes
==============

Findings from getting a kart paired, driven and streaming video with
OpenKart. They complement the
[SwitchBrew page](https://switchbrew.org/wiki/Mario_Kart_Live:_Home_Circuit),
which documents RCD, Fuji Control, the pairing QR code and teleoperation.
Anything marked *observed* was seen on one kart and may not hold everywhere.

Test setup:

- Kart firmware: system version 2.5, boot version 1.0.
- Host: Intel Wireless-AC 9560 (`iwlwifi`), Kali Linux with kernel 6.19.

Host / WiFi notes
-----------------

- `iwlwifi` (Intel 9560) works in AP mode with the patched hostapd. It only
  allows AP mode on 2.4 GHz: 5 GHz channels are flagged "No IR". That is fine,
  because the kart uses channels 1, 6 and 11.
- The card cannot be an AP and a client on different channels at the same
  time. Take the interface away from NetworkManager while openkartd runs
  (`nmcli device set wlan0 managed no`) and use Ethernet for internet.
- If hostapd fails to start, openkartd used to spin forever waiting for
  `AP-ENABLED`. It now raises an error instead.

Pairing
-------

### Putting the kart into pairing mode

A kart that is already paired with a console ignores pairing QR codes unless
it is put into pairing mode. The procedure, from Nintendo's support pages:

1. Press the ignition button briefly.
2. Wait until the red brake light turns off while the blue power light is
   still blinking.
3. Press the ignition button again.
4. Point the camera at the QR code.

Without this, the kart beeps when it sees a QR code but keeps looking for its
old network.

### Watching what the kart is doing

Before pairing, the kart sends directed probe requests for its stored
network. *Observed:* this SSID has 23 characters and starts with `G`, which
matches what SwitchBrew says about Home Circuit's game network. Once it
accepts a pairing QR code, it probes for the pairing SSID instead.

With `OPENKART_HOSTAPD_LOG` set, hostapd runs with `-dd` and logs every
received management frame. `tools/kart_watch.py` turns that log into a live
view of which SSID each nearby device is probing for, which makes pairing
problems easy to diagnose.

### QR code and pairing network

The QR payload follows the SwitchBrew layout. A generated code was checked
with an independent decoder (zxing-cpp): 62 bytes, byte mode, ECC level M,
version 4. Pairing succeeded with this configuration:

- The pairing SSID is 23 characters and starts with `P`, mimicking Home
  Circuit (`'P' + 11 random bytes in hex`).
- The pairing network runs on the main network's channel, and the QR code
  carries that channel. (Note: OpenKart-SDK/Pairing-QR-Code-Generator writes
  the channel as BCD-like hex, so channel 11 becomes `0x11`. Only channels 1
  and 6 come out right there.)

It is **not** known whether the old 30-character `openkart-pair_...` SSID or
channel 0 in the QR code would also work. The attempts that used them were
made without the pairing-mode procedure above, so they prove nothing either
way.

After `SetGroupInfo` the kart leaves the pairing network and joins the main
network by itself. *Observed:* the first connection to the main network
dropped after the handshake. A power cycle (single press) fixed it, and the
kart has reconnected reliably since.

Teleoperation
-------------

openkartd sends the SwitchBrew teleoperation packet (UDP 5102, 32 bytes)
at 30 Hz from the moment drive mode is enabled.

- **Dead man's switch:** if no command arrives for 0.5 s, the packets switch
  to throttle 0, steering 0 and the brake light on. The kart itself only
  zeroes throttle after 1 s *without packets*, so a host that keeps sending
  has to enforce this.
- **API values:** throttle and steering are taken in the range [-1, 1] and
  scaled to int8.

SetState(1) and the "LSP" connection
------------------------------------

After `SetState(1)` the kart:

- opens a TCP connection to the `video_control_port` given in
  `connection_info` (the "LSP" control channel);
- starts streaming video over UDP to `video_stream_port`.

*Observed:* the kart never sent any data on the LSP connection, and the host
did not send any either. When openkartd refused the connection (the old
`TCPRendezvous` behaviour, "Unexpected TCP connection"), the kart left the
network about 18 s later. openkartd now accepts the connection, keeps it open
and logs anything received at DEBUG level.

Home Circuit probably uses LSP to request keyframes (see below). Its protocol
is still unknown.

Video stream
------------

The video is **not encrypted**. It is H.264 High profile:

- 1280x800 at 30 fps, one slice per frame;
- every frame starts with an access unit delimiter (`00 00 00 01 09`);
- about 3.2 Mbit/s, sent as about 280 UDP packets per second of exactly
  0x588 (1416) bytes.

### Packet layout

| Offset | Size | Description |
|---|---|---|
| 0x00 | 2 | Magic `EC C1` |
| 0x02 | 3 | Packet sequence number, big-endian. Continuous across reconnections. |
| 0x05 | 1 | Frame counter (low byte) |
| 0x06 | 1 | Number of fragments in this frame |
| 0x07 | 1 | Index of this fragment |
| 0x08 | 1 | `0x0A` (chunk tag; see the note on the first packet of a stream) |
| 0x09 | 2 | Low 16 bits of the sequence number |
| 0x0B | 2 | Fragments 0..n-2: `0x8000 | (bytes - 1)`, see below |
| 0x0D | ... | Payload, see below |
| 0x580 | 8 | Trailer: timestamp-like value; the last byte increases by 2 per packet |

The payload depends on the fragment:

- **Fragment 0** starts with a 32-byte `FRAM` record at 0x0D (length field
  `0x801F`):

  | Offset in record | Size | Description |
  |---|---|---|
  | 0x00 | 4 | `FRAM` |
  | 0x04 | 4 | Frame size, big-endian: H.264 bytes in this frame + 31 |
  | 0x08 | 4 | Zero |
  | 0x0C | 4 | Increases each frame (timestamp?) |
  | 0x10 | 4 | Zero |
  | 0x14 | 4 | Frame number |
  | 0x18 | 8 | Timestamp/counter, like the packet trailer |

  It is followed by a 2-byte length field (`0x8000 | (bytes - 1)`). H.264
  data then runs from record + 0x22 up to 0x580.
- **Middle fragments:** H.264 data from 0x0D to 0x580, 1395 bytes. The length
  field says 1394, i.e. bytes - 1.
- **Last fragment:** offsets 0x0B..0x10 hold a different header: one byte
  (`0xBA`, `0xBE`, `0xB6`, ...) and an incrementing counter. H.264 data starts
  at **0x11**, and its length is `frame size - 31 - bytes so far`. The rest of
  the packet is stale data left over from the previous packet.

The very first packet of a stream has an extra 30-byte record at 0x08
(starting `4C`, containing `05 00 03 20` = 1280x800) before the `0A` chunk
with the `FRAM` record.

These rules reassemble 2523 out of 2523 captured frames, and FFmpeg decodes
all of them without a single error. See `openkartd/video.py`.

### Keyframes

SPS, PPS and an IDR frame are only sent when the kart's encoder starts. That
happens with the first `SetState(1)` after the kart is powered on. In an 84 s
capture there were no other keyframes.

*Observed:* the encoder keeps running when the kart disconnects and
reconnects. `SetState(0)` followed by `SetState(1)` does not restart it
either: a few frames are skipped and the same stream continues.

So openkartd has to be running, and has to wake the kart, after the kart is
powered on, or the video cannot be decoded. A lost packet damages the picture
until the next keyframe. Requesting keyframes (presumably over LSP) is an
open question.

openkartd decodes the stream continuously (PyAV) and serves JPEG frames to
viewers. A browser can join at any time, and decoder state survives while
nobody watches. `GET /v1/devices` reports `video.needs_keyframe` when packets
arrive but nothing decodes.

Telemetry
---------

- **Status (type 1):** byte 0x3 is the HUD battery bar count, 0-4, as
  documented on SwitchBrew. Values 1 and 2 were observed. There is no
  percentage or voltage, so `battery_percent` in the API is just
  `bars * 25`.
- **IMU (type 2):** received continuously, matching SwitchBrew.
- **Type 3:** 87-byte packets, about 30 per second while in drive mode.
  *Observed:* a float32 at offset 19 (after the type byte) ranged from 6.0 to
  8.25. Its meaning is unknown, and it does not look like a battery voltage.

Debugging aids
--------------

- `OPENKART_HOSTAPD_LOG=/path/hostapd.log` runs hostapd with `-dd -t` and
  appends its output to that file. Use it with `tools/kart_watch.py`.
- `OPENKART_CAPTURE_DIR=/path` records, per kart:
  - `video.bin`: the raw video packets, as records of `<f64 time><u32 length><packet>`;
  - `lsp.log`: LSP traffic;
  - `status.log`: status packets that changed;
  - `telemetryN.log`: other telemetry.

Open questions
--------------

- The LSP control protocol, and how to request a keyframe.
- The meaning of telemetry type 3.
- Whether the pairing SSID format and the QR channel value actually matter.
