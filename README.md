OpenKart SDK
============

This is a framework for interoperating with the 802.11 wireless ("WiFi") RC toy
karts manufactured and distributed by a certain well-known Japanese video game
corporation. This allows using a (Linux) computer's wireless interface to serve
as a host and pair the karts directly, so that you can interoperate with them
in your own project.

Getting Started
---------------

First, you will need a Linux system with wireless capability. Either install
Linux directly on a WLAN-equipped computer, or install it in a VM and
pass-through your wireless NIC (via USB pass-through for USB devices, or PCI
pass-through for built-in/PCI devices).

Check that the device (and its drivers) support operating in AP-mode:
```
$ iw phy phy0 info
...
valid interface combinations:
* #{ managed } <= 1, #{ AP, P2P-client, P2P-GO } <= 1, #{ P2P-device } <= 1,
```

If "AP" is listed, this device should work.

### Approach #1: Container

**Coming soon**

### Approach #2: Direct installation

You will need to install BusyBox's "udhcpd" and a
[patched](https://github.com/OpenKart-SDK/hostapd) copy of hostapd. Get that set up first.

Install the OpenKart server with:
`./setup.py install`

For video streaming, also install the optional dependencies (PyAV and
Pillow): `pip install '.[video]'`.

Customize the configuration (see `openkart.conf.example`).

Run OpenKart with `openkartd /path/to/your/openkart.conf`

API reference
-------------

OpenKart runs a server for HTTP and exposes an API (and, soon, a WebSocket
interface) for interacting with the server and karts. Here are the current API
calls:

**GET /v1/state**: Get server state; returns a JSON object with a "state"
string. The state may be one of:
- **RUNNING**: OpenKart is running normally.
- **DOWN**: OpenKart is in a "standby" mode.
- **PAIRING**: OpenKart is waiting for a device to attempt pairing.

In **PAIRING** mode, there may be a "pairing" object, which includes the "seed"
and "ssid" to include in the QR code to display to the kart.

**POST /v1/state**: Request a state change by POSTing a JSON object like
`{"state": "PAIRING"}`. Note that this may cause all devices to disconnect.

**GET /v1/devices**: Return a list of all devices currently connected to the
server.

**GET /v1/devices/{SERIAL}**: Return a specific device by its serial number.

**POST /v1/devices/{SERIAL}/shutdown**: Instruct the device to power off.

**POST /v1/devices/{SERIAL}/drive**: Drive the kart with a JSON object like
`{"throttle": 0.5, "steering": -0.2, "brake": false}` (throttle and steering
in [-1, 1]). The first command puts the kart in drive mode; commands should be
repeated (e.g. at 30 Hz), because the kart is stopped with the brake light on
if no command arrives for 0.5 seconds. The same command is available on the
WebSocket interface as `{"cmd": "drive", "serial": ..., ...}`.

**GET /v1/devices/{SERIAL}/video.mjpeg**: The kart's camera as an MJPEG
stream (`multipart/x-mixed-replace`), usable directly in an `<img>` tag.
Requires the `video` extra. The kart only sends a keyframe when it starts
streaming after power-on, so power the kart on while openkartd is running;
`video.needs_keyframe` in the device description tells you when it is needed.

Device descriptions also include `status.battery_percent` (approximate: the
kart only reports 0-4 battery bars), `status.driving` and `status.video`.

Pairing
-------

`tools/pair_qr.py` switches the server to `PAIRING`, displays the QR code and
waits for the kart. A kart that was paired with another console must be put
into pairing mode first: press the ignition button, wait until the red brake
light turns off while the blue light keeps blinking, then press it again.

Example UI
----------

`examples/drive-ui/` is a single-page UI showing the video, battery and
signal, with keyboard and gamepad driving. Point `docroot` at that directory
and open `http://localhost:8181/`.

Protocol notes and debugging
----------------------------

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for what was learned about pairing,
the "LSP" connection and the video stream format, and for the
`OPENKART_HOSTAPD_LOG` / `OPENKART_CAPTURE_DIR` debugging aids
(`tools/kart_watch.py` shows which network the kart is probing for).
