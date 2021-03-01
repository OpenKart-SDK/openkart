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
pass-through for builtin/PCI devices).

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

You will need to install Busybox's "udhcpd" and a
[patched](https://github.com/OpenKart-SDK/hostapd) copy of hostapd. Get those
set up first.

Install the OpenKart server with:
`./setup.py install`

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
