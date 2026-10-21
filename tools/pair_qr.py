#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Put openkartd into PAIRING mode and show the QR code for the kart to scan.

QR format (see docs/PROTOCOL.md): version 4 (33x33), error correction M, byte
mode, 0x3E bytes:
  0x00  0x10  pairing seed (the LP2P PSK is SHA256(seed))
  0x10  0x20  pairing SSID, zero-filled
  0x30  0x02  pairing channel, little-endian
  0x32  0x0C  zero padding

Requires the `qrcode` package (with Pillow) on the machine running this tool.

Usage: pair_qr.py [--api http://127.0.0.1:8181/v1] [--png pairing-qr.png]
"""

import argparse
import json
import struct
import subprocess
import sys
import time
import urllib.request

import qrcode


def api(base, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data,
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def build_payload(seed_hex: str, ssid: str, channel: int = 0) -> bytes:
    seed = bytes.fromhex(seed_hex)
    ssid_b = ssid.encode()
    assert len(seed) == 0x10, 'seed must be 16 bytes'
    assert len(ssid_b) <= 0x20, 'SSID too long'
    payload = (seed + ssid_b.ljust(0x20, b'\0') +
               struct.pack('<H', channel) + bytes(0x0C))
    assert len(payload) == 0x3E
    return payload


def make_qr(payload: bytes):
    qr = qrcode.QRCode(version=4,
                       error_correction=qrcode.constants.ERROR_CORRECT_M,
                       box_size=12, border=4)
    qr.add_data(qrcode.util.QRData(payload, mode=qrcode.util.MODE_8BIT_BYTE))
    qr.make(fit=False)
    return qr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--api', default='http://127.0.0.1:8181/v1')
    ap.add_argument('--png', default='pairing-qr.png')
    ap.add_argument('--qr-channel', type=int, default=None,
                    help='channel to write into the QR (default: the real one)')
    ap.add_argument('--timeout', type=int, default=300,
                    help='seconds to wait for the kart')
    args = ap.parse_args()

    state = api(args.api, '/state')
    if state['state'] != 'PAIRING':
        print('Switching to PAIRING (starting temporary network)...')
        state = api(args.api, '/state', {'state': 'PAIRING'})

    pairing = state.get('pairing')
    if not pairing:
        sys.exit(f'No pairing data from the server: {state}')

    channel = pairing.get('channel') or 0
    if args.qr_channel is not None:
        channel = args.qr_channel
    print(f"Pairing SSID: {pairing['ssid']} (channel {channel})")
    qr = make_qr(build_payload(pairing['seed'], pairing['ssid'], channel))
    qr.make_image().save(args.png)
    print(f'QR code saved to {args.png}')
    subprocess.Popen(['xdg-open', args.png],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print('\nPut the kart in pairing mode and point its camera at the QR code.')
    print('A kart paired to another console needs: press the ignition button,')
    print('wait until the red brake light turns off while the blue light keeps')
    print('blinking, then press the button again.\n')

    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        time.sleep(1)
        state = api(args.api, '/state')
        if state['state'] == 'RUNNING':
            print('Pairing complete: the kart now joins the main network.')
            for _ in range(30):
                devs = api(args.api, '/devices')['devices']
                if devs:
                    print(json.dumps(devs, indent=2))
                    return
                time.sleep(1)
            print('The kart has not reconnected yet; check GET /v1/devices.')
            return
        # After pairing the server briefly goes DOWN before RUNNING.
        if state['state'] not in ('PAIRING', 'DOWN'):
            sys.exit(f"Unexpected state: {state['state']}")

    sys.exit('Timeout: no kart completed pairing.')


if __name__ == '__main__':
    main()
