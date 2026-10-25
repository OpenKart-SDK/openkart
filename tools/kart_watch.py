#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Show, live, which WiFi network nearby devices (e.g. the kart) look for.

Reads the hostapd debug log written when openkartd runs with
OPENKART_HOSTAPD_LOG set, and decodes probe requests. Before pairing, a kart
searches for its previous console's network ("G..."); after it accepts a
pairing QR code it searches for the pairing network ("P...").

Usage: kart_watch.py [hostapd.log]
"""

import os
import re
import sys
import time

LOG = sys.argv[1] if len(sys.argv) > 1 else 'hostapd.log'
FRAME = re.compile(r'MLME event frame - hexdump\(len=\d+\): ([0-9a-f ]+)')
ASSOC = re.compile(r'(STA [0-9a-f:]{17} .*(authenticated|associated|deauth).*|AP-STA-\S+ .*)')


def probe_ssid(frame: bytes):
    if len(frame) < 24 or frame[0] != 0x40:  # probe requests only
        return None
    ies = frame[24:]
    i = 0
    while i + 2 <= len(ies):
        t, n = ies[i], ies[i + 1]
        if t == 0:
            return frame[10:16].hex(':'), ies[i + 2:i + 2 + n].decode(errors='replace')
        i += 2 + n
    return None


def main():
    last = {}
    with open(LOG, errors='replace') as f:
        f.seek(0, 2)
        print(f'Watching {LOG} (Ctrl-C to quit)...')
        while True:
            line = f.readline()
            if not line:
                # The log may be truncated when openkartd restarts.
                if os.path.getsize(LOG) < f.tell():
                    f.seek(0)
                time.sleep(0.2)
                continue
            if m := ASSOC.search(line):
                print(time.strftime('%H:%M:%S'), '>>>', m.group(0).strip())
                continue
            m = FRAME.search(line)
            if not m:
                continue
            res = probe_ssid(bytes.fromhex(m.group(1).replace(' ', '')))
            if not res:
                continue
            mac, ssid = res
            now = time.monotonic()
            if last.get(mac, (None, 0))[0] != ssid or now - last[mac][1] > 10:
                print(time.strftime('%H:%M:%S'), mac, 'probes for:',
                      repr(ssid) if ssid else '(any)')
                last[mac] = (ssid, now)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
