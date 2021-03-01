# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import os
import hmac
import random
import binascii
import asyncio
import subprocess
import atexit
from socket import AF_UNIX
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .lp2p_nonces import get_nonce_pair

LOCAL_COMMUNICATION_ID = 0x0100ED100BA3A000
TLV = (
    (1, 0x2013.to_bytes(2, 'big')),
    (2, (1<<2).to_bytes(8, 'big')),
)
APP_TLV = (
    (0x21, b''),
)

HOSTAPD_CONFIG_TEMPLATE = """\
interface={interface}
driver=nl80211
hw_mode=g
channel={channel}

ignore_broadcast_ssid=2
ssid={ssid}

static_ccmp_key={ccmp}
vendor_elements={ies}

ctrl_interface={ctrl_interface}
"""


@dataclass
class GroupInfo:
    ssid: str
    psk: bytes
    channel: int = field(default=None)

    def __post_init__(self):
        if len(self.psk) != 0x20:
            raise ValueError('psk is wrong length')

        if len(self.ssid.encode()) >= 0x20:
            raise ValueError('ssid is too long')

        if not self.channel:
            self.channel = random.choice([1, 6, 11])

        if self.channel not in [1, 6, 11]:
            raise ValueError('invalid channel')


class HostAPCtrl(asyncio.Protocol):
    def __init__(self):
        super().__init__()

        self.__lock = asyncio.Lock()
        self.__responses = asyncio.Queue()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        self.__responses.put_nowait(data.decode())

    async def call(self, cmd: str):
        async with self.__lock:
            self.transport.sendto(cmd.encode())
            return await self.__responses.get()


class LP2PAP:
    def __init__(self, interface: str, tempdir: Path):
        self.interface = interface
        self.tempdir = tempdir
        self.hostapd_path = 'hostapd'

        self.hostapd = None
        self.ctrl = None

        atexit.register(self.stop)

    @staticmethod
    def derive_keys(nonce: bytes, psk: bytes):
        hs256 = lambda k,m: hmac.HMAC(digestmod='sha256', key=k, msg=m).digest()
        two_keys = hs256(hs256(nonce, psk), b'\x02\x01')
        return two_keys[:0x10], two_keys[0x10:]

    @classmethod
    def encrypt_network(cls, psk: bytes, *, temporary=False):
        def pack_tlv(tags: list):
            return b''.join(bytes([t, len(v)]) + v for t,v in tags)

        plain_nonce, encrypted_nonce = get_nonce_pair(pure_random=temporary)

        ad0 = bytearray(0x20)
        ad0[0] = 0x20
        ad0[1] = 0x02
        ad0[2] = 0x02
        ad0[0x04:0x0C] = LOCAL_COMMUNICATION_ID.to_bytes(8, 'big')
        ad0[0x0C:0x1C] = encrypted_nonce
        ad0[0x1C:0x20] = os.urandom(4)

        iv0 = ad0[0x1C:0x20] + b'\0'*8
        tlv0 = pack_tlv(TLV)

        ad1 = os.urandom(4)
        iv1 = ad1 + b'\0'*8
        tlv1 = pack_tlv(APP_TLV)

        ka, kc = cls.derive_keys(plain_nonce, psk)
        kb, kd = cls.derive_keys(plain_nonce,
                                 LOCAL_COMMUNICATION_ID.to_bytes(8, 'little'))
        
        gcm_b = AESGCM(kb)
        gcm_c = AESGCM(kc)

        enc0 = gcm_b.encrypt(iv0, tlv0, bytes(ad0))
        enc1 = gcm_c.encrypt(iv1, tlv1, bytes(ad1))

        ie0 = ad0 + enc0[-0x10:] + enc0[:-0x10]
        ie1 = ad1 + enc1[-0x10:] + enc1[:-0x10]

        ies = b''
        for x,ie in enumerate((ie0, ie1)):
            ie = bytes([0x00, 0x22, 0xaa, 0x06, x]) + ie
            ies += bytes([0xdd, len(ie)]) + ie

        return ka, ies

    async def start(self, group_info: GroupInfo, *, temporary=False):
        if self.hostapd:
            await self.hostapd.wait()

        ccmp, ies = self.encrypt_network(group_info.psk, temporary=temporary)

        ctrl_path = self.tempdir / 'hostapd_ctrl'

        config = HOSTAPD_CONFIG_TEMPLATE.format(
            interface=self.interface,
            channel=group_info.channel,
            ssid=group_info.ssid,
            ccmp=binascii.hexlify(ccmp).decode(),
            ies=binascii.hexlify(ies).decode(),
            ctrl_interface=str(ctrl_path.resolve()),
        )

        config_path = self.tempdir / 'hostapd.conf'
        config_path.write_text(config)

        self.hostapd = await asyncio.create_subprocess_exec(
            self.hostapd_path, str(config_path.resolve()),
            stdout=subprocess.PIPE,
        )

        while True:
            line = await self.hostapd.stdout.readline()
            if b'AP-ENABLED' in line:
                break

        loop = asyncio.get_running_loop()
        _, self.ctrl = await loop.create_datagram_endpoint(
            HostAPCtrl,
            local_addr=str(ctrl_path/'.host'),
            remote_addr=str(ctrl_path/self.interface),
            family=AF_UNIX,
        )

    async def get_mib(self, sta: str):
        mib = await self.ctrl.call(f'STA {sta}')
        d = {}
        for line in mib.splitlines():
            line = line.strip()
            if '=' not in line: continue
            k, v = line.split('=', 1)
            d[k] = v
        return d

    def stop(self):
        if self.hostapd and self.hostapd.returncode is None:
            self.hostapd.terminate()

        self.ctrl = None
