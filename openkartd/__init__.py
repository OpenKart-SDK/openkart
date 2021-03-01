# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import asyncio
import logging
import binascii
import hashlib
import os
from enum import Enum

from .lp2p import GroupInfo, LP2PAP
from .rcd import RcdServer, RcdHandshakeService, RcdServerInfo, RcdDevice
from .util import GenericUDP, TCPRendezvous

from .fuji import Fuji

l = logging.getLogger(__name__)

PAIRING_PORT   = 5201
HANDSHAKE_PORT = 5202


class MiscPorts:
    def __init__(self):
        self.udp1 = None
        self.udp2 = None
        self.tcp1 = TCPRendezvous()

        self.is_setup = False

    async def setup(self, address: str):
        loop = asyncio.get_running_loop()

        coros = []
        for x in range(2):
            coros.append(loop.create_datagram_endpoint(GenericUDP,
                                                       local_addr=(address, 0)))

        coros.append(self.tcp1.create_server(host=address))

        (_, self.udp1), (_, self.udp2), _ = await asyncio.gather(*coros)
        self.is_setup = True


class OpenKart:
    # These may be accessed externally
    rcd_info: RcdServerInfo
    group_info: GroupInfo
    ap: LP2PAP
    address: str

    devices: list
    pairing_seed: bytes
    pairing_ssid: str
    state: Enum

    DEVTYPE_REGISTRY = {
        'Fuji': Fuji,
    }

    class State(Enum):
        DOWN = 0
        RUNNING = 1
        PAIRING = 2

    class PairHandler:
        def __init__(self, openkart):
            self.openkart = openkart

        def device_connected(self, device: RcdDevice):
            self.device = device

            self.task = asyncio.create_task(self.handle_device())

        async def handle_device(self):
            devtype = OpenKart.DEVTYPE_REGISTRY.get(self.device.name)
            if devtype is None:
                l.warning('Cannot pair unknown device: %s', self.device.name)
                self.device.close()
                return

            success = await devtype.pair(self.device, self.openkart.group_info)
            if success:
                asyncio.create_task(self.openkart.set_state(OpenKart.State.RUNNING))

        def device_disconnected(self, device: RcdDevice):
            assert self.device is device

            self.task.cancel()

    def __init__(self, *,
                 rcd_info: RcdServerInfo, group_info: GroupInfo = None,
                 ap: LP2PAP = None, address: str = '0.0.0.0'):
        self.devices = []
        self.__ident2device = {}
        self.__ident2task   = {}

        self.ports = MiscPorts()
        self.pair_server = None
        self.open_server = None

        self.state = self.State.DOWN

        self.group_info = group_info
        self.rcd_info = rcd_info
        self.ap = ap
        self.address = address

        self.pairing_seed = None
        self.pairing_ssid = None

    def device_connected(self, device: RcdDevice):
        devtype = self.DEVTYPE_REGISTRY.get(device.name)
        if devtype is None:
            l.warning('Cannot accept connection from unknown device: %s',
                      device.name)
            device.close()
            return

        if (device.ident in self.__ident2task or
            device.ident in self.__ident2device):
            l.warning('Device %s already in ident table(s), rejecting.',
                      device.address)
            device.close()
            return

        async def coro():
            try:
                client = await devtype.connect(device)
            except ConnectionError as e:
                l.warning('Failed to connect to device %s: %s',
                          device.address, e)
                return

            else:
                try:
                    await client.setup(self.ports, ap=self.ap)
                except:
                    client.close()
                    raise
                else:
                    self.devices.append(client)
                    self.__ident2device[device.ident] = client

            finally:
                del self.__ident2task[device.ident]

        self.__ident2task[device.ident] = asyncio.create_task(coro())

    def device_disconnected(self, device: RcdDevice):
        task = self.__ident2task.get(device.ident)
        client = self.__ident2device.pop(device.ident, None)

        if task:
            task.cancel()

        if client:
            self.devices.remove(client)
            client.close()

    async def set_state(self, state: State):
        if state == self.state: return

        if not self.group_info and state == self.State.PAIRING:
            raise AttributeError('Must set group_info first')

        if self.pair_server:
            self.pair_server.close()
            self.pair_server = None

        if self.open_server:
            self.open_server.close()
            self.open_server = None

        if self.ap:
            self.ap.stop()

        self.pairing_ssid = None
        self.pairing_seed = None

        self.state = self.State.DOWN
        l.info('Now operating in state: %s', self.state)
        if state == self.state: return

        loop = asyncio.get_running_loop()

        if state == self.State.RUNNING:
            if not self.ports.is_setup:
                await self.ports.setup(self.address)

            if self.ap and self.group_info:
                await self.ap.start(self.group_info)

            self.open_server = await loop.create_server(
                lambda: RcdServer(RcdHandshakeService(self.rcd_info,
                                                      handler=self)),
                self.address, HANDSHAKE_PORT)

        elif state == self.State.PAIRING:
            if self.ap:
                rand = os.urandom(0x1C)
                self.pairing_seed = rand[:0x10]
                ssid_b64 = binascii.b2a_base64(rand[0x10:]).decode().strip()
                self.pairing_ssid = f'openkart-pair_{ssid_b64}'

                pairing_info = GroupInfo(
                    ssid=self.pairing_ssid,
                    psk=hashlib.sha256(self.pairing_seed).digest(),
                )

                await self.ap.start(pairing_info, temporary=True)

            self.pair_server = await loop.create_server(
                lambda: RcdServer(RcdHandshakeService(
                    self.rcd_info, handler=self.PairHandler(self), pairing=True)),
                self.address, PAIRING_PORT)

        else:
            raise ValueError(f'unknown state {state}')

        self.state = state
        l.info('Now operating in state: %s', self.state)
