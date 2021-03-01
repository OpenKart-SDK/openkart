# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import asyncio
import struct
import time
import logging

from dataclasses import dataclass

from .util import pad_to, retry_connect
from .rcd import RcdClient, RcdDevice, RcdError
from .lp2p import GroupInfo

l = logging.getLogger(__name__)

DRIVE_PORT   = 5102
CONTROL_PORT = 5103
PAIRING_PORT = 5106
EVENT_PORT   = 5107

MAC_FORMAT = ':'.join('%02x' for x in range(6))

@dataclass
class FujiSystemInfo:
    boot_version: tuple
    system_version: tuple
    sha1: str

    @classmethod
    def decode(cls, data: bytes):
        return cls(
            boot_version=(data[0], data[1]),
            system_version=(data[2], data[3]),
            sha1=data[4:].split(b'\0', 1)[0].decode('latin1'),
        )


@dataclass
class FujiProductCode:
    unk1: int
    character: int
    unk2: int
    serial: str

    @classmethod
    def decode(cls, data: bytes):
        (unk1, character, unk2), serial = struct.unpack('<HHB', data[:5]), data[5:]

        serial = serial.split(b'\0', 1)[0].decode('latin1')

        return cls(
            unk1=unk1,
            character=character,
            unk2=unk2,
            serial=serial,
        )


class FujiControlClient(RcdClient):
    SERVICE_ID = 0x100

    async def get_system_info(self):
        resp = await self.invoke(self.SERVICE_ID, 1)

        return FujiSystemInfo.decode(resp)

    async def set_param(self, param: str, value: bytes):
        param = param.encode()
        assert len(param) < 0x80

        request  = pad_to(param, 0x80)
        request += pad_to(len(value).to_bytes(2, 'big'), 0x10)
        request += value

        await self.invoke(self.SERVICE_ID, 2, request)

    async def set_connection_info(self, *, telemetry_port, video_control_port,
                                  video_stream_port, unk=1, timestamp=None):
        if timestamp is None:
            timestamp = int(time.time())

        await self.set_param('connection_info',
                             struct.pack('<HHHHQ', unk, telemetry_port,
                                         video_control_port, video_stream_port,
                                         timestamp))

    async def get_param(self, param: str):
        param = param.encode()
        assert len(param) < 0x80

        request = pad_to(param, 0x80)

        resp = await self.invoke(self.SERVICE_ID, 3, request)

        x = int.from_bytes(resp[:2], 'big')
        return resp[0x10:][:x]

    # Special case of above
    async def get_product_code(self):
        resp = await self.get_param('product_code')

        return FujiProductCode.decode(resp)

    async def set_state(self, state: int):
        request = pad_to(bytes([state]), 0x10)

        await self.invoke(self.SERVICE_ID, 4, request)

    async def shutdown(self):
        await self.invoke(self.SERVICE_ID, 9)


class FujiPairingClient(RcdClient):
    SERVICE_ID = 0x102

    async def set_group_info(self, group_info: GroupInfo):
        assert len(group_info.psk) == 0x20

        ssid = group_info.ssid.encode()

        request  = pad_to(ssid, 0x20)
        request += group_info.psk

        await self.invoke(self.SERVICE_ID, 1, request)


class Fuji:
    """Client class for representing a 'Fuji' (Mario Kart Live kart) device."""

    @classmethod
    async def connect(cls, device: RcdDevice):
        assert device.name == 'Fuji'

        host = device.address
        try:
            (_, event), (_, control) = await asyncio.gather(*(
                retry_connect(proto, host, port) for proto, port in [
                    (RcdClient, EVENT_PORT),
                    (FujiControlClient, CONTROL_PORT)
                ]))

        except (ConnectionError, asyncio.CancelledError):
            device.close()
            raise

        else:
            return cls(device, event, control)

    @classmethod
    async def pair(cls, device: RcdDevice, group_info: GroupInfo):
        assert device.name == 'Fuji'

        client = None

        try:
            _, client = await retry_connect(FujiPairingClient,
                                            device.address, PAIRING_PORT)
            await client.set_group_info(group_info)

        except (ConnectionError, RcdError) as e:
            l.warning('Pairing with %s failed: %s', device.address, e)
            return False

        else:
            l.info('Pairing with %s succeeded', device.address)
            return True

        finally:
            if client:
                client.close()
            device.close()

    def __init__(self, device, event, control):
        self.device = device
        self.event = event
        self.control = control

        self.address = device.address
        self.mac_address = MAC_FORMAT % tuple(device.ident[-6:])
        self.system_info = None
        self.product_code = None

        self.battery_state = 0
        self.cable_connected = False
        self.signal = None

        self.telemetry_socket = None

        self.__telemetry_event = asyncio.Event()
        self.__poll_ap_task = None

    def close(self):
        self.device.close()
        self.event.close()
        self.control.close()

        if self.telemetry_socket:
            self.telemetry_socket.unregister(self.device.address)
            self.telemetry_socket = None

        if self.__poll_ap_task:
            self.__poll_ap_task.cancel()

    async def setup(self, ports, *, ap=None):
        self.system_info = await self.control.get_system_info()
        self.product_code = await self.control.get_product_code()

        self.telemetry_socket = ports.udp1
        self.video_socket = ports.udp2
        self.video_control_rendezvous = ports.tcp1

        self.telemetry_socket.register(self.device.address, self.handle_telemetry)
        await self.control.set_connection_info(
            telemetry_port=self.telemetry_socket.port,
            video_control_port=self.video_control_rendezvous.port,
            video_stream_port=self.video_socket.port,
        )

        await self.__telemetry_event.wait()

        if ap:
            self.__poll_ap_task = asyncio.create_task(self.__poll_ap(ap))

    async def __poll_ap(self, ap):
        while True:
            await asyncio.sleep(0.1)
            mib = await ap.get_mib(self.mac_address)
            signal = mib.get('signal')
            try:
                self.signal = int(signal)
            except (TypeError, ValueError):
                pass

    async def shutdown(self):
        await self.control.shutdown()
        self.close()

    def handle_telemetry(self, data: bytes):
        if not data:
            l.warning('Received empty telemetry packet from %s',
                      self.device.address)
            return

        telemetry_type, telemetry_data = data[0], data[1:]

        if telemetry_type == 1:
            self.handle_status(telemetry_data)

        elif telemetry_type == 2:
            self.handle_imu(telemetry_data)

        elif telemetry_type == 3:
            pass # TODO

        else:
            l.warning('%s sent unknown telemetry type 0x%02x',
                      self.device.address, telemetry_type)

    def handle_status(self, data: bytes):
        if len(data) != 0x1f:
            l.warning('%s sent status telemetry of size %d',
                      self.device.address, len(data))
            return

        self.cable_connected = bool(data[0]&1)
        self.battery_state = data[3]

        self.__telemetry_event.set()

    def handle_imu(self, data: bytes):
        pass # TODO
