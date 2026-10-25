# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import asyncio
import os
import struct
import time
import logging

from dataclasses import dataclass

from .util import pad_to, retry_connect
from .rcd import RcdClient, RcdDevice, RcdError
from .lp2p import GroupInfo
from .video import FujiVideo

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


class FujiDrive:
    """Streams teleoperation packets to a kart's drive port.

    The kart only zeroes its throttle after 1s without packets, so as long as
    this keeps sending, it is our job to stop the kart if the controller goes
    quiet: after DEADMAN seconds without set(), throttle drops to 0 and the
    brake light comes on.
    """

    RATE = 30
    DEADMAN = 0.5

    class proto(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

    def __init__(self, address: str):
        self.address = address
        self.transport = None
        self.task = None

        self.throttle = 0
        self.steering = 0
        self.brake = False
        self.counter = 0
        self.last_set = 0.0

    @staticmethod
    def to_int8(value: float) -> int:
        return max(-128, min(127, round(value * 127)))

    def set(self, throttle: float, steering: float, brake: bool = False):
        self.throttle = self.to_int8(throttle)
        self.steering = self.to_int8(steering)
        self.brake = bool(brake)
        self.last_set = time.monotonic()

    def packet(self) -> bytes:
        throttle, steering, brake = self.throttle, self.steering, self.brake
        if time.monotonic() - self.last_set > self.DEADMAN:
            throttle, steering, brake = 0, 0, True

        self.counter = (self.counter + 1) & 0xFFFFFFFF
        return pad_to(struct.pack('<bbBxI', throttle, steering, brake,
                                  self.counter), 0x20)

    async def start(self, control: FujiControlClient):
        await control.set_state(1)

        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            self.proto, remote_addr=(self.address, DRIVE_PORT))

        self.task = asyncio.create_task(self.__send_loop())
        l.info('Drive mode enabled for %s', self.address)

    async def __send_loop(self):
        interval = 1 / self.RATE
        while True:
            self.transport.sendto(self.packet())
            await asyncio.sleep(interval)

    @property
    def active(self) -> bool:
        return time.monotonic() - self.last_set <= self.DEADMAN

    def close(self):
        if self.task:
            self.task.cancel()
            self.task = None

        if self.transport:
            self.transport.close()
            self.transport = None


class FujiLSP(asyncio.Protocol):
    """The kart's "LSP" video control connection. Its protocol is unknown;
    we keep it open and log whatever arrives."""

    def __init__(self, fuji):
        self.fuji = fuji

    def log(self, line: str):
        l.debug('LSP %s: %s', self.fuji.address, line)
        if self.fuji.capture:
            self.fuji.capture.log('lsp', line)

    def connection_made(self, transport):
        self.log('connected')

    def data_received(self, data):
        self.log('<- ' + data.hex())

    def connection_lost(self, exc):
        self.log(f'closed ({exc!r})')


class FujiCapture:
    """Records the kart's undocumented traffic (status telemetry, "LSP" video
    control and video stream) under $OPENKART_CAPTURE_DIR for analysis."""

    MAX_VIDEO_BYTES = 32 << 20

    def __init__(self, directory: str):
        self.dir = directory
        os.makedirs(directory, exist_ok=True)
        self.video = open(os.path.join(directory, 'video.bin'), 'ab')
        self.video_bytes = 0
        self.last_status = None

    def log(self, name: str, line: str):
        with open(os.path.join(self.dir, name + '.log'), 'a') as f:
            f.write(f'{time.time():.3f} {line}\n')

    def status(self, data: bytes):
        if data != self.last_status:
            self.last_status = data
            self.log('status', data.hex())

    def video_packet(self, data: bytes):
        if self.video_bytes < self.MAX_VIDEO_BYTES:
            self.video.write(struct.pack('<dI', time.time(), len(data)) + data)
            self.video.flush()
            self.video_bytes += len(data)


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
        self.video_socket = None
        self.video = None
        self.drive = None
        self.capture = None
        self.__lsp_task = None

        self.__telemetry_event = asyncio.Event()
        self.__poll_ap_task = None
        self.__drive_lock = asyncio.Lock()

    def close(self):
        if self.drive:
            self.drive.close()
            self.drive = None

        self.device.close()
        self.event.close()
        self.control.close()

        if self.telemetry_socket:
            self.telemetry_socket.unregister(self.device.address)
            self.telemetry_socket = None

        if self.video_socket:
            self.video_socket.unregister(self.device.address)
            self.video_socket = None

        if self.video:
            self.video.close()
            self.video = None

        if self.__lsp_task:
            self.__lsp_task.cancel()

        if self.__poll_ap_task:
            self.__poll_ap_task.cancel()

    async def setup(self, ports, *, ap=None):
        self.system_info = await self.control.get_system_info()
        self.product_code = await self.control.get_product_code()

        self.telemetry_socket = ports.udp1
        self.video_socket = ports.udp2
        self.video_control_rendezvous = ports.tcp1

        self.telemetry_socket.register(self.device.address, self.handle_telemetry)

        capture_dir = os.environ.get('OPENKART_CAPTURE_DIR')
        if capture_dir:
            self.capture = FujiCapture(capture_dir)

        try:
            self.video = FujiVideo()
        except ImportError:
            l.warning('PyAV not installed: video disabled')
        self.video_socket.register(self.device.address, self.handle_video)

        # The kart opens the "LSP" control connection when it starts
        # streaming; it must be accepted or the kart drops off the network.
        self.__lsp_task = asyncio.create_task(self.__accept_lsp())

        await self.control.set_connection_info(
            telemetry_port=self.telemetry_socket.port,
            video_control_port=self.video_control_rendezvous.port,
            video_stream_port=self.video_socket.port,
        )

        await self.__telemetry_event.wait()

        if ap:
            self.__poll_ap_task = asyncio.create_task(self.__poll_ap(ap))

    async def __accept_lsp(self):
        while True:
            await self.video_control_rendezvous.expect(
                lambda: FujiLSP(self), self.device.address)

    def handle_video(self, data: bytes):
        if self.capture:
            self.capture.video_packet(data)
        if self.video:
            self.video.handle_packet(data)

    async def wake(self):
        """Enable drive mode (and with it the video stream) without moving:
        until set_drive() is called the kart gets stop+brake packets."""
        async with self.__drive_lock:
            if self.drive is None:
                drive = FujiDrive(self.address)
                await drive.start(self.control)
                self.drive = drive

    async def __poll_ap(self, ap):
        while True:
            await asyncio.sleep(0.1)
            mib = await ap.get_mib(self.mac_address)
            signal = mib.get('signal')
            try:
                self.signal = int(signal)
            except (TypeError, ValueError):
                pass

    async def set_drive(self, throttle: float, steering: float,
                        brake: bool = False):
        """Set throttle/steering in [-1, 1]; enables drive mode on first use."""
        await self.wake()
        self.drive.set(throttle, steering, brake)

    async def shutdown(self):
        await self.control.shutdown()
        self.close()

    def handle_telemetry(self, data: bytes):
        if not data:
            l.warning('Received empty telemetry packet from %s',
                      self.device.address)
            return

        telemetry_type, telemetry_data = data[0], data[1:]
        if self.capture and telemetry_type != 1:
            self.capture.log(f'telemetry{telemetry_type}', telemetry_data.hex())

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
        if self.capture:
            self.capture.status(data)

        self.__telemetry_event.set()

    BATTERY_BARS = 4

    @property
    def battery_percent(self) -> int:
        """Approximate: the kart only reports HUD bars (0-4)."""
        return min(self.battery_state, self.BATTERY_BARS) * 100 // self.BATTERY_BARS

    def handle_imu(self, data: bytes):
        pass # TODO
