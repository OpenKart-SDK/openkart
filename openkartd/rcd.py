# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import os
import asyncio
import struct
import logging
import hashlib
from dataclasses import dataclass, field
from socket import SOL_SOCKET, SO_KEEPALIVE
from socket import IPPROTO_TCP, TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL

from .util import pad_to

l = logging.getLogger(__name__)

@dataclass
class RcdMsg:
    service: int
    command: int
    status: int
    is_response: bool
    data: bytes

    HEADER = struct.Struct('>HHIIBxxx')

    @classmethod
    def size(cls, buf: bytes):
        if len(buf) < cls.HEADER.size:
            return cls.HEADER.size

        hdr = buf[:cls.HEADER.size]
        _, _, data_size, _, _ = cls.HEADER.unpack(hdr)

        return cls.HEADER.size + data_size

    @classmethod
    def decode(cls, buf: bytes):
        if len(buf) < cls.size(buf):
            raise ValueError('buffer too short')

        hdr = buf[:cls.HEADER.size]
        service, command, data_size, status, flags = cls.HEADER.unpack(hdr)

        data = buf[cls.HEADER.size:][:data_size]

        return cls(
            service=service,
            command=command,
            status=status,
            is_response=bool(flags&1),
            data=data
        )

    def encode(self):
        return self.HEADER.pack(
            self.service, self.command, len(self.data), self.status,
            self.is_response
        ) + self.data


class RcdProtocol(asyncio.Protocol):
    def __init__(self):
        self.max_data_size = 0x1000
        self.transport = None
        self.address = None
        self.port = None

        self.__disconnect_event = asyncio.Event()
        self.__buf = None
        self.__queue = None

    def connection_made(self, transport):
        self.transport = transport
        self.address, self.port = transport.get_extra_info('peername')

        s = transport.get_extra_info('socket')
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, 10)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, 1)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPCNT, 4)

        self.__buf = b''
        self.__queue = asyncio.Queue()
        self.__disconnect_event.clear()

    def data_received(self, data: bytes):
        self.__buf += data

        while True:
            size = RcdMsg.size(self.__buf)

            if size > self.max_data_size+RcdMsg.HEADER.size:
                l.warning('Peer %s sent %d byte message; terminating',
                          self.address, size)
                self.transport.close()
                return

            if size > len(self.__buf):
                break

            msg = RcdMsg.decode(self.__buf[:size])
            self.__buf = self.__buf[size:]

            self.__queue.put_nowait(msg)

    def connection_lost(self, exc):
        l.debug('Peer %s disconnected: %s', self.address, exc)

        self.transport = None

        self.__disconnect_event.set()

        # Make the GC's job a little easier
        self.__buf = None
        self.__queue = None

    @property
    def connected(self):
        return not self.__disconnect_event.is_set()

    def send(self, msg: RcdMsg):
        self.transport.write(msg.encode())

    async def receive(self):
        if not self.connected:
            raise EOFError()

        queue_task = asyncio.create_task(self.__queue.get())
        disco_task = asyncio.create_task(self.__disconnect_event.wait())

        try:
            done, _ = await asyncio.wait((queue_task, disco_task),
                                         return_when=asyncio.FIRST_COMPLETED)

            if not self.connected:
                raise EOFError()
            else:
                return done.pop().result()

        finally:
            queue_task.cancel()
            disco_task.cancel()

    def wait_disconnect(self):
        return self.__disconnect_event.wait()

    def close(self):
        if self.connected:
            self.transport.close()


class RcdError(Exception):
    CODE = None

    def __init__(self, code: int = None):
        super().__init__()

        if self.CODE is None:
            assert code is not None
            self.code = code
        else:
            assert code is None
            self.code = self.CODE

    def __str__(self):
        return f'{type(self).__name__}({hex(self.code)})'


class RcdErrorMissizedPayload(RcdError): CODE = 0x708e8
class RcdErrorBadRequest(RcdError): CODE = 0x710e8
class RcdErrorHandshakeVersionMismatch(RcdError): CODE = 0x800e8
class RcdErrorHandshakeSequence(RcdError): CODE = 0x810e8
class RcdErrorHandshakeBadVersions(RcdError): CODE = 0x820e8
class RcdErrorHandshakeHash(RcdError): CODE = 0x830e8
class RcdErrorHandshakeUnrecognizedDevice(RcdError): CODE = 0x850e8


class RcdClient(RcdProtocol):
    __lock = None

    def connection_made(self, *x):
        super().connection_made(*x)

        self.__lock = asyncio.Lock()

    async def exchange(self, msg: RcdMsg, *, timeout: float = 1.0):
        async with self.__lock:
            if not self.connected:
                raise EOFError()

            self.send(msg)

            try:
                return await asyncio.wait_for(asyncio.shield(self.receive()),
                                              timeout=timeout)

            except asyncio.TimeoutError as e:
                l.warning('Server %s timed out on command %04x/%d; closing',
                          self.address, msg.service, msg.command)
                self.close()
                raise EOFError() from e

    async def invoke(self, service: int, command: int, data: bytes = b'', *,
                     timeout: float = 1.0):
        msg = RcdMsg(service=service, command=command, status=0,
                     is_response=False, data=data)
        msg = await self.exchange(msg, timeout=timeout)

        if (msg.service != service or msg.command != command
            or not msg.is_response):
            l.error('Server %s gave bad response: %s', self.address, msg)
            self.close()
            raise EOFError()

        if msg.status != 0:
            raise RcdError(msg.status)

        return msg.data


class RcdServer(RcdProtocol):
    def __init__(self, *services):
        super().__init__()

        self._services = {x.SERVICE_ID: x for x in services}

        self.__serve_task = None

    def connection_made(self, *x):
        super().connection_made(*x)

        l.info('Client %s connected', self.address)

        loop = asyncio.get_running_loop()
        self.__serve_task = loop.create_task(self.serve())

    def connection_lost(self, *x):
        super().connection_lost(*x)

        self.__serve_task.cancel()
        for service in self._services.values():
            service.close()

    async def serve(self):
        while True:
            try:
                msg = await self.receive()
            except EOFError: break

            try:
                l.debug('Client %s -> %s', self.address, msg)
                response = await self.dispatch(msg)

            except RcdError as e:
                l.warning('Client %s: Command %04x/%d: %r',
                          self.address, msg.service, msg.command, e)
                msg.status = e.code
                msg.data = b''

            except Exception as e:
                l.error('Client %s: Command %04x/%d: %r',
                        self.address, msg.service, msg.command, e)
                self.close()
                raise

            else:
                msg.status = 0
                msg.data = response if response is not None else b''

            msg.is_response = True
            l.debug('Client %s <- %s', self.address, msg)
            self.send(msg)

    async def dispatch(self, msg: RcdMsg):
        service = self._services.get(msg.service)
        if msg.is_response or not service:
            l.warning('Client %s accessing unknown service %d',
                      self.address, msg.service)
            raise RcdErrorBadRequest()

        return await service.dispatch(self, msg)


class RcdService:
    SERVICE_ID = None

    channel = None
    msg = None

    @staticmethod
    def cmd(n: int):
        def decorate(f):
            f.cmd = n
            return f
        return decorate

    def __init_subclass__(cls):
        cls.CMDS = {}

        for funcname in dir(cls):
            func = getattr(cls, funcname)
            if hasattr(func, 'cmd'):
                cls.CMDS[func.cmd] = func

    def close(self):
        pass

    async def dispatch(self, channel: RcdServer, msg: RcdMsg):
        self.channel = channel
        self.msg = msg

        try:
            handler = self.CMDS.get(msg.command)

            if handler is None:
                l.warning('%s: Client %s sent unknown command %d',
                          type(self).__name__, channel.address, msg.command)

                raise RcdErrorBadRequest()

            result = handler(self, msg.data)

            if asyncio.iscoroutine(result):
                result = await result

            return result

        finally:
            self.channel = None
            self.msg = None


@dataclass
class RcdDevice:
    name: str
    ident: bytes
    pairing_id: bytes = field(repr=False)
    secret_key: bytes = field(repr=False)
    channel: RcdServer = field(repr=False)
    address: str
    version: int = field(default=None)

    def close(self):
        self.channel.close()


@dataclass
class RcdServerInfo:
    name: str
    ident: bytes
    master_key: bytes
    versions: tuple = field(default=(2, 1))

    def __post_init__(self):
        if len(self.ident) != 0x10:
            raise ValueError('ident must have length 0x10')

        if len(self.name.encode()) >= 0x10:
            raise ValueError('name too long')

    def get_pairing_keys(self, device_ident: bytes, device_name: str):
        device_id = device_ident + device_name.encode()

        mk = self.master_key
        pairing_id = hashlib.sha256(mk + device_id + mk).digest()
        secret_key = hashlib.sha512(mk + pairing_id + mk).digest()
        return pairing_id, secret_key


class RcdHandshakeService(RcdService):
    SERVICE_ID = 0x0001

    def __init__(self, server_info: RcdServerInfo, *,
                 handler=None, pairing: bool = False):
        super().__init__()

        self.server_info = server_info
        self.handler = handler
        self.pairing = pairing

        self.sha256 = hashlib.sha256()
        self.sha256_buf = b''
        self.device = None
        self.next_cmd = 1

    async def dispatch(self, channel: RcdServer, msg: RcdMsg):
        result = await super().dispatch(channel, msg)

        # If no exception in dispatch, update the running payloads hash
        # (but only in multiples of 64-byte blocks)
        self.sha256_buf += msg.data
        self.sha256_buf += result
        if len(self.sha256_buf) >= 64:
            x = len(self.sha256_buf)&~63
            self.sha256.update(self.sha256_buf[:x])
            self.sha256_buf = self.sha256_buf[x:]

        return result

    @RcdService.cmd(1)
    def begin_handshake(self, data: bytes):
        if len(data) != 0x50:
            raise RcdErrorMissizedPayload()

        elif self.next_cmd != 1:
            raise RcdErrorHandshakeSequence()

        handshake_version = data[0]
        device_name  = data[0x10:0x20]
        device_ident = data[0x20:0x30]

        if handshake_version != 1:
            raise RcdErrorHandshakeVersionMismatch()

        device_name = device_name.split(b'\0', 1)[0]
        try:
            device_name = device_name.decode('utf8')
        except UnicodeDecodeError:
            device_name = device_name.decode('latin1')

        pairing_id, secret_key = self.server_info.get_pairing_keys(
            device_ident, device_name)

        self.device = RcdDevice(
            name=device_name,
            ident=device_ident,
            pairing_id=pairing_id,
            secret_key=secret_key,
            channel=self.channel,
            address=self.channel.address,
        )

        self.next_cmd = 2

        resp  = pad_to(bytes([handshake_version]), 0x10)
        resp += pad_to(self.server_info.name.encode(), 0x10)
        resp += self.server_info.ident
        resp += os.urandom(0x20)

        return resp

    @RcdService.cmd(2)
    def negotiate_version(self, data: bytes):
        if len(data) < 0x21:
            raise RcdErrorMissizedPayload()

        elif self.next_cmd != 2:
            raise RcdErrorHandshakeSequence()

        num_versions = data[0x20]
        versions = data[0x21:]
        if len(versions) != num_versions:
            raise RcdErrorMissizedPayload()

        try:
            selected_version = next(x for x in self.server_info.versions
                                    if x in versions)
        except StopIteration:
            raise RcdErrorHandshakeBadVersions()

        pairing_id = data[:0x20]
        if pairing_id == self.device.pairing_id:
            self.next_cmd = 4
        elif not self.pairing:
            raise RcdErrorHandshakeUnrecognizedDevice()
        else:
            self.next_cmd = 3

        self.device.version = selected_version

        resp  = self.device.pairing_id
        resp += pad_to(bytes([selected_version]), 0x10)

        return resp

    @RcdService.cmd(3)
    def get_secret_key(self, data: bytes):
        if len(data) != 0x20:
            raise RcdErrorMissizedPayload()

        elif self.next_cmd != 3:
            raise RcdErrorHandshakeSequence()

        self.next_cmd = 4

        return self.device.secret_key

    @RcdService.cmd(4)
    def finalize(self, data: bytes):
        if len(data) != 0x20:
            raise RcdErrorMissizedPayload()

        elif self.next_cmd != 4:
            raise RcdErrorHandshakeSequence()

        elif self.sha256.copy().digest() != data:
            raise RcdErrorHandshakeHash()

        self.next_cmd = 0

        l.info('Device completed handshake: %s', self.device)
        if self.handler:
            loop = asyncio.get_running_loop()
            loop.call_soon(self.handler.device_connected, self.device)

        # Flush the SHA256 buffer and hash this latest payload
        self.sha256.update(self.sha256_buf + data)
        self.sha256_buf = b''
        return self.sha256.digest()

    def close(self):
        if self.next_cmd == 0:
            l.info('Device disconnected: %s', self.device)
            if self.handler:
                self.handler.device_disconnected(self.device)
