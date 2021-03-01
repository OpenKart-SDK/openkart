# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import asyncio
import logging

l = logging.getLogger(__name__)

pad_to = lambda x, l: x + b'\0'*(l - len(x))


async def retry_connect(protocol_factory, host, port, *, attempts=10, delay=0.1, timeout=0.2):
    loop = asyncio.get_running_loop()
    for tries_left in reversed(range(attempts)):
        try:
            coro = loop.create_connection(protocol_factory, host, port)
            connection = await asyncio.wait_for(coro, timeout)
            return connection

        except (asyncio.TimeoutError, ConnectionError) as e:
            if tries_left:
                await asyncio.sleep(delay)
            elif isinstance(e, ConnectionError):
                raise
            else:
                raise ConnectionError('All connection attempts timed out') from e


class GenericUDP(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        _, self.port = transport.get_extra_info('sockname')

        self.__callbacks = {}

    def datagram_received(self, data, peer):
        address, port = peer

        callback = self.__callbacks.get(address)
        if callback is None:
            l.debug('UDP packet received from %s, not registered', address)
            return

        loop = asyncio.get_running_loop()
        loop.call_soon(callback, data)

    def sendto(self, data: bytes, peer: tuple):
        self.transport.sendto(data, peer)

    def register(self, address: str, callback):
        if address in self.__callbacks:
            raise KeyError(f'Address {address} already registered')

        self.__callbacks[address] = callback

    def unregister(self, address: str):
        del self.__callbacks[address]


class TCPRendezvous:
    """This allows opening TCP by "expecting" an inbound connection."""

    class proto(asyncio.Protocol):
        def __init__(self, parent):
            asyncio.Protocol.__init__(self)

            self.__parent = parent

        def connection_made(self, transport):
            address, _ = transport.get_extra_info('peername')

            future = self.__parent._expects.get(address)
            if future:
                future.set_result(transport)
            else:
                l.warning('Unexpected TCP connection from %s', address)
                transport.close()

    def __init__(self):
        self.server = None

        self._expects = {}

    async def create_server(self, *args, **kwargs):
        loop = asyncio.get_running_loop()
        
        server = await loop.create_server(lambda: self.proto(self),
                                          *args, **kwargs)

        self.server = server
        _, self.port = server.sockets[0].getsockname()

        return server

    def close(self):
        if self.server is not None:
            self.server.close()
            self.server = None

    async def expect(self, protocol_factory, address: str):
        if address in self._expects:
            raise KeyError(f'Already expecting connection from {address}')

        loop = asyncio.get_running_loop()
        future = self._expects[address] = loop.create_future()

        try:
            transport = await future

            proto = protocol_factory()
            transport.set_protocol(proto)
            proto.connection_made(transport)

            return transport, proto

        finally:
            del self._expects[address]
