# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import asyncio
import binascii
import json
import logging

from aiohttp import web, WSMsgType

from ..fuji import Fuji
from ..pubsub import PubSub, Subscriber
from .. import OpenKart

l = logging.getLogger(__name__)


routes = web.RouteTableDef()


async def drive_device(device, data: dict):
    """Apply a {"throttle", "steering", "brake"} command, values in [-1, 1]."""
    if not isinstance(device, Fuji):
        raise ValueError('device cannot be driven')

    def axis(name):
        value = float(data.get(name, 0))
        if not -1 <= value <= 1:
            raise ValueError(f'{name} out of range [-1, 1]')
        return value

    await device.set_drive(axis('throttle'), axis('steering'),
                           bool(data.get('brake', False)))

class WebSocketSubscriber(Subscriber):
    def __init__(self, ps: PubSub, ws):
        super().__init__(ps)

        self.ws = ws

    def receive(self, data):
        asyncio.create_task(self.__receive(data))

    async def __receive(self, data):
        if isinstance(data, bytes):
            await self.ws.send_bytes(data)

        else:
            await self.ws.send_str(json.dumps(data))

@routes.get('/ws')
async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        subscriber = WebSocketSubscriber(request.app.pubsub, ws)

        async def cmd_subscribe(data):
            return subscriber.subscribe(data.get('topic'))

        async def cmd_unsubscribe(data):
            return subscriber.unsubscribe(data.get('s'))

        async def cmd_drive(data):
            device = request.app.find_device(data.get('serial'))
            if not device:
                raise KeyError('no such device')
            await drive_device(device, data)
            return True

        CMDS = {
            'subscribe': cmd_subscribe,
            'unsubscribe': cmd_unsubscribe,
            'drive': cmd_drive,
        }

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                    except json.decoder.JSONDecodeError:
                        l.warning('Disconnecting WS client due to invalid JSON')
                        break

                    response = {'id': data.get('id')}

                    cmd = data.get('cmd')
                    func = CMDS.get(cmd)
                    try:
                        if func is None: raise Exception(f'command {cmd!r} undefined')
                        result = await func(data)
                    except Exception as e:
                        response['error'] = repr(e)
                        l.warning('WS command %r resulted in error %r',
                                  data, e)
                    else:
                        response['result'] = result

                    if 'id' in data:
                        await ws.send_str(json.dumps(response))

                elif msg.type == WSMsgType.ERROR:
                    l.warning('Disconnecting WS client due to '
                              'error %r', msg)
                    break

                else:
                    l.warning('Disconnecting WS client due to '
                              'unrecognized message type %r', msg.type)
                    break

        finally:
            subscriber.unsubscribe_all(silent=True)

        return ws

@routes.get('/devices')
async def handler(request):
    devices = []

    for device in request.app.openkart.devices:
        d = {}
        if request.app.describe_device(d, device):
            devices.append(d)

    return web.json_response({'devices': devices})


@routes.get('/devices/{serial}')
async def handler(request):
    serial = request.match_info['serial']
    device = request.app.find_device(serial)
    if not device:
        raise web.HTTPNotFound()

    d = {}
    if request.app.describe_device(d, device):
        return web.json_response(d)
    else:
        raise web.HTTPNotFound()


@routes.post('/devices/{serial}/shutdown')
async def handler(request):
    serial = request.match_info['serial']
    device = request.app.find_device(serial)
    if not device:
        raise web.HTTPNotFound()

    await device.shutdown()
    return web.json_response(True)


@routes.get('/devices/{serial}/video.mjpeg')
async def handler(request):
    device = request.app.find_device(request.match_info['serial'])
    if not isinstance(device, Fuji):
        raise web.HTTPNotFound()
    if device.video is None:
        raise web.HTTPServiceUnavailable(text='video support not available')

    await device.wake()

    boundary = 'frame'
    response = web.StreamResponse(headers={
        'Content-Type': f'multipart/x-mixed-replace; boundary={boundary}',
        'Cache-Control': 'no-cache',
    })
    await response.prepare(request)

    video = device.video
    video.viewers += 1
    try:
        last = 0
        while device.video is video:
            result = await video.next_jpeg(last)
            if result is None or result[1] is None:
                continue
            last, jpeg = result
            await response.write(
                f'--{boundary}\r\nContent-Type: image/jpeg\r\n'
                f'Content-Length: {len(jpeg)}\r\n\r\n'.encode() + jpeg + b'\r\n')
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    finally:
        video.viewers -= 1

    return response


@routes.post('/devices/{serial}/drive')
async def handler(request):
    serial = request.match_info['serial']
    device = request.app.find_device(serial)
    if not device:
        raise web.HTTPNotFound()

    try:
        await drive_device(device, await request.json())
    except ValueError as e:
        raise web.HTTPNotAcceptable(text=str(e))

    return web.json_response(True)


@routes.get('/state')
async def get_state_handler(request):
    d = {}
    request.app.describe_state(d)
    return web.json_response(d)

@routes.post('/state')
async def handler(request):
    body = await request.json()
    state_str = body.get('state')
    state = request.app.openkart.State.__members__.get(state_str)
    if state is None:
        raise web.HTTPNotAcceptable(text=f'unknown state {state_str}')

    try:
        await request.app.openkart.set_state(state)
    except AttributeError:
        raise web.HTTPNotAcceptable(text='server not configured for this')

    return await get_state_handler(request)


class API(web.Application):
    def __init__(self, openkart: OpenKart):
        super().__init__()

        self.openkart = openkart
        self.pubsub = PubSub()

        self.pubsub.create_topic('devices')
        self.pubsub.create_topic('state')
        asyncio.create_task(self.poll_task())

        self.add_routes(routes)

    async def poll_task(self):
        # TODO: Remove this task; use events instead
        while True:
            await asyncio.sleep(0.1)

            if not self.openkart._state_lock.locked():
                with self.pubsub.topic('state') as d:
                    self.describe_state(d)

            with self.pubsub.topic('devices') as d:
                devices = d.setdefault('devices', [])

                num_devs = len(self.openkart.devices)
                del devices[num_devs:]
                for i,x in enumerate(self.openkart.devices):
                    if i == len(devices):
                        devices.append({})

                    self.describe_device(devices[i], x)

    @staticmethod
    def describe_fuji(d: dict, fuji: Fuji):
        d.setdefault('kind', 'Fuji')

        info = d.setdefault('info', {})
        info.setdefault('serial', fuji.product_code.serial)
        info.setdefault('mac_address', fuji.mac_address)
        info.setdefault('address', fuji.address)
        info.setdefault('character', fuji.product_code.character)

        version = info.setdefault('version', {})
        version.setdefault('system', fuji.system_info.system_version)
        version.setdefault('boot', fuji.system_info.boot_version)
        version.setdefault('sha1', fuji.system_info.sha1)

        status = d.setdefault('status', {})
        status['battery'] = fuji.battery_state
        status['battery_percent'] = fuji.battery_percent
        status['cable_connected'] = fuji.cable_connected
        status['driving'] = bool(fuji.drive and fuji.drive.active)
        status['video'] = bool(fuji.video and fuji.video.streaming)
        if fuji.video:
            d['video'] = fuji.video.stats()
        if status.get('signal') != fuji.signal:
            status['signal'] = fuji.signal

    @classmethod
    def describe_device(cls, d: dict, device):
        if isinstance(device, Fuji):
            cls.describe_fuji(d, device)
            return True

    def describe_state(self, d: dict):
        d['state'] = self.openkart.state._name_
        if self.openkart.pairing_seed and self.openkart.pairing_ssid:
            pairing = d.setdefault('pairing', {})
            if self.openkart.pairing_ssid != pairing.get('ssid'):
                pairing['seed'] = binascii.hexlify(self.openkart.pairing_seed).decode()
                pairing['ssid'] = self.openkart.pairing_ssid
                pairing['channel'] = self.openkart.pairing_channel

        elif 'pairing' in d:
            del d['pairing']

    def find_device(self, serial: str):
        for device in self.openkart.devices:
            if device.product_code.serial == serial:
                return device
