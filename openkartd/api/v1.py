# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import asyncio
import binascii
import json

from aiohttp import web, WSMsgType

from ..fuji import Fuji
from ..pubsub import PubSub, Subscriber
from .. import OpenKart


routes = web.RouteTableDef()

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

        CMDS = {
            'subscribe': cmd_subscribe,
            'unsubscribe': cmd_unsubscribe,
        }

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                    except json.decoder.JSONDecodeError:
                        break

                    response = {'id': data.get('id')}

                    cmd = data.get('cmd')
                    func = CMDS.get(cmd)
                    try:
                        if func is None: raise Exception(f'command {cmd!r} undefined')
                        result = await func(data)
                    except Exception as e:
                        response['error'] = repr(e)
                    else:
                        response['result'] = result

                    if 'id' in data:
                        await ws.send_str(json.dumps(response))

                elif msg.type == WSMsgType.ERROR:
                    break

                else:
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
        status['cable_connected'] = fuji.cable_connected
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

        elif 'pairing' in d:
            del d['pairing']

    def find_device(self, serial: str):
        for device in self.openkart.devices:
            if device.product_code.serial == serial:
                return device
