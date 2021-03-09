# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import asyncio
import binascii
from aiohttp import web

from ..fuji import Fuji
from .. import OpenKart


routes = web.RouteTableDef()

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
    state = request.app.openkart.state
    d = {'state': state._name_}
    if request.app.openkart.pairing_seed and request.app.openkart.pairing_ssid:
        d['pairing'] = {
            'seed': binascii.hexlify(request.app.openkart.pairing_seed).decode(),
            'ssid': request.app.openkart.pairing_ssid,
        }
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

        self.add_routes(routes)

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
        status['signal'] = fuji.signal

    @classmethod
    def describe_device(cls, d: dict, device):
        if isinstance(device, Fuji):
            cls.describe_fuji(d, device)
            return True

    def find_device(self, serial: str):
        for device in self.openkart.devices:
            if device.product_code.serial == serial:
                return device
