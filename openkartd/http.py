# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import asyncio
from aiohttp import web

from . import OpenKart
from .api.v1 import API as v1

class OpenKartApplication(web.Application):
    def __init__(self, openkart: OpenKart, *, docroot: str = None):
        super().__init__()

        self.add_subapp('/v1', v1(openkart))

        if docroot:
            self.router.add_static('/', docroot)

if __name__ == '__main__':
    web.run_app(app)
