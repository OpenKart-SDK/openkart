# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import sys
import asyncio
import argparse

from aiohttp import web

from .config import Config, ConfigError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('config', nargs='+')

    args = parser.parse_args()

    cfg = Config()

    for cfg_file in args.config:
        with open(cfg_file, 'r') as f:
            cfg.read(f)

    try:
        cfg.process()
    except ConfigError as e:
        print(f'Configuration error: {str(e)}', file=sys.stderr)
        raise SystemExit(1)

    async def coro():
        openkart, app, (apphost, appport) = await cfg.make_openkart()
        runner = web.AppRunner(app)        
        await runner.setup()
        site = web.TCPSite(runner, host=apphost, port=appport)
        await site.start()

        while True:
            await asyncio.sleep(3600)

    asyncio.run(coro())

main()
