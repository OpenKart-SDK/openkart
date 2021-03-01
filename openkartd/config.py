# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import logging
import hmac
import binascii
import ipaddress
import subprocess
import atexit

from configparser import ConfigParser
from tempfile import TemporaryDirectory
from pathlib import Path

from aiohttp import web

from .rcd import RcdServerInfo
from .lp2p import GroupInfo, LP2PAP
from .http import OpenKartApplication
from . import OpenKart


class ConfigError(Exception):
    pass


class Config:
    def __init__(self):
        self.parser = ConfigParser()

        self.loglevel = None
        self.address = None
        self.interface = None
        self.network = None
        self.group_info = None
        self.rcd_info = None
        self.tempdir_prefix = None
        self.hostapd_path = None
        self.udhcpd_path = None
        self.autostart = None
        self.http = None
        self.docroot = None

    def read(self, f):
        self.parser.read_file(f)

    def parse_bool(self, key, value):
        KEYWORDS = {
            '0': False,
            '1': True,
            'n': False,
            'y': True,
            'no': False,
            'yes': True,
            'f': False,
            't': True,
            'false': False,
            'true': True,
        }
        result = KEYWORDS.get(value.lower())
        if result is None:
            raise ConfigError(f'Unrecognized boolean for {key}: {value}')
        return result

    def process(self):
        try:
            general = self.parser['general']
        except KeyError:
            general = {}

        try:
            wireless = self.parser['wireless']
        except KeyError:
            wireless = {}

        try:
            rcd = self.parser['rcd']
        except KeyError:
            rcd = {}

        loglevel = general.pop('loglevel', 'WARNING')
        loglevel = logging.getLevelName(loglevel)
        if not isinstance(loglevel, int):
            raise ConfigError(f'Invalid loglevel: {loglevel}')

        secret = general.pop('secret', None)
        def derive(name: str, length: int):
            assert length <= 0x40
            if not secret:
                raise ConfigError(f'general/secret must be set to derive {name}')
            h = hmac.HMAC(digestmod='sha512', key=secret.encode(),
                          msg=name.encode())
            return h.digest()[:length]

        def from_hex(name: str, h: str, length: int = None):
            try:
                data = binascii.unhexlify(h)
            except binascii.Error as e:
                raise ConfigError(f'{name} must be hexadecimal') from e

            if length is not None and len(data) != length:
                raise ConfigError(f'{name} is wrong length')

            return data

        address = general.pop('address', None)
        if address is not None:
            try:
                address = ipaddress.IPv4Address(address)
            except Exception as e:
                raise ConfigError(f'Invalid IPv4 address: {address}') from e

        interface = wireless.pop('interface', None)
        network = wireless.pop('network', None)
        if network is not None:
            try:
                network = ipaddress.IPv4Network(network)
            except Exception as e:
                raise ConfigError(f'Invalid IPv4 network: {network}') from e

            if address is None:
                address = network.network_address + 1
            elif address not in network:
                raise ConfigError(f'Address {address} not in {network}')

        ssid = wireless.pop('ssid', None)
        psk  = wireless.pop('psk',  None)

        if psk is not None:
            psk = from_hex('wireless/psk', psk, 0x20)

        if interface is not None:
            if ssid is None:
                random_bytes = derive('wireless/ssid', 0xC)
                random_b64 = binascii.b2a_base64(random_bytes).decode().strip()
                ssid = f'openkart_{random_b64}'

            if psk is None:
                psk = derive('wireless/psk', 0x20)

        channel = wireless.pop('channel', None)
        group_info = None
        if ssid and psk:
            try:
                channel = channel and int(channel)
                group_info = GroupInfo(ssid=ssid, psk=psk, channel=channel)
            except ValueError as e:
                raise ConfigError(str(e)) from e

        name = rcd.pop('name', 'OpenKart')
        ident = rcd.pop('ident', None)
        master_key = rcd.pop('master_key', None)

        if ident is None:
            ident = derive('rcd/ident', 0x10)
        else:
            ident = from_hex('rcd/ident', ident, 0x10)

        if master_key is None:
            master_key = derive('rcd/master_key', 0x40)
        else:
            master_key = from_hex('rcd/master_key', master_key)

        rcd_info = RcdServerInfo(
            name=name,
            ident=ident,
            master_key=master_key,
        )

        tempdir_prefix = general.pop('tempdir_prefix', 'openkart')
        hostapd_path   = wireless.pop('hostapd_path', None)
        udhcpd_path    = wireless.pop('udhcpd_path', 'udhcpd')
        autostart      = self.parse_bool('general/autostart',
                                         general.pop('autostart', 'yes'))

        http = general.pop('http', '*:8181')
        http = http.rsplit(':', 1)
        if len(http) != 2 or not http[1].isdigit():
            raise ConfigError('general/http malformed IP:port')
        host, port = http
        if host == '*':
            host = None
        else:
            if host.startswith('[') and host.endswith(']'):
                host = host[1:-1]
            try:
                ipaddress.ip_address(host)
            except ValueError:
                raise ConfigError('general/http has malformed bind address')

        docroot = general.pop('docroot', None)

        unrecognized = []
        for section in self.parser.sections():
            for key in self.parser[section]:
                unrecognized.append(f'{section}/{key}')
        if unrecognized:
            raise ConfigError(f'Unrecognized: {" ".join(unrecognized)}')

        self.loglevel = loglevel
        self.address = address
        self.interface = interface
        self.network = network
        self.group_info = group_info
        self.rcd_info = rcd_info
        self.tempdir_prefix = tempdir_prefix
        self.hostapd_path = hostapd_path
        self.udhcpd_path = udhcpd_path
        self.autostart = autostart
        self.http = host, port
        self.docroot = docroot

        logging.basicConfig(level=self.loglevel)

    async def make_openkart(self):
        kwargs = {}

        if self.address is not None:
            kwargs['address'] = str(self.address)

        if self.interface is not None:
            self.tempdir = TemporaryDirectory(prefix=self.tempdir_prefix)
            tempdir_path = Path(self.tempdir.name)

            kwargs['ap'] = ap = LP2PAP(self.interface, tempdir_path)
            if self.hostapd_path is not None:
                ap.hostapd_path = self.hostapd_path

            if self.network is not None:
                prefix = f'{self.address}/{self.network.prefixlen}'
                subprocess.run(['ip', 'addr', 'flush', 'dev', self.interface])
                subprocess.run(['ip', 'addr', 'add', prefix, 'dev', self.interface])
                subprocess.run(['ip', 'link', 'set', self.interface, 'up'])

                udhcpd_config = tempdir_path/'udhcpd.conf'
                udhcpd_config.write_text('\n'.join([
                    f'start         {self.network.network_address+2}',
                    f'end           {self.network.broadcast_address-1}',
                    f'max_leases    {self.network.num_addresses-3}',
                    f'option subnet {self.network.netmask}',
                    f'interface     {self.interface}',
                    ''
                ]))
                udhcpd = subprocess.Popen([self.udhcpd_path,
                                           '-f', str(udhcpd_config)])
                atexit.register(udhcpd.terminate)

        openkart = OpenKart(
            rcd_info=self.rcd_info,
            group_info=self.group_info,
            **kwargs
        )

        if self.autostart:
            await openkart.set_state(openkart.State.RUNNING)

        app = OpenKartApplication(openkart, docroot=self.docroot)

        return openkart, app, self.http
