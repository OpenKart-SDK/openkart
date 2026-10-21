# SPDX-License-Identifier: BSD-3-Clause

"""Reassembly and decoding of a kart's "LSP" video stream.

The kart streams H.264 (High profile, 1280x800, 30fps, one slice per frame)
over UDP in 1416-byte packets. Layout, reverse-engineered from captures:

  0x00  2  magic ec c1
  0x02  3  packet sequence number (big-endian)
  0x05  1  frame number (low byte)
  0x06  1  number of fragments in this frame
  0x07  1  index of this fragment
  0x08  5  chunk header: 0x0a, sequence number again, flags|length

Fragment 0 carries a 32-byte "FRAM" record (u32 BE at +4 is the frame size,
which counts 31 bytes of headers) followed by a 2-byte chunk header; the
first packet of a stream also has an extra session record before it. Data
runs to offset 0x580 in every fragment; middle fragments start at 0x0d and
the last fragment at 0x11, followed by stale bytes from the previous packet.
The last 8 bytes of every packet are a timestamp/counter trailer.

The kart only sends a keyframe (with SPS/PPS) when its encoder starts, and
keeps the encoder running across reconnections, so the stream is decoded
continuously here and served to viewers as JPEG images. Toggling SetState
does not restart the encoder; only power-cycling the kart does (the keyframe
comes with the first SetState(1) after power-on). Home Circuit presumably
requests keyframes over the "LSP" TCP connection, whose protocol is unknown.
"""

import asyncio
import io
import logging
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

l = logging.getLogger(__name__)

MAGIC = b'\xec\xc1'
DATA_END = 0x580
MID_START = 0x0d
LAST_START = 0x11
FRAME_OVERHEAD = 31


class FrameAssembler:
    """Turns video packets into complete H.264 access units (Annex B)."""

    def __init__(self):
        self.fragments = None
        self.expected_seq = None
        self.lost = 0

    def feed(self, packet: bytes):
        """Returns a complete frame's bytes, or None."""
        if len(packet) < DATA_END or packet[:2] != MAGIC:
            return None

        seq = int.from_bytes(packet[2:5], 'big')
        if self.expected_seq is not None and seq != self.expected_seq:
            self.lost += (seq - self.expected_seq) & 0xFFFFFF
        self.expected_seq = (seq + 1) & 0xFFFFFF

        count, index = packet[6], packet[7]
        if index == 0:
            self.fragments = [packet]
        elif self.fragments is not None and index == len(self.fragments):
            self.fragments.append(packet)
        else:
            self.fragments = None  # lost a fragment: drop this frame
            return None

        if len(self.fragments) < count:
            return None

        fragments, self.fragments = self.fragments, None
        return self.assemble(fragments)

    @staticmethod
    def assemble(fragments: list):
        first = fragments[0]
        f = first.find(b'FRAM')
        if f < 0:
            return None

        total = struct.unpack_from('>I', first, f + 4)[0] - FRAME_OVERHEAD
        out = bytearray(first[f + 34:DATA_END][:total])
        for p in fragments[1:-1]:
            out += p[MID_START:DATA_END]
        if len(fragments) > 1:
            out += fragments[-1][LAST_START:LAST_START + max(total - len(out), 0)]
        return bytes(out)


class FujiVideo:
    """Decodes a kart's video and keeps the latest frame as a JPEG."""

    JPEG_QUALITY = 75

    def __init__(self):
        import av  # optional dependency, only needed for video
        self.av = av

        self.assembler = FrameAssembler()
        self.codec = av.CodecContext.create('h264', 'r')
        self.executor = ThreadPoolExecutor(max_workers=1)

        self.viewers = 0
        self.packets = 0
        self.jpeg = None
        self.frame_id = 0
        self.frames_decoded = 0
        self.decode_errors = 0
        self.last_frame_time = 0.0
        self._event = asyncio.Event()
        self._loop = asyncio.get_running_loop()
        self._lock = threading.Lock()

    def handle_packet(self, packet: bytes):
        self.packets += 1
        frame = self.assembler.feed(packet)
        if frame is not None:
            self.executor.submit(self._decode_logged, frame)

    def _decode_logged(self, data: bytes):
        try:
            self._decode(data)
        except Exception:
            l.exception('Video decoding failed')

    def stats(self) -> dict:
        return {
            'packets': self.packets,
            'frames': self.frames_decoded,
            'decode_errors': self.decode_errors,
            'lost_packets': self.assembler.lost,
            'viewers': self.viewers,
            'needs_keyframe': self.needs_keyframe,
        }

    def _decode(self, data: bytes):
        # Always decode, even without viewers, to keep the reference frames
        # current; only convert to JPEG when someone is watching.
        try:
            frames = [f for p in self.codec.parse(data)
                      for f in self.codec.decode(p)]
        except self.av.error.FFmpegError as e:
            self.decode_errors += 1
            l.debug('Video decode error: %s', e)
            return

        for frame in frames:
            self.frames_decoded += 1
            self.last_frame_time = time.monotonic()
            if not self.viewers:
                continue
            buf = io.BytesIO()
            frame.to_image().save(buf, 'JPEG', quality=self.JPEG_QUALITY)
            with self._lock:
                self.jpeg = buf.getvalue()
                self.frame_id += 1
            self._loop.call_soon_threadsafe(self._notify)

    def _notify(self):
        self._event.set()
        self._event = asyncio.Event()

    async def next_jpeg(self, after_id: int, timeout: float = 2.0):
        """Wait for a frame newer than after_id; returns (id, jpeg) or None."""
        event = self._event
        if self.frame_id <= after_id:
            try:
                await asyncio.wait_for(event.wait(), timeout)
            except asyncio.TimeoutError:
                return None
        with self._lock:
            return self.frame_id, self.jpeg

    @property
    def needs_keyframe(self) -> bool:
        """Packets arrive but nothing decodes: the keyframe was missed."""
        return self.packets > 90 and self.frames_decoded == 0

    @property
    def streaming(self) -> bool:
        return time.monotonic() - self.last_frame_time < 1.0

    def close(self):
        self.executor.shutdown(wait=False, cancel_futures=True)
