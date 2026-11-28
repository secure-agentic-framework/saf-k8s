#!/usr/bin/env python3
"""Hold one authorized Flower Fleet HTTP/2 transport open without an RPC."""

import argparse
import json
import socket
import ssl
import struct
import sys
import time

from relay import FLEET_HOST, HANDSHAKE_TIMEOUT, SENTINEL, tls_context


PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS = struct.pack("!3sBB4s", b"\x00\x00\x00", 0x04, 0x00, b"\x00\x00\x00\x00")
SETTINGS_ACK = struct.pack("!3sBB4s", b"\x00\x00\x00", 0x04, 0x01, b"\x00\x00\x00\x00")
MAX_FRAME = 65536
DEFAULT_HOLD_SECONDS = 180.0


def emit(name, **fields):
    print(json.dumps({"event": name, **fields}, sort_keys=True, separators=(",", ":")), flush=True)


def recv_exact(sock, count):
    chunks = bytearray()
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            if chunks:
                raise EOFError("peer closed during an HTTP/2 frame")
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def read_frame(sock):
    header = recv_exact(sock, 9)
    if header is None:
        return None
    length = int.from_bytes(header[:3], "big")
    if length > MAX_FRAME:
        raise ValueError(f"HTTP/2 frame length {length} exceeds bound {MAX_FRAME}")
    payload = recv_exact(sock, length)
    if payload is None:
        raise EOFError("peer closed before the HTTP/2 payload")
    return header[3], header[4], header[5:9], payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("address")
    parser.add_argument("port", type=int)
    parser.add_argument("--once", action="store_true",
                        help="exit after confirming a real TLS and HTTP/2 Fleet connection")
    parser.add_argument("--hold-seconds", type=float, default=DEFAULT_HOLD_SECONDS)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.hold_seconds <= 600:
        parser.error("port must be valid and hold-seconds must be between 1 and 600")

    sock = None
    try:
        context = tls_context()
        raw = socket.create_connection((args.address, args.port), timeout=HANDSHAKE_TIMEOUT)
        sock = context.wrap_socket(raw, server_hostname=FLEET_HOST)
        sock.settimeout(HANDSHAKE_TIMEOUT)
        sentinel = recv_exact(sock, len(SENTINEL))
        if sentinel != SENTINEL:
            raise RuntimeError("relay sentinel mismatch or premature close")

        # Speak only the HTTP/2 connection preface and empty SETTINGS. This
        # initializes the real gRPC transport without issuing any RPC.
        sock.sendall(PREFACE + SETTINGS)
        first = read_frame(sock)
        if (first is None or first[:3] != (0x04, 0, b"\x00" * 4)
                or len(first[3]) % 6):
            raise RuntimeError("Fleet did not return an initial HTTP/2 SETTINGS frame")
        sock.sendall(SETTINGS_ACK)

        tls = sock.version()
        emit("fleet-hold-ready", tls=tls, settings_observed=True)
        if args.once:
            return 0
        deadline = time.monotonic() + args.hold_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                emit("fleet-hold-failed", outcome="hold-timeout")
                return 2
            sock.settimeout(remaining)
            try:
                frame = read_frame(sock)
            except (socket.timeout, TimeoutError):
                emit("fleet-hold-failed", outcome="hold-timeout")
                return 2
            except ssl.SSLZeroReturnError:
                emit("fleet-hold-closed", outcome="closed")
                return 0
            except ssl.SSLEOFError:
                emit("fleet-hold-closed", outcome="closed")
                return 0
            if frame is None:
                emit("fleet-hold-closed", outcome="closed")
                return 0
            frame_type, flags, stream_id, payload = frame
            # ACK legitimate peer SETTINGS changes; no application data or RPC
            # frames are sent by this holder.
            if frame_type == 0x04 and flags == 0 and stream_id == b"\x00" * 4 and len(payload) % 6 == 0:
                sock.sendall(SETTINGS_ACK)
            if frame_type == 0x06 and flags == 0 and stream_id == b"\x00" * 4 and len(payload) == 8:
                sock.sendall(b"\x00\x00\x08\x06\x01" + stream_id + payload)
    except (OSError, ssl.SSLError, EOFError, RuntimeError, ValueError) as exc:
        emit("fleet-hold-failed", outcome="transport-error", detail=type(exc).__name__)
        return 2
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
