#!/usr/bin/env python3
"""Bounded mTLS TCP pass-through for the SAF Flower Fleet fixture."""

import argparse
import asyncio
import hashlib
import json
import re
import socket
import ssl
import sys


TLS_DIR = "/tls"
ALLOW_FILE = "/enrollment/allow.json"
FLEET_HOST = "flower-fleet.saf-fixture.test"
LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 19092
RELAY_PORT = 9443
FLEET_PORT = 9092
HANDSHAKE_TIMEOUT = 8.0
CONNECT_TIMEOUT = 5.0
COPY_CHUNK = 65536
SENTINEL = b"SAF-FLEET-AUTH-v1\n"
UPSTREAM_FAILURE = b"SAF-FLEET-UPSTREAM-UNAVAILABLE-v1\n"
PARTICIPANTS = {"participant-a", "participant-b", "participant-c"}


def event(name, **fields):
    row = {"event": name, **fields}
    print(json.dumps(row, sort_keys=True, separators=(",", ":")), flush=True)


def tls_context(*, server=False, present_certificate=True):
    if server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_verify_locations(cafile=f"{TLS_DIR}/ca.crt")
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{TLS_DIR}/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    if server or present_certificate:
        context.load_cert_chain(f"{TLS_DIR}/tls.crt", f"{TLS_DIR}/tls.key")
    return context


def read_allowlist(*, initial=False):
    def unique_entries(items):
        result = dict(items)
        if len(result) != len(items):
            raise ValueError("allowlist contains duplicate digests")
        return result

    with open(ALLOW_FILE, "r", encoding="utf-8") as source:
        parsed = json.load(source, object_pairs_hook=unique_entries)
    if not isinstance(parsed, dict):
        raise ValueError("allowlist must be a digest-to-participant object")
    valid = {}
    for digest, participant in parsed.items():
        if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or not isinstance(participant, str) or participant not in PARTICIPANTS):
            raise ValueError("allowlist contains an invalid entry")
        valid[digest] = participant
    if len(set(valid.values())) != len(valid):
        raise ValueError("allowlist must assign each digest and participant exactly once")
    if initial and (len(valid) != len(PARTICIPANTS) or set(valid.values()) != PARTICIPANTS):
        raise ValueError("initial allowlist must contain each participant exactly once")
    return valid


async def bridge(left_reader, left_writer, right_reader, right_writer, participant=None):
    seen = [False, False]
    reported = False

    async def pump_direction(reader, writer, direction):
        nonlocal reported
        try:
            while True:
                data = await reader.read(COPY_CHUNK)
                if not data:
                    try:
                        writer.write_eof()
                    except (AttributeError, OSError, RuntimeError):
                        pass
                    return
                writer.write(data)
                await writer.drain()
                seen[direction] = True
                if participant and all(seen) and not reported:
                    reported = True
                    event("fleet-forwarded", participant=participant,
                          client_and_server_bytes=True)
        except (ConnectionError, OSError, ssl.SSLError):
            return

    tasks = [asyncio.create_task(pump_direction(left_reader, right_writer, 0)),
             asyncio.create_task(pump_direction(right_reader, left_writer, 1))]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.gather(*done, return_exceptions=True)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(close(left_writer), close(right_writer))


def peer_digest(writer):
    ssl_object = writer.get_extra_info("ssl_object")
    peer = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
    return hashlib.sha256(peer).hexdigest() if peer else None


async def server_connection(reader, writer, state, original):
    digest = peer_digest(writer)
    participant = state["allowlist"].get(digest)
    if participant is None:
        if digest in state["retired"]:
            event("retired-leaf-denied", participant=original[digest])
        else:
            event("unenrolled-client")
        await close(writer)
        return
    task = asyncio.current_task()
    state["active"].setdefault(digest, set()).add(task)
    upstream_writer = None
    try:
        try:
            async with asyncio.timeout(CONNECT_TIMEOUT):
                upstream_reader, upstream_writer = await asyncio.open_connection(
                    LOCAL_HOST, FLEET_PORT)
        except (OSError, TimeoutError, ConnectionError):
            event("fleet-upstream-unavailable", participant=participant)
            writer.write(UPSTREAM_FAILURE)
            try:
                await writer.drain()
            except (ConnectionError, OSError):
                pass
            return
        event("relay-open", participant=participant)
        writer.write(SENTINEL)
        await writer.drain()
        await bridge(reader, writer, upstream_reader, upstream_writer, participant)
    except (ConnectionError, OSError, ssl.SSLError):
        pass
    finally:
        active = state["active"].get(digest)
        if active is not None:
            active.discard(task)
            if not active:
                state["active"].pop(digest, None)
        await asyncio.gather(close(writer), close(upstream_writer))


async def run_server():
    allowlist = read_allowlist(initial=True)
    original = dict(allowlist)
    state = {"allowlist": allowlist, "retired": set(), "active": {}}
    event("roster-reloaded", participants=sorted(set(allowlist.values())))

    async def reload_roster():
        while True:
            await asyncio.sleep(0.2)
            try:
                current = read_allowlist()
            except (OSError, ValueError):
                # A missing or malformed projected file immediately revokes all entries.
                current = {}
            if not set(current.items()).issubset(set(original.items())):
                # Do not let a refreshed roster substitute another leaf for an alias.
                current = {}
            if current == state["allowlist"]:
                continue
            removed = set(state["allowlist"]) - set(current)
            state["allowlist"] = current
            state["retired"] = set(original) - set(current)
            event("roster-reloaded", participants=sorted(set(current.values())))
            for digest in removed:
                for task in tuple(state["active"].get(digest, ())):
                    if not task.done():
                        event("retired-fleet-session", participant=original[digest])
                        task.cancel()

    context = tls_context(server=True)
    loop = asyncio.get_running_loop()

    async def handle(connection):
        reader = asyncio.StreamReader(limit=COPY_CHUNK)
        protocol = asyncio.StreamReaderProtocol(reader)
        try:
            transport, _ = await loop.connect_accepted_socket(
                lambda: protocol, connection, ssl=context, ssl_handshake_timeout=HANDSHAKE_TIMEOUT)
        except ssl.SSLError as error:
            if error.reason == "PEER_DID_NOT_RETURN_A_CERTIFICATE":
                event("client-certificate-required")
            return
        except (OSError, TimeoutError):
            return
        writer = asyncio.StreamWriter(transport, protocol, reader, loop)
        await server_connection(reader, writer, state, original)

    handlers = set()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", RELAY_PORT))
        listener.listen(32)
        listener.setblocking(False)
        reloader = asyncio.create_task(reload_roster())
        try:
            while True:
                connection, _ = await loop.sock_accept(listener)
                task = asyncio.create_task(handle(connection))
                handlers.add(task)
                task.add_done_callback(handlers.discard)
        finally:
            reloader.cancel()
            await asyncio.gather(reloader, return_exceptions=True)
            for task in handlers:
                task.cancel()
            await asyncio.gather(*handlers, return_exceptions=True)


async def client_connection(reader, writer, relay_address, relay_port, context):
    relay_writer = None
    try:
        async with asyncio.timeout(CONNECT_TIMEOUT):
            relay_reader, relay_writer = await asyncio.open_connection(
                relay_address, relay_port, ssl=context, server_hostname=FLEET_HOST,
                ssl_handshake_timeout=HANDSHAKE_TIMEOUT, limit=COPY_CHUNK)
            sentinel = await asyncio.wait_for(relay_reader.readexactly(len(SENTINEL)),
                                              timeout=HANDSHAKE_TIMEOUT)
        if sentinel != SENTINEL:
            raise ssl.SSLError("relay authentication marker mismatch")
    except (OSError, asyncio.IncompleteReadError, TimeoutError):
        await asyncio.gather(close(writer), close(relay_writer))
        return
    try:
        await bridge(reader, writer, relay_reader, relay_writer)
    except OSError:
        await asyncio.gather(close(relay_writer), close(writer))


async def run_client(address, port):
    # The local Flower endpoint is deliberately loopback-only.
    context = tls_context(server=False)

    async def handle(reader, writer):
        await client_connection(reader, writer, address, port, context)

    server = await asyncio.start_server(handle, LOCAL_HOST, LOCAL_PORT,
                                        limit=COPY_CHUNK)
    async with server:
        await server.serve_forever()


async def close(writer):
    if writer is None:
        return
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=2)
    except (OSError, TimeoutError):
        pass


async def run_probe(address, port, mode):
    context = tls_context(present_certificate=mode != "missing")
    server_name = "wrong.saf-fixture.test" if mode == "wrong-server" else FLEET_HOST
    writer = None
    result = {"mode": mode, "outcome": "infrastructure-error"}
    try:
        async with asyncio.timeout(CONNECT_TIMEOUT + HANDSHAKE_TIMEOUT):
            reader, writer = await asyncio.open_connection(
                address, port, ssl=context, server_hostname=server_name,
                ssl_handshake_timeout=HANDSHAKE_TIMEOUT, limit=COPY_CHUNK)
            if mode == "retired":
                prefix = await reader.read(1)
                if prefix == b"" and writer.get_extra_info("ssl_object") is not None:
                    result["outcome"] = "closed-without-admission"
            else:
                prefix = await reader.readuntil(b"\n")
                if prefix == SENTINEL:
                    result["outcome"] = "admitted" if mode == "approved" else "unexpectedly-admitted"
                    result["tls"] = writer.get_extra_info("ssl_object").version()
                elif prefix == UPSTREAM_FAILURE:
                    result["reason"] = "fleet-upstream-unavailable"
    except ssl.SSLCertVerificationError as exc:
        if mode == "wrong-server" and exc.verify_code == 62:
            result["outcome"] = "rejected-by-server-identity"
        else:
            result["reason"] = f"certificate-verification-{exc.verify_code}"
    except ssl.SSLError as exc:
        if mode == "missing" and exc.reason == "TLSV13_ALERT_CERTIFICATE_REQUIRED":
            result["outcome"] = "rejected-by-tls"
        else:
            result["reason"] = "unexpected-tls-error"
    except asyncio.IncompleteReadError as exc:
        if writer is not None and not exc.partial and mode in ("missing", "unassigned", "retired"):
            result["outcome"] = "closed-without-admission"
        else:
            result["reason"] = "incomplete-authentication"
    except (OSError, TimeoutError) as exc:
        result["reason"] = type(exc).__name__
    finally:
        await close(writer)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
    return 0


def parse_port(value):
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port is outside the valid TCP range")
    return port


def parse_args():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("server")
    client = commands.add_parser("client")
    client.add_argument("address", help="approved relay endpoint address")
    client.add_argument("port", type=parse_port)
    probe = commands.add_parser("probe")
    probe.add_argument("address", help="approved relay endpoint address")
    probe.add_argument("port", type=parse_port)
    probe.add_argument("mode", choices=("missing", "unassigned", "wrong-server", "approved", "retired"))
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        if args.command == "server":
            asyncio.run(run_server())
        elif args.command == "client":
            asyncio.run(run_client(args.address, args.port))
        else:
            return asyncio.run(run_probe(args.address, args.port, args.mode))
    except (OSError, ValueError) as exc:
        # Configuration failures remain visibly distinct from negative probes.
        event("relay-configuration-error", error_class=type(exc).__name__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
