"""Async framed JSON mesh helpers with TLS contexts."""

from __future__ import annotations

import asyncio
import json
import ssl
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def tls_server_context(certfile: Path, keyfile: Path, cafile: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile, keyfile)
    ctx.load_verify_locations(cafile)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def tls_client_context(certfile: Path, keyfile: Path, cafile: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(cafile))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile, keyfile)
    ctx.check_hostname = False
    return ctx


async def send_frame(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, msg: dict[str, Any]
) -> dict[str, Any]:
    data = json.dumps(msg, sort_keys=True).encode()
    writer.write(len(data).to_bytes(4, "big") + data)
    await writer.drain()
    size = int.from_bytes(await reader.readexactly(4), "big")
    return dict(json.loads(await reader.readexactly(size)))


async def handle_framed(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, handler: Handler
) -> None:
    try:
        while True:
            header = await reader.readexactly(4)
            size = int.from_bytes(header, "big")
            req = dict(json.loads(await reader.readexactly(size)))
            resp = await handler(req)
            data = json.dumps(resp, sort_keys=True).encode()
            writer.write(len(data).to_bytes(4, "big") + data)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        writer.close()
        await writer.wait_closed()
