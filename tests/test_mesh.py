from __future__ import annotations

import asyncio

from zero_trust_edge_agent_mesh.mesh import handle_framed


def test_framed_handler_roundtrip() -> None:
    async def run() -> None:
        async def handler(req: dict[str, object]) -> dict[str, object]:
            return {"ok": req["ping"]}

        server = await asyncio.start_server(
            lambda r, w: handle_framed(r, w, handler), "127.0.0.1", 0
        )
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        data = b'{"ping": true}'
        writer.write(len(data).to_bytes(4, "big") + data)
        await writer.drain()
        size = int.from_bytes(await reader.readexactly(4), "big")
        assert await reader.readexactly(size) == b'{"ok": true}'
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()

    asyncio.run(run())
