import asyncio
import json
import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from config import settings

router = APIRouter()

connected_clients: list[WebSocket] = []


async def redis_listener():
    while True:
        try:
            r = aioredis.from_url(settings.redis_url, decode_responses=True)
            pubsub = r.pubsub()
            await pubsub.subscribe("events:live")
            while True:
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )
                if message and message["type"] == "message":
                    data = message["data"]
                    dead = []
                    for client in connected_clients:
                        try:
                            await client.send_text(data)
                        except Exception:
                            dead.append(client)
                    for d in dead:
                        connected_clients.remove(d)
                await asyncio.sleep(0.1)
        except Exception as e:
            print(f"Redis listener error: {e} — retrying in 3s")
            await asyncio.sleep(3)


@router.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_text('{"type":"ping"}')
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)