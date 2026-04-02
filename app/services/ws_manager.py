"""
WebSocket Manager — push en temps réel des alertes de sécurité.
"""
from __future__ import annotations
import asyncio
import json
import logging
from typing import Set, Dict, Any
from fastapi import WebSocket

logger = logging.getLogger("ws_manager")


class WebSocketManager:
    def __init__(self):
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        logger.info(f"WS client connected. Total: {len(self._connections)}")

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            self._connections.discard(ws)
        logger.info(f"WS client disconnected. Total: {len(self._connections)}")

    async def broadcast_alert(self, payload: Dict[str, Any]):
        """Diffuse une alerte JSON à tous les clients connectés."""
        if not self._connections:
            return

        message = json.dumps({"type": "alert", "data": payload})
        dead: Set[WebSocket] = set()

        async with self._lock:
            connections_snapshot = set(self._connections)

        for ws in connections_snapshot:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)

        if dead:
            async with self._lock:
                self._connections -= dead

    async def broadcast_event(self, payload: Dict[str, Any]):
        """Diffuse un événement générique (stat update, etc.)."""
        if not self._connections:
            return
        message = json.dumps({"type": "event", "data": payload})
        dead: Set[WebSocket] = set()
        async with self._lock:
            connections_snapshot = set(self._connections)
        for ws in connections_snapshot:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        if dead:
            async with self._lock:
                self._connections -= dead

    @property
    def count(self) -> int:
        return len(self._connections)


ws_manager = WebSocketManager()