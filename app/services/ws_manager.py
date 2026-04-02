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

    async def _broadcast(self, message: str):
        """Méthode interne pour diffuser un message en parallèle."""
        if not self._connections:
            return

        async with self._lock:
            connections_snapshot = list(self._connections)

        async def _send(ws: WebSocket):
            try:
                await ws.send_text(message)
                return None
            except Exception:
                return ws

        # Envoi en parallèle
        results = await asyncio.gather(*[_send(ws) for ws in connections_snapshot])
        
        # Nettoyage des connexions mortes
        dead = {ws for ws in results if ws is not None}
        if dead:
            async with self._lock:
                self._connections -= dead

    async def broadcast_alert(self, payload: Dict[str, Any]):
        """Diffuse une alerte JSON à tous les clients connectés."""
        await self._broadcast(json.dumps({"type": "alert", "data": payload}))

    async def broadcast_event(self, payload: Dict[str, Any]):
        """Diffuse un événement générique (stat update, etc.)."""
        await self._broadcast(json.dumps({"type": "event", "data": payload}))

    @property
    def count(self) -> int:
        return len(self._connections)


ws_manager = WebSocketManager()