"""
Event Manager — pub/sub asynchrone.
Chaque événement est émis via emit() et dispatché à tous les handlers enregistrés.
Les handlers s'exécutent en tâches asyncio indépendantes pour ne pas bloquer la requête.
"""
from __future__ import annotations
import asyncio
import logging
from typing import Callable, Dict, List, Any
from app.events.event_types import EventType

logger = logging.getLogger("event_manager")


class EventManager:
    def __init__(self):
        self._handlers: Dict[EventType, List[Callable]] = {}
        self._global_handlers: List[Callable] = []

    def on(self, event_type: EventType, handler: Callable):
        """Enregistre un handler pour un type d'événement spécifique."""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    def on_any(self, handler: Callable):
        """Handler global appelé pour tous les événements."""
        self._global_handlers.append(handler)

    async def emit(self, event_type: EventType, data: Dict[str, Any]):
        """Émet un événement de manière asynchrone (non-bloquant)."""
        data["event_type"] = event_type

        handlers = self._handlers.get(event_type, []) + self._global_handlers
        if not handlers:
            return

        async def _run_handler(handler):
            try:
                await handler(event_type, data)
            except Exception as e:
                logger.error(f"Handler error [{handler.__name__}] for {event_type}: {e}")

        # Lance tous les handlers en parallèle sans bloquer la requête HTTP
        tasks = [asyncio.create_task(_run_handler(h)) for h in handlers]
        asyncio.gather(*tasks, return_exceptions=True)


# Instance globale unique
event_manager = EventManager()