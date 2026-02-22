# Notifier.py
"""
Notification module (Strategy Pattern) for security detector.

- BaseNotifier: abstract strategy interface
- ConsoleNotifier: colored terminal output by severity level
- MatrixNotifier: send message to Matrix room via requests
- NotificationManager: fan-out to multiple notifiers with severity filtering

Expected input data (from analyzer.py):
    { 'time': ..., 'path': ..., 'action': ..., 'score': int, 'level': 'Info'|'Warning'|'Critical', ... }

Dependencies:
    pip install requests
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

import requests

Level = Literal["Info", "Warning", "Critical"]


# ----------------------------
# Severity helpers
# ----------------------------
_LEVEL_ORDER: Dict[str, int] = {"Info": 10, "Warning": 20, "Critical": 30}


def level_value(level: str) -> int:
    return _LEVEL_ORDER.get(level, 0)


def should_notify(level: str, minimum_level: str) -> bool:
    return level_value(level) >= level_value(minimum_level)


def format_event_line(data: Dict[str, Any]) -> str:
    t = data.get("time", "?")
    level = data.get("level", "?")
    score = data.get("score", "?")
    action = data.get("action", "?")
    path = data.get("path", "?")
    return f"[{t}] {level} (score={score}) {action}: {path}"


# ----------------------------
# Strategy interface
# ----------------------------
class BaseNotifier(ABC):
    """
    Strategy interface. Concrete notifiers implement send().
    """

    @abstractmethod
    def send(self, data: Dict[str, Any]) -> None:
        raise NotImplementedError


# ----------------------------
# Console notifier
# ----------------------------
class ConsoleNotifier(BaseNotifier):
    """
    Prints messages to the terminal with ANSI colors per severity.
    """

    # ANSI escape codes (no external deps)
    _RESET = "\033[0m"
    _BOLD = "\033[1m"
    _DIM = "\033[2m"

    _COLOR_INFO = "\033[36m"      # cyan
    _COLOR_WARNING = "\033[33m"   # yellow
    _COLOR_CRITICAL = "\033[31m"  # red

    def __init__(self, *, include_json: bool = False) -> None:
        self._include_json = include_json

    def _color_for(self, level: str) -> str:
        if level == "Critical":
            return self._COLOR_CRITICAL
        if level == "Warning":
            return self._COLOR_WARNING
        return self._COLOR_INFO

    def send(self, data: Dict[str, Any]) -> None:
        level = str(data.get("level", "Info"))
        color = self._color_for(level)

        line = format_event_line(data)
        prefix = f"{self._BOLD}{color}{level}{self._RESET}"
        # Replace the first occurrence of level in the formatted line for a nicer look
        pretty = line.replace(level, prefix, 1)

        print(pretty)

        if self._include_json:
            print(f"{self._DIM}{json.dumps(data, ensure_ascii=False)}{self._RESET}")


# ----------------------------
# Matrix notifier
# ----------------------------
@dataclass(frozen=True)
class MatrixConfig:
    homeserver_url: str          # e.g., "https://matrix.example.com"
    access_token: str            # "syt_..."
    room_id: str                 # e.g., "!abcdef:example.com"
    # optional tuning
    timeout_seconds: float = 8.0
    verify_tls: bool = True      # set False only for testing/self-signed (not recommended)
    message_type: str = "m.notice"  # or "m.text"


class MatrixNotifier(BaseNotifier):
    """
    Sends a text message to a Matrix room using client-server API.

    Uses:
        POST /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}

    Note:
      - This is a minimal implementation. For production use, consider retries/backoff
        and a dedicated Matrix SDK.
    """

    def __init__(self, config: MatrixConfig) -> None:
        self._cfg = config
        self._base = self._cfg.homeserver_url.rstrip("/")

    def _endpoint(self, txn_id: str) -> str:
        room = requests.utils.quote(self._cfg.room_id, safe="")
        return f"{self._base}/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn_id}"

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._cfg.access_token}"}

    def _build_body(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # Keep it simple: human readable line + JSON fallback
        text = format_event_line(data)
        return {
            "msgtype": self._cfg.message_type,
            "body": text,
            # Include JSON as formatted block for clients that show it nicely
            "format": "org.matrix.custom.html",
            "formatted_body": (
                f"<pre>{json.dumps(data, ensure_ascii=False, indent=2)}</pre>"
            ),
        }

    def send(self, data: Dict[str, Any]) -> None:
        txn_id = str(int(time.time() * 1000))
        url = self._endpoint(txn_id)
        body = self._build_body(data)

        resp = requests.post(
            url,
            headers=self._headers(),
            json=body,
            timeout=self._cfg.timeout_seconds,
            verify=self._cfg.verify_tls,
        )
        # Raise on non-2xx so the caller can handle/log it
        resp.raise_for_status()


# ----------------------------
# Manager (fan-out + filtering)
# ----------------------------
class NotificationManager:
    """
    Manages multiple notifiers and broadcasts to all of them in one call.

    Filtering:
      - minimum_level: only send if data['level'] >= minimum_level
      - per-notifier overrides supported via add_notifier(..., minimum_level=...)
    """

    def __init__(self, *, minimum_level: str = "Info") -> None:
        self._default_min_level = minimum_level
        self._items: List[Tuple[BaseNotifier, str]] = []

    def add_notifier(self, notifier: BaseNotifier, *, minimum_level: Optional[str] = None) -> None:
        self._items.append((notifier, minimum_level or self._default_min_level))

    def notify(self, data: Dict[str, Any]) -> None:
        level = str(data.get("level", "Info"))

        for notifier, min_level in self._items:
            if not should_notify(level, min_level):
                continue
            try:
                notifier.send(data)
            except Exception:
                # Don't let one notifier failure break others.
                # In production, replace with proper logging.
                continue


# ----------------------------
# Demo usage
# ----------------------------
def _demo() -> None:
    sample = {
        "time": "2026-02-21T00:00:00Z",
        "path": "/home/user/.ssh/id_rsa",
        "action": "modified",
        "score": 80,
        "level": "Critical",
    }

    mgr = NotificationManager(minimum_level="Warning")

    # Console: show Warning+
    mgr.add_notifier(ConsoleNotifier(include_json=False), minimum_level="Warning")

    mgr.notify(sample)


if __name__ == "__main__":
    _demo()