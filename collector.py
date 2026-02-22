# collector.py
"""
File system collector using watchdog.

Features:
- Watch multiple directories (recursively by default)
- Detect create/modify/delete events
- Emit normalized event dict:
  {'time': <ISO8601 UTC>, 'path': <str>, 'action': 'created'|'modified'|'deleted'}
- Supports callback or internal queue polling

Requirements:
    pip install watchdog
"""

from __future__ import annotations

import os
import time
import queue
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# 타입 힌트 정의: 이벤트 데이터는 문자열 키와 값을 가진 딕셔너리 형태
EventDict = Dict[str, str]
EventCallback = Callable[[EventDict], None]


def _utc_iso() -> str:
    # ISO 8601 in UTC with 'Z'
    """분석의 용이성을 위해 현재 시간을 ISO 8601 UTC 포맷으로 반환"""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _norm_path(path: str) -> str:
    # Normalize path for consistency across platforms
    r"""경로의 슬래시(/) 역슬래시(\) 등을 통일하고 절대 경로로 변환"""
    return os.path.normpath(os.path.abspath(path))


@dataclass(frozen=True)
class WatcherConfig:
    """감시기의 설정값을 담는 데이터 클래스"""
    recursive: bool = True          # 하위 폴더까지 감시할지 여부
    debounce_seconds: float = 0.15  # 동일 이벤트 중복 발생 시 무시할 시간
    ignore_directories: bool = True # 폴더 생성/수정 이벤트는 무시하고 파일만 볼지 여부


class _WatchdogHandler(FileSystemEventHandler):
    """Watchdog의 이벤트를 받아 시스템에 맞게 1차 가공하는 내부 클래스"""
    def __init__(
        self,
        emit: Callable[[EventDict], None],
        config: WatcherConfig,
    ) -> None:
        self._emit = emit
        self._config = config
        self._last_seen = {}  # 중복 이벤트 방지를 위해 (행위, 경로) 별 마지막 발생 시간을 기록
        self._lock = threading.Lock()

    def _should_ignore(self, event) -> bool:
        """설정에 따라 디렉토리 이벤트 필터링"""
        if self._config.ignore_directories and getattr(event, "is_directory", False):
            return True
        return False

    def _debounced(self, action: str, path: str) -> bool:
        """
        매우 짧은 시간 안에 발생하는 동일한 수정을 하나로 합침.
        (ex: 파일을 저장할 때 OS 레벨에서 수정 이벤트가 여러 번 발생하는 것 방지)
        """
        if self._config.debounce_seconds <= 0:
            return False

        key = (action, path)
        now = time.monotonic()
        with self._lock:
            last = self._last_seen.get(key)
            if last is not None and (now - last) < self._config.debounce_seconds:
                return True
            self._last_seen[key] = now
        return False

    def _handle(self, action: str, src_path: str) -> None:
        """이벤트를 최종적으로 정규화하여 배출(Emit)함."""
        path = _norm_path(src_path)

        if self._debounced(action, path):
            return

        event_dict: EventDict = {
            "time": _utc_iso(),
            "path": path,
            "action": action,
        }
        self._emit(event_dict)

    # Watchdog 라이브러리의 기본 이벤트 핸들러들을 오버라이드
    def on_created(self, event) -> None:
        if self._should_ignore(event):
            return
        self._handle("created", event.src_path)

    def on_modified(self, event) -> None:
        if self._should_ignore(event):
            return
        self._handle("modified", event.src_path)

    def on_deleted(self, event) -> None:
        if self._should_ignore(event):
            return
        self._handle("deleted", event.src_path)


class FileWatcher:
    """
    실제로 사용하게 될 메인 인터페이스 클래스
    여러 폴더를 동시에 감시하고, 이벤트를 큐에 쌓거나 콜백함수 실행.
    
    Watch multiple directories for create/modify/delete events.

    Usage patterns:
    1) Callback-driven:
        def cb(ev): print(ev)
        fw = FileWatcher(["/tmp/a", "/tmp/b"], callback=cb)
        fw.start()
        ...
        fw.stop()

    2) Polling-driven:
        fw = FileWatcher(["/tmp/a", "/tmp/b"])
        fw.start()
        ev = fw.get_event(timeout=1.0)
        fw.stop()
    """

    def __init__(
        self,
        paths: Iterable[str],
        *,
        callback: Optional[EventCallback] = None,
        recursive: bool = True,
        debounce_seconds: float = 0.15,
        ignore_directories: bool = True,
        queue_maxsize: int = 0,
    ) -> None:
        self._paths: List[str] = [_norm_path(p) for p in paths]
        self._callback = callback
        self._config = WatcherConfig(
            recursive=recursive,
            debounce_seconds=debounce_seconds,
            ignore_directories=ignore_directories,
        )
        
        # thread-safe한 큐를 사용하여 수집된 이벤트를 안전하게 보관
        self._events: "queue.Queue[EventDict]" = queue.Queue(maxsize=queue_maxsize)
        self._observer = Observer()
        self._handler = _WatchdogHandler(self._emit, self._config)

        self._running = False
        self._lock = threading.Lock()

        self._validate_paths()

    def _validate_paths(self) -> None:
        """감시하려는 경로가 실제로 존재하는 폴더인지 확인."""
        if not self._paths:
            raise ValueError("paths must not be empty.")
        missing = [p for p in self._paths if not os.path.isdir(p)]
        if missing:
            raise FileNotFoundError(f"Directory not found: {missing}")

    def _emit(self, event: EventDict) -> None:
        """이벤트 발생 시 큐에 넣고, 설정된 콜백 함수가 있다면 실행."""
        try:
            self._events.put_nowait(event)
        except queue.Full:
            pass # 큐가 꽉 찼을 경우 최신 이벤트를 버려 시스템 부하를 방지

        if self._callback is not None:
            try:
                self._callback(event)
            except Exception:
                pass # 콜백 오류가 전체 감시 시스템을 멈추지 않도록 예외 처리

    @property
    def paths(self) -> List[str]:
        return list(self._paths)

    def start(self) -> None:
        """감시 시작. 별도의 스레드에서 Observer가 돌아감."""
        with self._lock:
            if self._running:
                return

            for p in self._paths:
                self._observer.schedule(
                    self._handler,
                    p,
                    recursive=self._config.recursive,
                )
            self._observer.start()
            self._running = True

    def stop(self) -> None:
        """감시 중단하고 자원 해제"""
        with self._lock:
            if not self._running:
                return
            self._observer.stop()
            self._observer.join(timeout=5.0)
            self._running = False

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def get_event(self, timeout: Optional[float] = None) -> Optional[EventDict]:
        """
        분석 모듈에서 큐에 쌓인 이벤트를 하나씩 꺼내갈 때 사용.
        Poll one event from internal queue.
        Returns None on timeout.
        """
        try:
            return self._events.get(timeout=timeout)
        except queue.Empty:
            return None

    def drain_events(self, limit: Optional[int] = None) -> List[EventDict]:
        """
        Drain queued events quickly (non-blocking).
        """
        out: List[EventDict] = []
        while True:
            if limit is not None and len(out) >= limit:
                break
            try:
                out.append(self._events.get_nowait())
            except queue.Empty:
                break
        return out
    
    # Python의 'with'문을 사용하여 안전하게 시작/종료할 수 있게 함 (context manager)
    def __enter__(self) -> "FileWatcher":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


def _demo() -> None:
    """명령행에서 직접 실행했을 때 작동하는 데모 코드."""
    import argparse

    parser = argparse.ArgumentParser(description="FileWatcher demo")
    parser.add_argument("paths", nargs="+", help="Directories to watch")
    parser.add_argument("--no-recursive", action="store_true", help="Do not watch recursively")
    parser.add_argument("--include-dirs", action="store_true", help="Include directory events")
    args = parser.parse_args()
    
    # 이벤트 발생 시 실행될 간단한 출력 함수
    def cb(ev: EventDict) -> None:
        print(ev)

    fw = FileWatcher(
        args.paths,
        callback=cb,
        recursive=not args.no_recursive,
        ignore_directories=not args.include_dirs,
    )

    print("Watching... (Ctrl+C to stop)")
    fw.start()
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        fw.stop()
        print("Stopped.")


if __name__ == "__main__":
    _demo()