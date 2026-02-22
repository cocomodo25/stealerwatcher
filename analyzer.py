# analyzer.py
"""
Heuristic event analyzer for a security detector.

- Input: collector.py에서 생성된 이벤트 딕셔너리:
    {'time': ..., 'path': ..., 'action': ...}

- Output: 기존 데이터에 'score'와 'level'이 추가된 확장 딕셔너리:
    {<original fields>, 'score': int, 'level': 'Critical'|'Warning'|'Info'}

Designed to be independent and easy to integrate with notification modules (e.g., Matrix).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any, Literal

EventDict = Dict[str, str]
Level = Literal["Critical", "Warning", "Info"]


@dataclass(frozen=True)
class AnalyzerConfig:
    """
    분석기의 채점 기준을 설정하는 데이터 클래스.
    수치들을 조정하여 탐지기 민감도 조절 가능.
    """
    # 특정 확장자(민감 정보)에 대한 가산점
    sensitive_ext_score: int = 50
    sensitive_exts: Tuple[str, ...] = (".env", ".key", ".json", ".db")

    # 특정 폴더 경로(중요 길목)에 대한 가산점
    sensitive_path_score: int = 40
    # Use forward slashes in patterns; we normalize paths accordingly.
    sensitive_path_patterns: Tuple[str, ...] = ("venv/bin/", "/.ssh/")

    # 파일 행위별 기본 점수 (삭제는 흔적 인멸 가능성이 있어 가중치 적용)
    score_created: int = 10
    score_modified: int = 20
    score_deleted: int = 35

    # 등급 결정 임계치 (Thresholds)
    warning_threshold: int = 40
    critical_threshold: int = 70


class EventAnalyzer:
    """
    파일 이벤트를 분석하여 위헙 점수와 등급(Critical/Warning/Info)를 할당함.

    Example:
        analyzer = EventAnalyzer()
        out = analyzer.analyze({'time':'...', 'path':'/home/user/.ssh/id_rsa', 'action':'modified'})
        # -> {'time':..., 'path':..., 'action':..., 'score':..., 'level':...}
    """

    def __init__(self, config: Optional[AnalyzerConfig] = None) -> None:
        # 설정값이 없으면 기본 설정 사용
        self._cfg = config or AnalyzerConfig()

    @staticmethod
    def _norm_path_for_match(path: str) -> str:
        """
        경로 비교를 위해 OS에 상관없이 동일한 포맷(절대경로, 슬래시 사용)으로 정규화.
        """
        p = os.path.abspath(os.path.expanduser(path))
        p = os.path.normpath(p)
        return p.replace("\\", "/")

    def _score_extension(self, path: str) -> int:
        """파일 확장자가 감시 대상(비밀키, 환경변수 등)인지 확인하여 점수를 부여함."""
        # path.endswitch는 튜플을 받아서 하나라도 일치하면 True를 반환함.
        if path.lower().endswith(self._cfg.sensitive_exts):
            return self._cfg.sensitive_ext_score
        return 0

    def _score_sensitive_path(self, norm_path: str) -> int:
        """파일이 위치한 경로가 보안상 중요한 위치(SSH 설정 등)인지 확인"""
        # Match patterns against normalized forward-slash path
        for pat in self._cfg.sensitive_path_patterns:
            if pat in norm_path:
                return self._cfg.sensitive_path_score
        return 0

    def _score_action(self, action: str) -> int:
        """파일에 가해진 행위(생성/수정/삭제)에 따라 점수를 부여함."""
        a = (action or "").strip().lower()
        if a == "deleted":
            return self._cfg.score_deleted
        if a == "modified":
            return self._cfg.score_modified
        if a == "created":
            return self._cfg.score_created
        # Unknown action -> low baseline (but not zero, so it still shows up)
        return 5 # 알 수 없는 행위는 기본 점수 5점

    def _level(self, score: int) -> Level:
        """합산된 최종 점수를 바탕으로 위협 등급을 결정함."""
        if score > self._cfg.critical_threshold:
            return "Critical"
        if score > self._cfg.warning_threshold:
            return "Warning"
        return "Info"

    def analyze(self, event: EventDict) -> Dict[str, Any]:
        """
        이벤트를 종합 분석하여 결과 딕셔너리 반환.
        기존 데이터는 유지하고 점수와 등급만 추가.
        Return enriched event dict with score and level.

        Required keys (best effort):
            - 'path'
            - 'action'
        Other keys are passed through unchanged.
        """
        path = event.get("path", "")
        action = event.get("action", "")

        norm_path = self._norm_path_for_match(path)
        # 각 항목별 점수 합산(휴리스틱 채점)
        score = 0
        score += self._score_action(action)
        score += self._score_extension(norm_path)  # extension from normalized path is fine
        score += self._score_sensitive_path(norm_path)

        # 결과 딕셔너리 구성
        out: Dict[str, Any] = dict(event)  # keep original fields
        out["score"] = int(score)
        out["level"] = self._level(score)
        return out


def _demo() -> None:
    """분석기 모듈이 단독으로 잘 작동하는지 확인하기 위한 테스트 코드"""
    analyzer = EventAnalyzer()
    
    # 가상의 테스트 데이터 (샘플)
    samples = [
        {"time": "2026-02-21T00:00:00Z", "path": "~/.ssh/id_rsa", "action": "modified"},
        {"time": "2026-02-21T00:00:01Z", "path": "/srv/app/.env", "action": "created"},
        {"time": "2026-02-21T00:00:02Z", "path": "/home/user/project/venv/bin/activate", "action": "deleted"},
        {"time": "2026-02-21T00:00:03Z", "path": "/tmp/notes.txt", "action": "modified"},
    ]
    for s in samples:
        print(analyzer.analyze(s))


if __name__ == "__main__":
    _demo()