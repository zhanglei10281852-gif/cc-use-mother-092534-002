"""可注入的时钟，保证时间相关逻辑可测试。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FakeClock:
    """测试用时钟：时间只在调用 advance 后前进。"""

    def __init__(self, start: datetime | None = None) -> None:
        if start is None:
            start = datetime(2026, 9, 25, 0, 0, 0, tzinfo=timezone.utc)
        if start.tzinfo is None:
            raise ValueError("时间必须带时区")
        self._now = start.astimezone(timezone.utc)

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> datetime:
        from datetime import timedelta

        self._now = self._now + timedelta(seconds=seconds)
        return self._now

    def set(self, value: datetime) -> None:
        if value.tzinfo is None:
            raise ValueError("时间必须带时区")
        self._now = value.astimezone(timezone.utc)


def to_utc_iso(value: datetime) -> str:
    """统一存成 UTC ISO 8601，保证字典序与时间序一致。"""
    if value.tzinfo is None:
        raise ValueError("时间必须带时区")
    return value.astimezone(timezone.utc).isoformat()


def parse_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("存储的时间必须带时区")
    return parsed.astimezone(timezone.utc)
