import asyncio
import time
from typing import Optional

from src.models import State
from src.utils import _dbg


class CFRateLimiter:
    BUDGET = 550
    WINDOW = 600

    def __init__(self):
        self.count = 0
        self.window_start = 0.0
        self.blocked_until = 0.0
        self._lock = asyncio.Lock()

    async def _wait_blocked(self, st: Optional[State]):
        while time.monotonic() < self.blocked_until:
            if st and st.interrupted:
                return
            left = int(self.blocked_until - time.monotonic())
            if st:
                st.phase_label = f"CF rate limit — resuming in {left}s"
            await asyncio.sleep(1)

    async def _wait_budget(self, wait_until: float, st: Optional[State]):
        while time.monotonic() < wait_until:
            if st and st.interrupted:
                return
            left = int(wait_until - time.monotonic())
            if st:
                st.phase_label = f"Rate limit ({self.count} reqs) — next window in {left}s"
            await asyncio.sleep(1)

    async def acquire(self, st: Optional[State] = None):
        if self.blocked_until > 0 and time.monotonic() < self.blocked_until:
            _dbg(f"RATE: waiting {self.blocked_until - time.monotonic():.0f}s for CF window reset")
            await self._wait_blocked(st)

        await self._lock.acquire()
        try:
            if self.blocked_until > 0 and time.monotonic() >= self.blocked_until:
                self.count = 0
                self.window_start = time.monotonic()
                self.blocked_until = 0.0

            now = time.monotonic()
            if self.window_start == 0.0:
                self.window_start = now

            if now - self.window_start >= self.WINDOW:
                self.count = 0
                self.window_start = now

            if self.count >= self.BUDGET:
                remaining = self.WINDOW - (now - self.window_start)
                if remaining > 0:
                    _dbg(f"RATE: budget exhausted ({self.count} reqs), waiting {remaining:.0f}s")
                    wait_until = self.window_start + self.WINDOW
                    saved_window = self.window_start
                    self._lock.release()
                    try:
                        await self._wait_budget(wait_until, st)
                    finally:
                        await self._lock.acquire()
                    if self.window_start == saved_window:
                        self.count = 0
                        self.window_start = time.monotonic()
                else:
                    self.count = 0
                    self.window_start = time.monotonic()

            self.count += 1
        finally:
            self._lock.release()

    def would_block(self) -> bool:
        now = time.monotonic()
        if self.blocked_until > 0 and now < self.blocked_until:
            return True
        if self.window_start > 0 and now - self.window_start < self.WINDOW:
            if self.count >= self.BUDGET:
                return True
        return False

    def report_429(self, retry_after: int):
        capped = min(max(retry_after, 30), 600)
        until = time.monotonic() + capped
        if until > self.blocked_until:
            self.blocked_until = until
            _dbg(f"RATE: 429 received (retry-after={retry_after}s, capped={capped}s)")
