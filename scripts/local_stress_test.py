#!/usr/bin/env python3
"""Safe in-process stress tests. No remote target can be supplied."""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from url_guard_bot.rate_limiter import UserRateLimiter  # noqa: E402


async def run(
    users: int, requests_per_user: int, concurrency: int
) -> dict[str, object]:
    limiter = UserRateLimiter(limit=5, window_seconds=60, max_keys=max(users, 1))
    semaphore = asyncio.Semaphore(concurrency)
    latencies_ms: list[float] = []
    allowed = 0
    blocked = 0

    async def one(user_id: int) -> None:
        nonlocal allowed, blocked
        async with semaphore:
            started = time.perf_counter()
            ok, _ = await limiter.check(user_id)
            latencies_ms.append((time.perf_counter() - started) * 1000)
            if ok:
                allowed += 1
            else:
                blocked += 1

    tracemalloc.start()
    started = time.perf_counter()
    await asyncio.gather(
        *(one(user) for user in range(users) for _ in range(requests_per_user))
    )
    elapsed = time.perf_counter() - started
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "mode": "safe_in_process_only",
        "users": users,
        "requests_per_user": requests_per_user,
        "total_checks": users * requests_per_user,
        "allowed": allowed,
        "blocked": blocked,
        "elapsed_seconds": round(elapsed, 4),
        "checks_per_second": round((users * requests_per_user) / elapsed, 2),
        "latency_ms_p50": round(statistics.median(latencies_ms), 4),
        "latency_ms_p95": round(
            sorted(latencies_ms)[int(len(latencies_ms) * 0.95) - 1], 4
        ),
        "memory_current_bytes": current,
        "memory_peak_bytes": peak,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=2_000)
    parser.add_argument("--requests-per-user", type=int, default=8)
    parser.add_argument("--concurrency", type=int, default=100)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.users <= 100_000:
        raise SystemExit("--users must be between 1 and 100000")
    if not 1 <= args.requests_per_user <= 100:
        raise SystemExit("--requests-per-user must be between 1 and 100")
    if not 1 <= args.concurrency <= 1_000:
        raise SystemExit("--concurrency must be between 1 and 1000")

    result = asyncio.run(run(args.users, args.requests_per_user, args.concurrency))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
