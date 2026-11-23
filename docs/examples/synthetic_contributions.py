"""Create synthetic RESI homes for the Learning Contributions demo.

Every value is generated from a seeded random source: no real user data, no
real artifacts. Each home gets execution episodes for a few built-in tools,
claim feedback and calibration points, which ``resi contribute export`` then
turns into a contribution file.

    python docs/examples/synthetic_contributions.py --out /tmp/resi-demo --users 5 --seed 7
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

from resi.adapters.outbound.sqlite_store import SqliteStore
from resi.domain.enums import Confidence
from resi.domain.models import CalibrationPoint, Episode

# (tool id, artifact kind, true success rate, typical latency ms)
PROFILE = (
    ("rea.list_procedures", "macho", 0.95, 900.0),
    ("cli.rizin", "macho", 0.85, 4_000.0),
    ("rea.inspect_macho", "macho", 0.99, 300.0),
    ("rea.list_procedures", "elf", 0.90, 1_200.0),
    ("rea.batch_decompile", "elf", 0.60, 45_000.0),
)
CONFIDENCE_TRUTH = {Confidence.LOW: 0.4, Confidence.MEDIUM: 0.7, Confidence.HIGH: 0.8}


def seed_home(home: Path, rng: random.Random) -> None:
    home.mkdir(parents=True, exist_ok=True)
    store = SqliteStore(home / "resi.db")
    try:
        n = 0
        for tool, kind, rate, latency in PROFILE:
            for _ in range(rng.randint(8, 20)):
                n += 1
                ok = rng.random() < rate
                store.add_episode(Episode(
                    f"epi-{n:05d}", tool, kind, ok, rng.expovariate(1 / latency),
                    f"2026-01-01T{n // 3600:02d}:{n // 60 % 60:02d}:{n % 60:02d}+00:00",
                    "" if ok else "synthetic failure", tool_version="unspecified"))
            for _ in range(rng.randint(1, 4)):
                n += 1
                good = rng.random() < 0.8
                store.add_episode(Episode(
                    f"epi-{n:05d}", tool, kind, good, 0.0, "2026-01-02T00:00:00+00:00",
                    validated_claims=int(good), downgraded_claims=int(not good),
                    kind="claim_feedback"))
        for i in range(rng.randint(5, 15)):
            level = rng.choice(list(Confidence))
            store.add_calibration(CalibrationPoint(f"clm-{i}", level,
                                                   rng.random() < CONFIDENCE_TRUTH[level],
                                                   "2026-01-02T00:00:00+00:00"))
    finally:
        store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--users", type=int, default=5)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    for user in range(1, args.users + 1):
        seed_home(args.out / f"user{user}", rng)
        print(f"seeded {args.out / f'user{user}'}")


if __name__ == "__main__":
    main()
