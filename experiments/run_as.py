"""AS-level experiments (NOVELTY_PLAN.md section 3). All values are SIMULATED.

    python3 experiments/run_as.py <grid> [seeds=30] [out_root=results]

grid:
  T1  adoption curve: adopt_frac x policy x attacker placement x malicious fraction, attacker "always"
  T2  attacker strategies: adopt_frac x attacker strategy x policy, top placement, 5 % malicious
  smoke  a few runs for CI (needs the CAIDA snapshot)
Downloads the CAIDA AS-relationships snapshot (serial-2, 2026-11-01) into data/ if missing. Use is subject to
the CAIDA Acceptable Use Agreement: https://www.caida.org/about/legal/aua/
"""
import csv
import os
import platform
import subprocess
import sys
import time
import urllib.request
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dataclasses import asdict  # noqa: E402

from trustpath.assim import DATA, ASConfig, run  # noqa: E402

URL = "https://publicdata.caida.org/datasets/as-relationships/serial-2/" + DATA.name


def grid(name, seeds):
    for s in seeds:
        if name == "T1":
            for f in (0.0, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0):
                for policy in ("local", "shared", "agreement"):
                    for place in ("random", "top"):
                        for m in (0.02, 0.05, 0.1):
                            yield ASConfig(seed=s, adopt_frac=f, policy=policy, mal_placement=place, mal_frac=m)
        elif name == "T2":
            for f in (0.1, 0.25, 0.5, 0.75):
                for att in ("always", "on_off", "adopter_aware", "conflicting"):
                    for policy in ("local", "shared", "agreement"):
                        yield ASConfig(seed=s, adopt_frac=f, attacker=att, policy=policy, mal_placement="top")
        elif name == "smoke":
            yield ASConfig(seed=s, adopt_frac=0.5, epochs=6, warmup=2, flows_per_epoch=100)
        else:
            raise SystemExit(f"unknown grid {name}")


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "smoke"
    seeds = range(1, 1 + int(sys.argv[2] if len(sys.argv) > 2 else 30))
    if not DATA.exists():
        DATA.parent.mkdir(exist_ok=True)
        urllib.request.urlretrieve(URL, DATA)
    # Fixed directory per grid and seed count: rows are appended as runs finish, and a rerun after a crash
    # skips configurations already in raw.csv (resume).
    out = Path(sys.argv[3] if len(sys.argv) > 3 else "results") / f"as-{name}-{len(seeds)}seeds"
    out.mkdir(parents=True, exist_ok=True)
    raw = out / "raw.csv"
    fields = list(asdict(ASConfig()))
    done = set()
    if raw.exists():
        done = {tuple(r[k] for k in fields) for r in csv.DictReader(open(raw, newline=""))}
    items = [c for c in grid(name, seeds) if tuple(str(v) for v in asdict(c).values()) not in done]
    # agreement runs are ~20x slower; start them first so the pool does not idle at the end
    items.sort(key=lambda c: c.policy != "agreement")
    print(f"{len(done)} runs already done, {len(items)} to go", flush=True)
    t0 = time.time()
    # each worker caches the full CAIDA graph (~250 MB); 6 workers keep WSL memory (and the host pagefile) small
    with Pool(max(1, min((os.cpu_count() or 2) - 1, 6))) as pool, open(raw, "a", newline="") as fh:
        w = None
        for k, row in enumerate(pool.imap_unordered(run, items, chunksize=1), 1):
            if w is None:
                w = csv.DictWriter(fh, fieldnames=list(row))
                if not done:
                    w.writeheader()
            w.writerow(row)
            fh.flush()
            if k % 100 == 0:
                print(f"{k}/{len(items)} {time.time() - t0:.0f} s", flush=True)
    rows = list(csv.DictReader(open(raw, newline="")))
    git = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    import networkx
    import numpy

    (out / "environment.txt").write_text(
        f"date_utc: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\ngrid: {name}\n"
        f"runs: {len(rows)} ({len(seeds)} seeds), wall time of last session {time.time() - t0:.0f} s\ngit: {git}\n"
        f"topology: CAIDA AS relationships serial-2 {DATA.name}\n"
        f"python: {platform.python_version()} ({platform.platform()})\n"
        f"networkx: {networkx.__version__}, numpy: {numpy.__version__}\n"
        "all metrics are simulated\n"
    )
    subprocess.run([sys.executable, str(Path(__file__).parent / "analyze_as.py"), str(out / "raw.csv"), str(out)], check=False)
    print(f"results in {out}")


if __name__ == "__main__":
    main()
