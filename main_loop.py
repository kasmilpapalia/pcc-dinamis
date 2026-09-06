"""main_loop.py — Orkestrasi penuh: collect -> filter -> SAW -> ALQI -> decide -> push.

Jadwal: tiap POLL_INTERVAL detik (default 20s, sesuai diagram feedback loop).
Log: controller/log.csv + tabel SQLite controller/pcc_log.db (Logging & Database).
"""
from __future__ import annotations
import csv
import os
import sqlite3
import time
from datetime import datetime

from collector import collect_all
from filter import EWMAFilter, StabilityGate
from saw_alqi import compute_saw
from decider import decide
from mikrotik_api import MikroTikPCCPusher

BASE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE, "log.csv")
DB_PATH = os.path.join(BASE, "pcc_log.db")
POLL_INTERVAL = 20

CRITERIA = ["bandwidth_mbps", "latency_ms", "jitter_ms", "loss_pct"]


def _init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS pcc_log(
        ts TEXT, link TEXT, bw REAL, lat REAL, jit REAL, loss REAL,
        alqi REAL, action TEXT, ratio TEXT)""")
    con.commit()
    return con


def one_cycle(ewma: EWMAFilter, gate: StabilityGate, pusher: MikroTikPCCPusher, con) -> dict:
    raw = collect_all()  # {link: LinkMetrics}
    smooth_matrix = {}
    for link, m in raw.items():
        d = {"bandwidth_mbps": m.bandwidth_mbps, "latency_ms": m.latency_ms,
             "jitter_ms": m.jitter_ms, "loss_pct": m.loss_pct}
        smooth_matrix[link] = ewma.update(link, d)

    saw = compute_saw(smooth_matrix)  # {link: {score_V, alqi, r}}
    alqis = {link: v["alqi"] for link, v in saw.items()}
    decision = decide(alqis, gate)
    pusher.push_ratio(decision)

    # --- Logging (umpan balik / feedback loop) ---
    ts = datetime.now().isoformat(timespec="seconds")
    ratio_s = f"{decision.get('ratio')}"
    new_csv = not os.path.exists(CSV_PATH)
    with open(CSV_PATH, "a", newline="") as f:
        w = csv.writer(f)
        if new_csv:
            w.writerow(["ts", "link", "bw", "lat", "jit", "loss", "alqi", "action", "ratio"])
        for link, m in raw.items():
            w.writerow([ts, link, m.bandwidth_mbps, m.latency_ms, m.jitter_ms,
                        m.loss_pct, alqis[link], decision["action"], ratio_s])
    for link, m in raw.items():
        con.execute("INSERT INTO pcc_log VALUES(?,?,?,?,?,?,?,?,?)",
                    (ts, link, m.bandwidth_mbps, m.latency_ms, m.jitter_ms,
                     m.loss_pct, alqis[link], decision["action"], ratio_s))
    con.commit()
    print(f"[{ts}] ALQI={alqis} -> {decision['action']} {ratio_s}")
    return decision


def main(cycles: int = 0):
    """cycles=0 -> loop selamanya. Isi >0 untuk testing."""
    ewma, gate = EWMAFilter(alpha=0.4), StabilityGate(hysteresis=10.0, hold_cycles=3)
    pusher = MikroTikPCCPusher().connect()
    con = _init_db()
    i = 0
    try:
        while True:
            one_cycle(ewma, gate, pusher, con)
            i += 1
            if cycles and i >= cycles:
                break
            time.sleep(POLL_INTERVAL)
    finally:
        con.close()


if __name__ == "__main__":
    import sys
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    main(cycles=n)