"""decider.py — Tahap 5: Keputusan PCC Dinamis (pilih jalur / atur rasio).

Aturan (sesuai blok 5 diagram):
1. Failover: ALQI < DOWN_THRESHOLD -> link dianggap mati (porsi 0).
2. HOLD: jika gate.hysteresis belum terlampaui -> jangan ubah MikroTik.
3. Weighted: rasio = ALQI1 : ALQI2, dipetakan ke denominator PCC (maks 10).

PCC MikroTik: classifier both-addresses-and-ports:denominator/remainder.
Contoh rasio 6:1 -> denominator=7, ISP1 dapat remainder 0-5, ISP2 remainder 6.
"""
from __future__ import annotations

DOWN_THRESHOLD = 20.0  # ALQI di bawah ini = link DOWN
MAX_DENOMINATOR = 10   # batasi agar rule mangle tidak terlalu banyak
LINKS_ORDER = ["ISP1-FO", "ISP2-VSAT"]


def ratio_to_pcc(alqi1: float, alqi2: float) -> tuple[int, int, int]:
    """Konversi ALQI -> (porsi_ISP1, porsi_ISP2, denominator).

    Failover ditangani dulu: (1,0,1) atau (0,1,1).
    """
    if alqi1 < DOWN_THRESHOLD and alqi2 < DOWN_THRESHOLD:
        return (1, 1, 2)  # dua-duanya jelek -> bagi rata sambil menunggu pulih
    if alqi1 < DOWN_THRESHOLD:
        return (0, 1, 1)
    if alqi2 < DOWN_THRESHOLD:
        return (1, 0, 1)
    total = min(MAX_DENOMINATOR, max(2, round((alqi1 + alqi2) / 15)))
    # total adaptif: selisih kecil -> denom kecil (misal 2 = 1:1), dominan -> denom besar
    p1 = max(1, round(total * alqi1 / (alqi1 + alqi2)))
    p1 = min(p1, total - 1)
    return (p1, total - p1, total)


def decide(alqis: dict[str, float], gate=None) -> dict:
    """alqis = {nama_link: ALQI}. Return dict aksi untuk mikrotik_api."""
    a1 = alqis.get(LINKS_ORDER[0], 0.0)
    a2 = alqis.get(LINKS_ORDER[1], 0.0)
    p1, p2, denom = ratio_to_pcc(a1, a2)

    # StabilityGate dicek per link terbaik agar flapping tertahan
    best = LINKS_ORDER[0] if a1 >= a2 else LINKS_ORDER[1]
    best_alqi = max(a1, a2)
    if gate is not None and not gate.should_update(best, best_alqi):
        return {"action": "HOLD", "reason": "selisih < hysteresis / hold_cycles",
                "alqi": alqis, "ratio": (p1, p2), "denominator": denom}

    if (p1, p2) in [(1, 0), (0, 1)]:
        mode = "FAILOVER"
    elif (p1, p2) == (1, 1):
        mode = "BALANCED_1:1"
    else:
        mode = "WEIGHTED"
    return {"action": "UPDATE", "mode": mode, "alqi": alqis,
            "ratio": (p1, p2), "denominator": denom,
            # remainder 0..p1-1 -> ISP1, p1..denom-1 -> ISP2
            "rem_ISP1": list(range(p1)), "rem_ISP2": list(range(p1, denom))}


if __name__ == "__main__":
    print(decide({"ISP1-FO": 100, "ISP2-VSAT": 15.5}))   # harapFAILOVER 1:0
    print(decide({"ISP1-FO": 85, "ISP2-VSAT": 70}))      # harap WEIGHTED/BALANCED