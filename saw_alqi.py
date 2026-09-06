"""saw_alqi.py — Tahap 3 & 4: SAW (MCDM) + formulasi ALQI 0-100%.

Kriteria:
  benefit (makin besar baik): bandwidth_mbps
  cost (makin kecil baik)    : latency_ms, jitter_ms, loss_pct

Normalisasi:
  benefit: r_ij = x_ij / max(x_j)
  cost   : r_ij = min(x_j) / x_ij   (x_ij=0 dilindungi epsilon)

Skor: V_i = sum(w_j * r_ij),  sum(w)=1
ALQI_i = V_i * 100
"""
from __future__ import annotations

WEIGHTS = {  # jumlah harus 1.0 — kotak "Evaluasi & Penyesuaian Parameter"
    "bandwidth_mbps": 0.35,
    "latency_ms": 0.30,
    "jitter_ms": 0.15,
    "loss_pct": 0.20,
}
BENEFIT = {"bandwidth_mbps"}
COST = {"latency_ms", "jitter_ms", "loss_pct"}
_EPS = 1e-9


def normalize(matrix: dict[str, dict[str, float]]) -> dict[str, dict[str, float]]:
    """matrix = {link: {kriteria: nilai}}. Return R ternormalisasi 0..1."""
    crits = list(WEIGHTS.keys())
    out: dict[str, dict[str, float]] = {link: {} for link in matrix}
    for c in crits:
        vals = [matrix[link][c] for link in matrix]
        if c in BENEFIT:
            denom = max(vals) or _EPS
            for link in matrix:
                out[link][c] = matrix[link][c] / denom
        else:  # cost
            numer = min(vals)
            if numer == 0:  # loss 0% di semua link -> semua sempurna
                for link in matrix:
                    out[link][c] = 1.0 if matrix[link][c] == 0 else 0.0
            else:
                for link in matrix:
                    out[link][c] = numer / (matrix[link][c] or _EPS)
    return out


def compute_saw(matrix: dict[str, dict[str, float]]) -> dict:
    """Return {link: {'score_V':, 'alqi':, 'r': {...}}}. ALQI 0-100."""
    r = normalize(matrix)
    result = {}
    for link in matrix:
        v = sum(WEIGHTS[c] * r[link][c] for c in WEIGHTS)
        result[link] = {"score_V": round(v, 4), "alqi": round(v * 100, 2), "r": r[link]}
    return result


if __name__ == "__main__":
    # Contoh matematik dari dokumentasi: FO vs VSAT
    demo = {
        "ISP1-FO": {"bandwidth_mbps": 50, "latency_ms": 20, "jitter_ms": 5, "loss_pct": 0.5},
        "ISP2-VSAT": {"bandwidth_mbps": 10, "latency_ms": 600, "jitter_ms": 30, "loss_pct": 2.0},
    }
    for link, res in compute_saw(demo).items():
        print(link, res)
    # Harapan: ISP1-FO V=1.0 ALQI=100, ISP2-VSAT V~0.155 ALQI~15.5