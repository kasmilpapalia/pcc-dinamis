"""filter.py — Tahap 2: Filter Stabilitas (EWMA + Hysteresis/Time-Threshold).

Tujuan: metrik mentah berisik -> dihaluskan agar PCC tidak flapping
(bolak-balik pindah jalur setiap detik).

Matematika:
  S_t = alpha * X_t + (1 - alpha) * S_{t-1},  alpha 0..1 (0.3-0.5 umum)
  Lolos update HANYA JIKA |baru - lama| > Hysteresis dan bertahan N siklus.
"""
from __future__ import annotations
from dataclasses import dataclass, field


class EWMAFilter:
    def __init__(self, alpha: float = 0.4):
        assert 0 < alpha <= 1.0
        self.alpha = alpha
        self.state: dict[str, dict[str, float]] = {}  # {link: {metric: S}}

    def update(self, link: str, raw: dict[str, float]) -> dict[str, float]:
        """Haluskan satu sampel mentah. Return nilai S_t per metrik."""
        prev = self.state.get(link, {})
        smooth: dict[str, float] = {}
        for k, x in raw.items():
            s_prev = prev.get(k, x)  # sampel pertama: S = X
            smooth[k] = round(self.alpha * x + (1 - self.alpha) * s_prev, 3)
        self.state[link] = smooth
        return smooth


@dataclass
class StabilityGate:
    """Hysteresis + time-threshold untuk skor ALQI.

    should_update() -> True hanya jika selisih ALQI vs terakhir-diterapkan
    melebihi H dan terjadi N kali berturut-turut.
    """
    hysteresis: float = 10.0   # poin ALQI, misal 10
    hold_cycles: int = 3       # misal 3 x polling 20 dtk = 60 dtk
    _last_applied: dict[str, float] = field(default_factory=dict)
    _pending_count: dict[str, int] = field(default_factory=dict)

    def should_update(self, link: str, new_alqi: float) -> bool:
        old = self._last_applied.get(link)
        if old is None:
            self._last_applied[link] = new_alqi
            return True  # siklus pertama selalu lolos
        if abs(new_alqi - old) < self.hysteresis:
            self._pending_count[link] = 0
            return False  # perubahan kecil -> HOLD
        cnt = self._pending_count.get(link, 0) + 1
        self._pending_count[link] = cnt
        if cnt >= self.hold_cycles:
            self._pending_count[link] = 0
            self._last_applied[link] = new_alqi
            return True
        return False

    def force_sync(self, link: str, alqi: float):
        self._last_applied[link] = alqi
        self._pending_count[link] = 0