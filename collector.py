"""collector.py — Tahap 1: Pengumpulan Metrik Link (WAN1-FO & WAN2-VSAT).

Sumber data sesuai diagram:
- Latency / Jitter / Packet Loss -> ping via gateway masing-masing WAN
- Bandwidth (throughput) -> SNMP ifHCInOctet/ifHCOutOctet, fallback speedtest/manual

Mode SIMULASI = True agar bisa dites tanpa hardware.
Ubah ke False + isi IP/GW/SNMP saat deploy nyata.
"""
from __future__ import annotations
import concurrent.futures
import os
import random
import subprocess
import platform
import re
import time
from dataclasses import dataclass, asdict

# --- Konfigurasi link (sesuaikan dengan topologi) ---
# iface = nama interface di MikroTik (wajib benar, dicek via /interface print).
LINKS = {
    "ISP1-FO":   {"src_ip": "192.168.1.2", "gateway": "192.168.1.1", "snmp_target": "192.168.1.1", "if_index": 1, "iface": "ether1-ISP-A"},
    "ISP2-VSAT": {"src_ip": "192.168.2.2", "gateway": "192.168.2.1", "snmp_target": "192.168.2.1", "if_index": 1, "iface": "ether2-ISP-B"},
}
# Mapping link -> nama interface di MikroTik (untuk override realtime).
IFACE_MAP = {name: cfg["iface"] for name, cfg in LINKS.items()}
# Kredensial router untuk ping per-interface (sama seperti mikrotik_api.py).
ROS_HOST = os.getenv("PCC_ROS_HOST", "200.100.10.1")
ROS_USER = os.getenv("PCC_ROS_USER", "admin")
ROS_PASS = os.getenv("PCC_ROS_PASS", "admin123")
ROS_PORT = int(os.getenv("PCC_ROS_PORT", "8728"))
PING_TARGET = os.getenv("PCC_PING_TARGET", "8.8.8.8")
# Default 4x ping agar 1 siklus ~4-5 detik (dulu 10x = ~20 detik, tidak realtime).
PING_COUNT = int(os.getenv("PCC_PING_COUNT", "4"))
# Default REAL (False) agar uji cabut kabel langsung kelihatan.
# Paksa simulasi hanya jika PCC_SIMULATE=1/true.
SIMULATE = os.getenv("PCC_SIMULATE", "0").lower() in ("1", "true", "yes", "on")


@dataclass
class LinkMetrics:
    name: str
    bandwidth_mbps: float  # benefit (makin besar makin baik)
    latency_ms: float      # cost
    jitter_ms: float       # cost
    loss_pct: float        # cost

    def to_dict(self):
        return asdict(self)


def _ping_stats(target: str, count: int = 4, src_ip: str | None = None) -> tuple[float, float, float]:
    """Return (avg_latency_ms, jitter_ms, loss_pct). Cross-platform Windows/Linux.

    PENTING realtime: ping di-bind ke src_ip masing-masing WAN agar
    ISP1 down / ISP2 up terbaca berbeda (dulu tanpa bind -> hasil kembar
    lewat default route). Windows: ping -S, Linux: ping -I.
    Timeout per-reply 1 detik agar link mati cepat terdeteksi (<count+2 detik).
    """
    is_win = platform.system().lower().startswith("win")
    if is_win:
        cmd = ["ping", "-n", str(count), "-w", "1000"]
        if src_ip:
            cmd += ["-S", src_ip]
        cmd += [target]
    else:
        cmd = ["ping", "-c", str(count), "-W", "1"]
        if src_ip:
            cmd += ["-I", src_ip]
        cmd += [target]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=count * 2 + 5).stdout
    except Exception:
        return 999.0, 99.0, 100.0

    # Jika src_ip tidak ada di PC ini, Windows error 'General failure' langsung
    # untuk SEMUA reply (bukan berarti link down!). Deteksi + fallback tanpa bind.
    low = (out or "").lower()
    has_reply = ("reply from" in low or "bytes=" in low)
    if src_ip and not has_reply:
        if ("general failure" in low or "cannot assign" in low or "bad option" in low
                or "is not valid" in low or "failure" in low):
            return _ping_stats(target, count, src_ip=None)

    # Ambil semua nilai time=XXms
    times = [float(x) for x in re.findall(r"time[=<]\s*([\d.]+)\s*ms", out)]
    # Packet loss: "Lost = X (Y% loss)" (win) atau "X% packet loss" (linux)
    loss = 0.0
    m = re.search(r"(\d+(?:\.\d+)?)\s*%\s*(?:loss|packet loss)", out)
    if m:
        loss = float(m.group(1))
    elif not times:
        loss = 100.0

    if not times:
        return 999.0, 99.0, loss
    avg_lat = sum(times) / len(times)
    if len(times) > 1:
        jitter = sum(abs(times[i] - times[i - 1]) for i in range(1, len(times))) / (len(times) - 1)
    else:
        jitter = 0.0
    return round(avg_lat, 2), round(jitter, 2), round(loss, 2)


def _bandwidth_snmp(snmp_target: str, if_index: int, interval: int = 1) -> float:
    """Baca throughput via SNMP. Butuh `pysnmp`. Return Mbps.

    Rumus: BW = (Octet_t2 - Octet_t1) * 8 / interval / 1e6
    Jika gagal / lib tidak ada -> raise agar caller bisa fallback.
    Kompatibel pysnmp lama (hlapi.getCmd) maupun baru v7 (v3arch.get_cmd/asyncio).
    interval default 1 detik agar realtime (dulu 3 detik x 2 link sekuensial).
    """
    OID_IN = f"1.3.6.1.2.1.31.1.1.1.6.{if_index}"   # ifHCInOctets
    OID_OUT = f"1.3.6.1.2.1.31.1.1.1.10.{if_index}"  # ifHCOutOctets

    def _read_legacy():
        from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
        it = getCmd(SnmpEngine(), CommunityData("public", mpModel=1),
                    UdpTransportTarget((snmp_target, 161), timeout=1, retries=0),
                    ContextData(), ObjectType(ObjectIdentity(OID_IN)),
                    ObjectType(ObjectIdentity(OID_OUT)))
        err, _, _, var_binds = next(it)
        if err:
            raise RuntimeError(str(err))
        return int(var_binds[0][1]), int(var_binds[1][1])

    def _read_v7():
        # pysnmp >= 6/7: API asyncio di pysnmp.hlapi.v3arch.asyncio
        import asyncio
        try:
            from pysnmp.hlapi.v3arch.asyncio import (SnmpEngine, CommunityData, UdpTransportTarget,
                                                     ContextData, ObjectType, ObjectIdentity, get_cmd)
        except ImportError:
            from pysnmp.hlapi.v3arch import get_cmd  # type: ignore
            from pysnmp.hlapi.v3arch import (SnmpEngine, CommunityData, UdpTransportTarget,  # type: ignore
                                             ContextData, ObjectType, ObjectIdentity)

        async def _go():
            eng = SnmpEngine()
            res = await get_cmd(eng,
                                CommunityData("public", mpModel=1),
                                await UdpTransportTarget.create((snmp_target, 161), timeout=1, retries=0),
                                ContextData(),
                                ObjectType(ObjectIdentity(OID_IN)),
                                ObjectType(ObjectIdentity(OID_OUT)))
            return res

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        if loop.is_running():
            # Dipanggil dari thread executor tanpa loop jalan -> buat loop baru
            new_loop = asyncio.new_event_loop()
            try:
                err, _, _, var_binds = new_loop.run_until_complete(_go())
            finally:
                new_loop.close()
        else:
            err, _, _, var_binds = loop.run_until_complete(_go())
        if err:
            raise RuntimeError(str(err))
        return int(var_binds[0][1]), int(var_binds[1][1])

    # Coba legacy dulu (cepat jika masih ada), lalu v7
    last_err: Exception | None = None
    for reader in (_read_legacy, _read_v7):
        try:
            in1, out1 = reader()
            break
        except Exception as e:  # noqa: BLE001 - lanjut ke reader berikut
            last_err = e
            continue
    else:
        raise RuntimeError(f"SNMP gagal: {last_err}")

    time.sleep(interval)
    # Baca kedua dengan reader yang sukses tadi (coba ulang keduanya)
    for reader in (_read_legacy, _read_v7):
        try:
            in2, out2 = reader()
            break
        except Exception as e:  # noqa: BLE001
            last_err = e
            continue
    else:
        raise RuntimeError(f"SNMP gagal: {last_err}")
    delta = max(in2 - in1, 0) + max(out2 - out1, 0)
    return round(delta * 8 / interval / 1e6, 2)


def _parse_ros_time(s: str | None) -> float | None:
    """Parse waktu RouterOS ('63ms29us', '1s5ms', '53ms393us') -> ms float."""
    if not s:
        return None
    s = str(s).strip().lower()
    total = 0.0
    found = False
    for val, unit in re.findall(r"([\d.]+)\s*(ms|us|µs|s)", s):
        found = True
        v = float(val)
        if unit == "s":
            total += v * 1000.0
        elif unit == "ms":
            total += v
        else:  # us
            total += v / 1000.0
    return round(total, 3) if found else None


def _stats_from_times(times: list[float], sent: int) -> tuple[float, float, float]:
    recv = len(times)
    loss = round((sent - recv) / sent * 100.0, 2) if sent else 100.0
    if not times:
        return 999.0, 99.0, loss
    avg = sum(times) / len(times)
    jit = (sum(abs(times[i] - times[i - 1]) for i in range(1, len(times))) / (len(times) - 1)) if len(times) > 1 else 0.0
    return round(avg, 2), round(jit, 2), loss


def _bw_from_monitor_row(row: dict) -> float:
    """Jumlahkan rx/tx (+fast-path) bits-per-second -> Mbps."""
    total_bps = 0.0
    for k in ("rx-bits-per-second", "fp-rx-bits-per-second",
              "tx-bits-per-second", "fp-tx-bits-per-second"):
        try:
            total_bps += float(row.get(k, 0) or 0)
        except (TypeError, ValueError):
            continue
    return round(total_bps / 1e6, 3)


def _router_link_stats(iface: str, target: str = "8.8.8.8", count: int = 4,
                       timeout: float = 10.0) -> tuple[float, float, float, float]:
    """Ping + bandwidth DARI router dalam 1 koneksi. Return (lat, jit, loss, bw_mbps).

    BW via /interface/monitor-traffic once (instan ~0.5 dtk, tanpa sleep).
    Raise jika router tak terjangkau.
    """
    from librouteros import connect as ros_connect
    api = ros_connect(username=ROS_USER, password=ROS_PASS, host=ROS_HOST,
                      port=ROS_PORT, timeout=timeout)
    try:
        rows = list(api("/ping", address=target, interface=iface, count=str(count)))
        try:
            mon = list(api("/interface/monitor-traffic", interface=iface, once=True))
            bw = _bw_from_monitor_row(mon[0]) if mon else 0.0
        except Exception:
            bw = 0.0
    finally:
        try:
            api.close()
        except Exception:
            pass
    times: list[float] = []
    sent = count
    for r in rows:
        try:
            sent = max(sent, int(r.get("sent", sent)))
        except Exception:
            pass
        t = _parse_ros_time(r.get("time"))
        if t is not None and r.get("received", 1) != 0 and "timeout" not in str(r.get("status", "")).lower() \
                and "rejected" not in str(r.get("status", "")).lower():
            times.append(t)
    lat, jit, loss = _stats_from_times(times, sent)
    return lat, jit, loss, bw


def _router_running_map(timeout: float = 5.0) -> dict[str, bool]:
    from librouteros import connect as ros_connect
    api = ros_connect(username=ROS_USER, password=ROS_PASS, host=ROS_HOST,
                      port=ROS_PORT, timeout=timeout)
    try:
        return {r.get("name"): bool(r.get("running"))
                for r in api.path("interface").select("name", "running")}
    finally:
        try:
            api.close()
        except Exception:
            pass


def collect_via_router(ping_count: int | None = None,
                       target: str | None = None) -> tuple[dict[str, LinkMetrics], dict[str, bool]]:
    """Kumpulkan metrik via ping router per-interface (paralel).

    Return (metrics, running_map). Raise jika router tak terjangkau.
    Ini metode UTAMA di topologi MGMT (kontroler 1 NIC) karena ping dari
    kontroler dengan -S selalu 'General failure'.
    """
    pc = ping_count if ping_count is not None else PING_COUNT
    tgt = target or PING_TARGET
    running = _router_running_map()
    out: dict[str, LinkMetrics] = {}

    def _one(link: str, cfg: dict) -> tuple[str, LinkMetrics]:
        try:
            lat, jit, loss, bw = _router_link_stats(cfg["iface"], tgt, pc)
        except Exception:
            # Interface down di router -> /ping melempar/trap -> vonis DOWN
            if running.get(cfg["iface"]) is False:
                return link, LinkMetrics(link, 0.0, 999.0, 99.0, 100.0)
            raise
        return link, LinkMetrics(link, bw, lat, jit, loss)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(LINKS)) as ex:
        futs = [ex.submit(_one, name, cfg) for name, cfg in LINKS.items()]
        for f in concurrent.futures.as_completed(futs):
            link, m = f.result()  # raise ke caller jika router mati total
            out[link] = m
    # Urutan tetap: ISP1 dulu, ISP2 terakhir (jangan ikut urutan finish thread).
    return apply_iface_override({k: out[k] for k in LINKS if k in out}, running), running


def _simulate(name: str) -> LinkMetrics:
    """Data dummy realistis: FO bagus, VSAT latency tinggi (600ms)."""
    if "FO" in name:
        return LinkMetrics(name, round(random.uniform(40, 60), 2),
                           round(random.uniform(15, 30), 2),
                           round(random.uniform(2, 8), 2),
                           round(random.uniform(0, 1), 2))
    return LinkMetrics(name, round(random.uniform(8, 12), 2),
                       round(random.uniform(550, 650), 2),
                       round(random.uniform(20, 40), 2),
                       round(random.uniform(1, 3), 2))


def collect_one(name: str, cfg: dict, ping_count: int | None = None,
                snmp_interval: int = 1, snmp_enabled: bool = True) -> LinkMetrics:
    if SIMULATE:
        return _simulate(name)
    pc = ping_count if ping_count is not None else PING_COUNT
    lat, jit, loss = _ping_stats(PING_TARGET, pc, src_ip=cfg.get("src_ip"))
    if snmp_enabled:
        try:
            bw = _bandwidth_snmp(cfg["snmp_target"], cfg["if_index"], interval=snmp_interval)
        except Exception:
            bw = 0.0  # SNMP gagal -> dianggap 0 agar SAW menghukum link ini
    else:
        bw = 0.0
    return LinkMetrics(name, bw, lat, jit, loss)


def collect_all(ping_count: int | None = None, snmp_interval: int = 1,
                parallel: bool = True, snmp_enabled: bool = True,
                use_router: bool = True) -> dict[str, LinkMetrics]:
    """Kumpulkan metrik semua WAN. Return {nama: LinkMetrics}.

    Urutan: router-/ping per-interface (akurat, paralel) -> fallback ping
    kontroler tanpa bind (kasus router API mati). parallel=True wajib
    agar dashboard 5 detik tidak antri.
    """
    if SIMULATE:
        return {name: _simulate(name) for name in LINKS}
    if use_router:
        try:
            metrics, _ = collect_via_router(ping_count)
            # SNMP opsional: di dashboard dimatikan (bw=0) agar <6 detik.
            # Failover cukup mengandalkan lat/loss + iface running.
            return metrics
        except Exception:
            pass  # jatuh ke ping kontroler di bawah
    if not parallel:
        return {name: collect_one(name, cfg, ping_count, snmp_interval, snmp_enabled)
                for name, cfg in LINKS.items()}
    out: dict[str, LinkMetrics] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(LINKS)) as ex:
        futs = {ex.submit(collect_one, name, cfg, ping_count, snmp_interval, snmp_enabled): name
                for name, cfg in LINKS.items()}
        for fut in concurrent.futures.as_completed(futs):
            out[futs[fut]] = fut.result()
    return {k: out[k] for k in LINKS if k in out}


def apply_iface_override(metrics: dict[str, LinkMetrics],
                         iface_running: dict[str, bool]) -> dict[str, LinkMetrics]:
    """Paksa metrik DOWN jika interface router dilaporkan down.

    iface_running = {nama_iface_mikrotik: running_bool}.
    Ini yang bikin flip ISP1-off langsung kelihatan walau ping masih smoothing.
    """
    out = dict(metrics)
    for link, iface in IFACE_MAP.items():
        if link in out and iface in iface_running and iface_running[iface] is False:
            m = out[link]
            out[link] = LinkMetrics(m.name, 0.0, 999.0, 99.0, 100.0)
    return out


if __name__ == "__main__":
    for m in collect_all().values():
        print(m.to_dict())