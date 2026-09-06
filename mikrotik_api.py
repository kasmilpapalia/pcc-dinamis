"""mikrotik_api.py — Tahap 6: Kirim Perintah ke MikroTik (API - Change Rule PCC).

Prasyarat di RouterOS (sekali saja, via terminal):
  /ip firewall mangle add chain=prerouting in-interface=LAN action=mark-connection \\
    new-connection-mark=ISP1_conn per-connection-classifier=both-addresses-and-ports:2/0 comment="PCC-ISP1" passthrough=yes
  ... (rule ISP2 dengan 2/1), lalu mark-routing -> table to_ISP1/to_ISP2 + NAT.

Class ini me-rewrite per-connection-classifier sesuai denominator dinamis.
Butuh: pip install librouteros. DRY_RUN=True = hanya cetak perintah.
"""
from __future__ import annotations

HOST = "200.100.10.1"   # Port 4 MGMT - PCC Controller
USERNAME = "admin"
PASSWORD = "admin123"
DRY_RUN = True          # <-- set False untuk eksekusi nyata


class MikroTikPCCPusher:
    def __init__(self, host=HOST, username=USERNAME, password=PASSWORD, dry_run=DRY_RUN):
        self.host, self.username, self.password = host, username, password
        self.dry_run = dry_run
        self.api = None

    def connect(self):
        if self.dry_run:
            return self
        from librouteros import connect as ros_connect
        self.api = ros_connect(username=self.username, password=self.password, host=self.host)
        return self

    def _run(self, path: str, action: str, params: dict):
        if self.dry_run:
            print(f"[DRY-RUN] {path} {action} {params}")
            return None
        resource = self.api.path(*path.split("/"))
        if action == "remove":
            # librouteros: Path.remove(*ids) posisi, bukan kwargs
            _id = params.get(".id") or params.get("id")
            return resource.remove(_id)
        return getattr(resource, action)(**params)

    def push_ratio(self, decision: dict):
        """Terapkan decision dari decider.py ke mangle PCC."""
        if decision.get("action") == "HOLD":
            print("[INFO] HOLD — tidak ada perubahan PCC.")
            return False
        denom = decision["denominator"]
        p1, p2 = decision["ratio"]
        print(f"[INFO] PUSH PCC {p1}:{p2} (denom={denom}) mode={decision.get('mode')}")

        # Strategi sederhana: hapus rule PCC lama lalu buat ulang sebanyak denom.
        # Rule ke-i: remainder=i, connection-mark ISP1 jika i < p1 else ISP2.
        if not self.dry_run:
            all_rules = list(self.api.path("ip", "firewall", "mangle").select(".id", "comment"))
            old = [r for r in all_rules if str(r.get("comment", "")).startswith("PCC-")]
            for r in old:
                self.api.path("ip", "firewall", "mangle").remove(r[".id"])

        remainder = 0
        for _ in range(p1):
            self._mangle_rule("ISP1", denom, remainder); remainder += 1
        for _ in range(p2):
            self._mangle_rule("ISP2", denom, remainder); remainder += 1
        return True

    def _mangle_rule(self, isp: str, denom: int, remainder: int):
        tag = "ISP1" if isp == "ISP1" else "ISP2"
        self._run("ip/firewall/mangle", "add", {
            "chain": "prerouting",
            "in-interface": "LAN",
            "action": "mark-connection",
            "new-connection-mark": f"{tag}_conn",
            "per-connection-classifier": f"both-addresses-and-ports:{denom}/{remainder}",
            "comment": f"PCC-{tag}-{denom}/{remainder}",
            "passthrough": "yes",
        })


if __name__ == "__main__":
    pusher = MikroTikPCCPusher(dry_run=True).connect()
    pusher.push_ratio({"action": "UPDATE", "mode": "WEIGHTED",
                       "ratio": (6, 1), "denominator": 7})