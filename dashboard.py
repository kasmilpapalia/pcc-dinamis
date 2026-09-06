"""dashboard.py — Dashboard monitoring PCC + ALQI (stdlib only, no pip baru).

Jalankan:  python dashboard.py [port, default 8080]
Buka:      http://localhost:8080

Sumber data:
- Live metrik link  : collector.collect_all() (SIMULATE=True = dummy FO vs VSAT)
- ALQI + rekomendasi: filter.EWMA + saw_alqi.compute_saw + decider.decide
- Real router       : librouteros (identity, resource, interface, mangle PCC + counter)
- Riwayat           : pcc_log.db (fallback log.csv) hasil main_loop.py

Dashboard ini READ-ONLY (tidak push ke MikroTik), jadi aman dibuka kapan saja.
Push tetap lewat main_loop.py (DRY_RUN=False).
"""
from __future__ import annotations
import csv
import json
import os
import sqlite3
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from collector import collect_all, apply_iface_override, IFACE_MAP, PING_COUNT
import collector
from filter import EWMAFilter, StabilityGate
from saw_alqi import compute_saw, WEIGHTS
from decider import decide
from mikrotik_api import HOST, USERNAME, PASSWORD, DRY_RUN

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "pcc_log.db")
CSV_PATH = os.path.join(BASE, "log.csv")

# Dashboard responsif: alpha besar + gate longgar agar flip <10 detik terlihat.
# Push nyata tetap stabil via main_loop.py (alpha=0.4, hysteresis=10, hold=3).
ewma = EWMAFilter(alpha=0.6)
gate = StabilityGate(hysteresis=6.0, hold_cycles=2)
state_lock = threading.Lock()

_ROUTER_CACHE = {"ts": 0.0, "data": None}
_ROUTER_TTL = 4.0  # detik — tiap refresh 5 detik dapat counter baru (rate hidup)


_IFACE_LAST: dict = {}  # {name: (ts, rx_byte, tx_byte)} untuk rate per-detik
_IFACE_ORDER = ["ether1-ISP-A", "ether2-ISP-B", "ether3", "ether4", "ether5",
                "sfp1", "LAN_IN", "lo"]


def _is_pcc_rule(m: dict) -> bool:
    c = str(m.get("comment", "") or "")
    pcc = str(m.get("per-connection-classifier", "") or "")
    cm = str(m.get("connection-mark", "") or "")
    rm = str(m.get("routing-mark", "") or "")
    if pcc.strip():
        return True
    up = (c + " " + cm + " " + rm).upper()
    return ("PCC" in up or "VIA-ETHER" in up or "VIA_ETHER" in up)


def poll_router(timeout: float = 2.5) -> dict:
    """Ambil state real router. Gagal -> online=False, dashboard tetap jalan."""
    global _ROUTER_CACHE
    now = time.time()
    cached = _ROUTER_CACHE.get("data")
    if cached is not None and (now - _ROUTER_CACHE.get("ts", 0)) < _ROUTER_TTL:
        return cached
    try:
        from librouteros import connect as ros_connect
        api = ros_connect(username=USERNAME, password=PASSWORD, host=HOST,
                          port=8728, timeout=timeout)
        try:
            ident = list(api.path("system", "identity").select("name"))
            res = list(api.path("system", "resource").select(
                "cpu-load", "free-memory", "total-memory", "uptime",
                "version", "board-name"))
            ifaces = list(api.path("interface").select(
                ".id", "name", "type", "running", "disabled",
                "rx-byte", "tx-byte", "rx-packet", "tx-packet"))
            # Rate per-detik dari selisih counter (seperti kolom Rate di Winbox)
            t_now = time.time()
            for i in ifaces:
                try:
                    rx = int(i.get("rx-byte", 0) or 0); tx = int(i.get("tx-byte", 0) or 0)
                except (TypeError, ValueError):
                    rx = tx = 0
                prev = _IFACE_LAST.get(i.get("name"))
                if prev:
                    dt = max(t_now - prev[0], 0.001)
                    i["rx-bps"] = max(0, int((rx - prev[1]) * 8 / dt)) if rx >= prev[1] else 0
                    i["tx-bps"] = max(0, int((tx - prev[2]) * 8 / dt)) if tx >= prev[2] else 0
                else:
                    i["rx-bps"] = 0; i["tx-bps"] = 0
                _IFACE_LAST[i.get("name")] = (t_now, rx, tx)
            # Urutan kanonik ether1..sfp1, LAN_IN, lo agar sama seperti di MikroTik
            ifaces.sort(key=lambda x: (_IFACE_ORDER.index(x["name"])
                                       if x.get("name") in _IFACE_ORDER else 99,
                                       str(x.get("name"))))
            mangle = list(api.path("ip", "firewall", "mangle").select(
                ".id", "comment", "chain", "action", "connection-mark",
                "routing-mark", "per-connection-classifier", "bytes", "packets"))
            # PCC = punya classifier ATAU comment/mark terkait PCC/LB
            # (rule lama tanpa comment 'PCC-' ikut terhitung, cth. 'LB PCC' + 2/0)
            pcc = [m for m in mangle if _is_pcc_rule(m)]
            out = {"online": True, "identity": ident[0] if ident else {},
                    "resource": res[0] if res else {},
                    "interfaces": ifaces, "mangle_total": len(mangle),
                    "mangle_pcc": pcc, "error": ""}
            _ROUTER_CACHE = {"ts": time.time(), "data": out}
            return out
        finally:
            try:
                api.close()
            except Exception:
                pass
    except Exception as e:  # auth gagal / timeout / API mati
        # Jangan cache kegagalan lebih dari 3 detik agar recovery cepat terlihat
        err = {"online": False, "identity": {}, "resource": {},
                "interfaces": [], "mangle_total": 0, "mangle_pcc": [],
                "error": f"{type(e).__name__}: {e}"}
        if cached is not None and (now - _ROUTER_CACHE.get("ts", 0)) < 3.0:
            return cached
        return err


def live_snapshot() -> dict:
    t0 = time.time()
    ts = datetime.now().isoformat(timespec="seconds")
    # IO jaringan (ping + router) paralel & DI LUAR lock -> tidak antre.
    # SNMP dimatikan di dashboard (snmp_enabled=False, bw=0) agar <6 detik;
    # failover mengandalkan lat/loss + status interface (cukup & cepat).
    # BW presisi tetap diukur main_loop.py.
    import concurrent.futures as _cf
    with _cf.ThreadPoolExecutor(max_workers=2) as ex:
        f_raw = ex.submit(collect_all, PING_COUNT, 1, True, False)
        f_router = ex.submit(poll_router)
        raw = f_raw.result()
        router = f_router.result()
    # Override realtime: interface down -> metrik DOWN seketika
    try:
        running_map = {i.get("name"): bool(i.get("running"))
                       for i in router.get("interfaces", [])}
        if running_map:
            raw = apply_iface_override(raw, running_map)
    except Exception:
        running_map = {}
    with state_lock:
        smooth = {}
        for link in collector.LINKS:  # urutan tetap ISP1 -> ISP2
            if link not in raw:
                continue
            m = raw[link]
            smooth[link] = ewma.update(link, {
                "bandwidth_mbps": m.bandwidth_mbps, "latency_ms": m.latency_ms,
                "jitter_ms": m.jitter_ms, "loss_pct": m.loss_pct})
        saw = compute_saw(smooth)
        alqis = {link: v["alqi"] for link, v in saw.items()}
        decision = decide(alqis, gate)
        # Status DOWN per link: interface down ATAU ping mati total.
        # Link DOWN dibekukan: alqi tampil 0, share 0, bar 0 — tidak ikut goyang
        # oleh normalisasi relatif SAW (sebelumnya 12<->17 karena link UP berubah).
        # Keputusan PCC (decide) tetap pakai alqis asli agar logika failover utuh.
        from decider import DOWN_THRESHOLD
        _down = {}
        for link, m in raw.items():
            iface_up = running_map.get(IFACE_MAP.get(link, ""), None)
            ping_dead = (m.loss_pct >= 99.9 and m.latency_ms >= 900)
            _down[link] = (iface_up is False) or ping_dead or (saw[link]["alqi"] < DOWN_THRESHOLD and ping_dead)
        _up_sum = sum(alqis[l] for l in alqis if not _down.get(l)) or 0.0
        links = {}
        for link in collector.LINKS:  # urutan tetap ISP1 -> ISP2
            if link not in raw:
                continue
            m = raw[link]
            if _down.get(link):
                share = 0.0
                disp_alqi, disp_v = 0.0, 0.0
            elif _up_sum > 0:
                share = round(alqis[link] / _up_sum * 100, 1)
                disp_alqi, disp_v = saw[link]["alqi"], saw[link]["score_V"]
            else:  # semua down -> 0 semua (bukan 50:50 agar jelas mati)
                share = 0.0
                disp_alqi, disp_v = 0.0, 0.0
            links[link] = {"raw": {"bw": m.bandwidth_mbps, "lat": m.latency_ms,
                                   "jit": m.jitter_ms, "loss": m.loss_pct},
                           "smooth": smooth[link],
                           "alqi": disp_alqi,
                           "score_V": disp_v,
                           "r": saw[link]["r"],
                           "down": bool(_down.get(link)),
                           "share_pct": share}
    p1, p2 = [int(x) for x in decision.get("ratio", (1, 1))]
    denom = int(decision.get("denominator", p1 + p2) or (p1 + p2) or 2)
    # Tandai status interface per link agar frontend bisa badge UP/DOWN seketika
    iface_by_link = {link: running_map.get(iface, None)
                     for link, iface in IFACE_MAP.items()}
    elapsed_ms = int((time.time() - t0) * 1000)
    return {"ts": ts, "links": links, "alqis": alqis,
            "decision": {"action": decision.get("action"), "mode": decision.get("mode"),
                         "ratio": [p1, p2], "denominator": denom,
                         "pct": [round(p1 / denom * 100, 1), round(p2 / denom * 100, 1)],
                         "reason": decision.get("reason", "")},
            "weights": WEIGHTS, "router": router,
            "iface_by_link": iface_by_link, "elapsed_ms": elapsed_ms,
            "config": {"mikrotik_host": HOST, "simulate": collector.SIMULATE,
                       "dry_run": DRY_RUN, "poll_s": 5,
                       "ping_count": PING_COUNT, "ewma_alpha": ewma.alpha,
                       "hysteresis": gate.hysteresis, "hold_cycles": gate.hold_cycles}}


def read_history(limit: int = 30) -> list:
    rows: list = []
    try:
        if os.path.exists(DB_PATH):
            con = sqlite3.connect(DB_PATH)
            try:
                cur = con.execute(
                    "SELECT ts,link,bw,lat,jit,loss,alqi,action,ratio "
                    "FROM pcc_log ORDER BY rowid DESC LIMIT ?", (limit,))
                for ts, link, bw, lat, jit, loss, alqi, action, ratio in cur.fetchall():
                    rows.append({"ts": ts, "link": link, "bw": bw, "lat": lat,
                                 "jit": jit, "loss": loss, "alqi": alqi,
                                 "action": action, "ratio": ratio})
                return rows
            finally:
                con.close()
    except Exception:
        pass
    try:
        if os.path.exists(CSV_PATH):
            with open(CSV_PATH, newline="") as f:
                data = list(csv.DictReader(f))[-limit:]
                data.reverse()
                return data
    except Exception:
        pass
    return rows


PAGE = """<!DOCTYPE html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PCC Controller — Monitoring ALQI</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:16px}
h1{font-size:20px;margin:0 0 4px}.sub{color:#94a3b8;font-size:13px;margin-bottom:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
.card{background:#1e293b;border-radius:10px;padding:12px 14px}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:12px;margin-right:6px}
.ok{background:#065f46}.warn{background:#92400e}.bad{background:#991b1b}.info{background:#1e40af}
.bar{height:12px;background:#334155;border-radius:6px;overflow:hidden;margin:6px 0}
.bar>div{height:100%;background:linear-gradient(90deg,#22c55e,#84cc16)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{border-bottom:1px solid #334155;padding:5px 6px;text-align:left}
th{color:#94a3b8;font-weight:600}.mono{font-family:Consolas,monospace;font-size:12px}
.kv{display:flex;justify-content:space-between;font-size:13px;padding:2px 0}
#err{color:#fca5a5;font-size:13px}
button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:6px 12px;cursor:pointer}
</style></head><body>
<h1>PCC Controller — Monitoring ALQI</h1>
<div class="sub">Live metrik &rarr; ALQI (SAW) &rarr; rekomendasi rasio PCC &nbsp;|&nbsp; auto-refresh 5 dtk &nbsp;|&nbsp; READ-ONLY (tidak push)</div>
<div><span id="st" class="badge info">...</span><span id="cfg" class="badge info"></span><span id="ts" class="mono"></span></div>
<div id="err"></div>
<h3>Link &amp; ALQI (presentase = ALQI link / total ALQI)</h3>
<div class="grid" id="links"></div>
<h3>Rekomendasi konfigurasi PCC</h3>
<div class="card" id="dec"></div>
<h3>MikroTik real (<span id="rid" class="mono"></span>)</h3>
<div class="grid"><div class="card" id="res"></div><div class="card"><b>Interface</b><div id="ifs"></div></div></div>
<div class="card" style="margin-top:12px"><b>Mangle PCC aktif</b> (<span id="mp"></span>)<div id="mangle" style="margin-top:8px"></div></div>
<h3>Riwayat ALQI (pcc_log.db)</h3>
<div class="card"><button onclick="loadHist()">Muat ulang riwayat</button><div id="hist"></div></div>
<script>
let _fetching=false;
function fmtB(b){b=+b||0;if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';if(b<1073741824)return (b/1048576).toFixed(1)+' MB';return (b/1073741824).toFixed(2)+' GB';}
function fmtR(b){b=+b||0;if(b<1000)return b+' bps';if(b<1e6)return (b/1e3).toFixed(1)+' kbps';return (b/1e6).toFixed(2)+' Mbps';}
async function live(){
 if(_fetching) return; _fetching=true;
 try{
  const t0=Date.now();
  const ctl=new AbortController(); const to=setTimeout(()=>ctl.abort(),12000);
  const r=await fetch('/api/live',{signal:ctl.signal}); clearTimeout(to);
  const d=await r.json();
  const rtt=Date.now()-t0;
  document.getElementById('ts').textContent='update: '+d.ts+' | backend '+(d.elapsed_ms??'-')+'ms / rtt '+rtt+'ms';
  const st=document.getElementById('st');
  if(d.router.online){st.textContent='MikroTik ONLINE';st.className='badge ok';}
  else{st.textContent='MikroTik OFFLINE';st.className='badge bad';}
  document.getElementById('cfg').textContent=(d.config.simulate?'SIMULASI':'REAL')+' | '+(d.config.dry_run?'DRY-RUN':'LIVE-PUSH')+' | pingx'+(d.config.ping_count??'?');
  document.getElementById('rid').textContent=(d.router.identity&&d.router.identity.name||d.config.mikrotik_host);
  let lh='';const _order=(a,b)=>{const o=['ISP1-FO','ISP2-VSAT'];return o.indexOf(a[0])-o.indexOf(b[0]);};for(const [name,L] of Object.entries(d.links).sort(_order)){
   const up=(d.iface_by_link&&d.iface_by_link[name]);
   const badge=up===false?'<span class="badge bad">IF-DOWN</span>':up===true?'<span class="badge ok">IF-UP</span>':'';
   const isDown=!!L.down||L.raw.loss>=100||L.raw.lat>=999;
   lh+='<div class="card"><b>'+name+'</b> '+badge+(isDown?' <span class="badge bad">LINK-DOWN</span>':'')
   +' <span class="badge info">share '+L.share_pct+'%</span>'
   +'<div class="bar"><div style="width:'+L.share_pct+'%"></div></div>'
   +'<div class="kv"><span>ALQI</span><b>'+L.alqi+(isDown?' (DOWN)':'')+'</b></div>'
   +'<div class="kv"><span>BW</span><span>'+L.raw.bw+' Mbps (smooth '+L.smooth.bandwidth_mbps+')</span></div>'
   +'<div class="kv"><span>Latency</span><span>'+L.raw.lat+' ms</span></div>'
   +'<div class="kv"><span>Jitter</span><span>'+L.raw.jit+' ms</span></div>'
   +'<div class="kv"><span>Loss</span><span>'+L.raw.loss+' %</span></div></div>';}
  document.getElementById('links').innerHTML=lh;
  const D=d.decision;
  document.getElementById('dec').innerHTML='<b>'+D.action+'</b> | mode '+D.mode
   +' | rasio <b>'+D.ratio[0]+':'+D.ratio[1]+'</b> (denom '+D.denominator+')'
   +' | presentase trafik ISP1 '+D.pct[0]+'% / ISP2 '+D.pct[1]+'%'
   +(D.reason?'<div class="mono">'+D.reason+'</div>':'')
   +'<div class="sub">Bobot SAW: '+Object.entries(d.weights).map(e=>e[0]+'='+e[1]).join(', ')+'</div>';
  const R=d.router.resource||{};
  document.getElementById('res').innerHTML='<b>Resource</b><div class="kv"><span>CPU</span><span>'+(R['cpu-load']??'-')+'%</span></div>'
   +'<div class="kv"><span>Mem</span><span>'+(R['free-memory']??'-')+' / '+(R['total-memory']??'-')+'</span></div>'
   +'<div class="kv"><span>Uptime</span><span>'+(R.uptime||'-')+'</span></div>'
   +'<div class="kv"><span>ROS</span><span>'+(R.version||'-')+'</span></div>'
   +'<div class="kv"><span>Board</span><span>'+(R['board-name']||'-')+'</span></div>'
   +'<div id="rerr" class="mono">'+(d.router.error||'')+'</div>';
  let ih='<table><tr><th>iface</th><th>run</th><th>rx (rate)</th><th>tx (rate)</th></tr>';
  for(const i of d.router.interfaces){ih+='<tr><td>'+i.name+(i.disabled?' (dis)':'')+'</td><td>'+(i.running?'up':'down')+'</td><td>'+fmtB(i['rx-byte'])+' ('+fmtR(i['rx-bps'])+')</td><td>'+fmtB(i['tx-byte'])+' ('+fmtR(i['tx-bps'])+')</td></tr>';}
  document.getElementById('ifs').innerHTML=ih+'</table>';
  document.getElementById('mp').textContent=d.router.mangle_pcc.length+' dari '+d.router.mangle_total;
  let mh='<table><tr><th>comment</th><th>chain/mark</th><th>classifier</th><th>bytes</th><th>pkts</th></tr>';
  for(const m of d.router.mangle_pcc){mh+='<tr><td class="mono">'+(m.comment||'-')+'</td><td class="mono">'+(m.chain||'')+' '+(m['connection-mark']||m['routing-mark']||'')+'</td><td class="mono">'+(m['per-connection-classifier']||'-')+'</td><td>'+fmtB(m.bytes)+'</td><td>'+(m.packets??'')+'</td></tr>';}
  document.getElementById('mangle').innerHTML=mh+'</table>';
  document.getElementById('err').textContent='';
  }catch(e){if(e&&e.name==='AbortError'){document.getElementById('err').textContent='backend >12s, skip (request berikutnya jalan)';}else{document.getElementById('err').textContent='fetch /api/live gagal: '+e;}}
  finally{_fetching=false;}}
async function loadHist(){
 const r=await fetch('/api/history?limit=20');const rows=await r.json();
 let h='<table><tr><th>ts</th><th>link</th><th>bw</th><th>lat</th><th>alqi</th><th>aksi</th><th>rasio</th></tr>';
 for(const x of rows){h+='<tr><td class="mono">'+(x.ts||'')+'</td><td>'+(x.link||'')+'</td><td>'+(x.bw??'')+'</td><td>'+(x.lat??'')+'</td><td><b>'+(x.alqi??'')+'</b></td><td>'+(x.action||'')+'</td><td class="mono">'+(x.ratio||'')+'</td></tr>';}
 document.getElementById('hist').innerHTML=h+'</table>';}
live();loadHist();setInterval(live,5000);setInterval(loadHist,15000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "PCCDash/1.0"

    def _json(self, obj: dict | list, code: int = 200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif u.path == "/api/live":
            try:
                self._json(live_snapshot())
            except Exception as e:
                self._json({"error": f"{type(e).__name__}: {e}"}, 500)
        elif u.path == "/api/history":
            q = parse_qs(u.query)
            try:
                limit = max(1, min(200, int(q.get("limit", ["30"])[0])))
            except ValueError:
                limit = 30
            self._json(read_history(limit))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass  # biar console bersih


def main():
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"Dashboard: http://localhost:{port}  (Ctrl+C berhenti)")
    print(f"Router: {HOST} simulate={collector.SIMULATE} dry_run={DRY_RUN} pingx={PING_COUNT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
