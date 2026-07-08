#!/usr/bin/env python3
"""
PlutoSDR Knight Rider Scanner + FS-5000 Forensic HTML Dashboard
"""

import argparse
import datetime
import json
import math
import pathlib
import signal
import statistics
import threading
import time
from collections import deque
from http.server import HTTPServer, BaseHTTPRequestHandler

import numpy as np
import iio

# ====================== CONFIG ======================
HOST = "0.0.0.0"
PORT = 8080

DEFAULT_START = 300_000_000
DEFAULT_STOP  = 900_000_000
DEFAULT_STEP  = 200_000

# ====================== HTML TEMPLATE ======================
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>FS-5000 FORENSIC RF MONITOR</title>
<style>
  :root {
    --bg: #060809; --panel: rgba(10,13,16,0.9); --border: #141c22;
    --accent: #00e5ff; --warn: #ffb300; --danger: #ff1744; --text: #90a4ae;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#000; color:var(--text); font-family:'Courier New',monospace; font-size:12px; overflow:hidden; height:100vh; }
  #ui { position:fixed; inset:0; z-index:10; display:flex; flex-direction:column; }
  #topbar { height:52px; background:var(--panel); border-bottom:1px solid var(--border); display:flex; align-items:center; backdrop-filter:blur(6px); }
  #brand { padding:0 20px; border-right:1px solid var(--border); height:100%; display:flex; flex-direction:column; justify-content:center; }
  #brand .t1 { color:var(--accent); font-weight:bold; letter-spacing:3px; }
  .stat { padding:0 16px; border-right:1px solid var(--border); height:100%; display:flex; flex-direction:column; justify-content:center; }
  .stat .lbl { font-size:9px; color:#1e3040; text-transform:uppercase; letter-spacing:1px; }
  .stat .val { font-size:18px; font-weight:bold; color:var(--accent); }
  #right { margin-left:auto; padding:0 20px; text-align:right; }
  canvas { image-rendering:pixelated; }
  #eq-wrap { flex:1; background:rgba(5,7,9,0.9); position:relative; }
  canvas#eq { position:absolute; inset:0; width:100%; height:100%; }
</style>
</head>
<body>
<div id="ui">
  <div id="topbar">
    <div id="brand">
      <span class="t1">FS-5000</span><br>
      <span style="font-size:9px;color:#1e3040;">RF FORENSIC MONITOR</span>
    </div>
    <div class="stat"><span class="lbl">FREQ</span><span class="val" id="freq">---.---</span></div>
    <div class="stat"><span class="lbl">PEAK</span><span class="val" id="peak">-00.0</span></div>
    <div class="stat"><span class="lbl">FLOOR</span><span class="val" id="floor">-00.0</span></div>
    <div id="right">
      <div id="time" style="color:var(--accent);font-size:13px;"></div>
      <div id="status" style="color:#1e3040;font-size:10px;">SCANNING</div>
    </div>
  </div>
  <div id="eq-wrap"><canvas id="eq"></canvas></div>
</div>

<script>
// Simple adapted EQ from your template
const eqC = document.getElementById('eq');
const qctx = eqC.getContext('2d');
let history = [];

function resize() {
  eqC.width = eqC.offsetWidth;
  eqC.height = eqC.offsetHeight;
}

function drawEQ(peak, floor) {
  const W = eqC.width, H = eqC.height;
  qctx.clearRect(0, 0, W, H);
  resize();

  history.push(peak);
  if (history.length > 120) history.shift();

  const barW = W / history.length * 0.9;
  const range = Math.max(35, Math.max(...history) - floor + 10);

  for (let i = 0; i < history.length; i++) {
    const val = history[i];
    const norm = Math.max(0, Math.min(1, (val - floor + 5) / range));
    const height = norm * (H - 30);
    const x = i * (W / history.length);

    let color = '#00e5ff';
    if (norm > 0.75) color = '#ff1744';
    else if (norm > 0.45) color = '#ffb300';
    else if (norm > 0.25) color = '#76ff03';

    qctx.fillStyle = color;
    qctx.fillRect(x, H - height - 20, barW, height);

    // peak hold
    if (norm > 0.6) {
      qctx.fillStyle = '#ffffff';
      qctx.fillRect(x, H - height - 25, barW, 4);
    }
  }
}

const es = new EventSource('/stream');
es.onmessage = (e) => {
  const d = JSON.parse(e.data);
  document.getElementById('freq').textContent = (d.freq / 1e6).toFixed(3);
  document.getElementById('peak').textContent = d.peak.toFixed(1);
  document.getElementById('floor').textContent = d.floor.toFixed(1);
  document.getElementById('time').textContent = new Date().toISOString().slice(11,19);

  drawEQ(d.peak, d.floor);
};

window.addEventListener('resize', resize);
resize();
</script>
</body>
</html>
"""

# ====================== SERVER ======================
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode())
        elif self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            try:
                while not STOP_REQUESTED:
                    if latest_data:
                        self.wfile.write(f"data: {json.dumps(latest_data)}\n\n".encode())
                        self.wfile.flush()
                    time.sleep(0.15)
            except:
                pass
        else:
            self.send_response(404)
            self.end_headers()

# ====================== GLOBALS ======================
latest_data = None
STOP_REQUESTED = False
server = None

# ====================== PLUTO + SCAN ======================
def main():
    global server, latest_data

    parser = argparse.ArgumentParser()
    parser.add_argument("--uri", default="ip:192.168.2.1")
    parser.add_argument("--gain", type=int, default=50)
    parser.add_argument("--start", type=int, default=DEFAULT_START)
    parser.add_argument("--stop", type=int, default=DEFAULT_STOP)
    parser.add_argument("--step", type=int, default=DEFAULT_STEP)
    args = parser.parse_args()

    # Start web server
    def run_server():
        global server
        server = HTTPServer((HOST, PORT), Handler)
        print(f"\n🌐 FS-5000 Dashboard running at http://127.0.0.1:{PORT}")
        server.serve_forever()

    threading.Thread(target=run_server, daemon=True).start()

    # Pluto setup
    ctx, phy, rxdev = connect_pluto(args.uri)
    enable_rx(rxdev)
    configure_rx(phy, args.gain)

    noise_floor = -75.0
    direction = 1

    print("Starting Knight Rider Scan → Open browser at http://127.0.0.1:8080")

    try:
        while not STOP_REQUESTED:
            freq_range = range(args.start, args.stop + args.step, args.step) if direction > 0 else range(args.stop, args.start - args.step, -args.step)

            for freq in freq_range:
                if STOP_REQUESTED: break
                set_frequency(phy, freq)
                time.sleep(0.06)

                peaks = []
                for _ in range(8):
                    samples = capture_iq(rxdev)
                    peaks.append(analyze_iq_dual(samples))

                peak = statistics.mean(peaks)
                noise_floor = noise_floor * 0.85 + peak * 0.15

                latest_data = {
                    "freq": freq,
                    "peak": round(peak, 2),
                    "floor": round(noise_floor, 2),
                    "timestamp": datetime.datetime.now().isoformat()
                }

                if peak > -62:
                    print(f"\033[91mSPIKE!\033[0m {freq/1e6:.3f} MHz | {peak:.1f} dBFS")

            direction *= -1

    except KeyboardInterrupt:
        print("\nShutdown.")
    finally:
        if server:
            server.shutdown()


# Pluto helper functions (same as before)
def connect_pluto(uri):
    ctx = iio.Context(uri)
    return ctx, ctx.find_device("ad9361-phy"), ctx.find_device("cf-ad9361-lpc")

def enable_rx(rxdev):
    for ch in rxdev.channels:
        if ch.id in ("voltage0", "voltage1"):
            ch.enabled = True

def configure_rx(phy, gain):
    for name in ("voltage0", "voltage1"):
        ch = phy.find_channel(name, False)
        if ch:
            ch.attrs["gain_control_mode"].value = "manual"
            ch.attrs["hardwaregain"].value = str(int(gain))

def set_frequency(phy, freq_hz):
    lo = phy.find_channel("altvoltage0", True)
    lo.attrs["frequency"].value = str(int(freq_hz))
    time.sleep(0.07)
    return int(lo.attrs["frequency"].value)

def capture_iq(rxdev):
    buf = iio.Buffer(rxdev, 65536, False)
    try:
        buf.refill()
        return np.frombuffer(buf.read(), dtype=np.int16).copy()
    finally:
        del buf

def analyze_iq_dual(samples):
    if len(samples) < 4: return -999.0
    i0 = samples[0::4].astype(np.float64)
    q0 = samples[1::4].astype(np.float64)
    i1 = samples[2::4].astype(np.float64)
    q1 = samples[3::4].astype(np.float64)

    def dbfs(i, q):
        power = i*i + q*q
        rms = math.sqrt(math.sqrt(float(np.mean(power))))
        return 20 * math.log10(rms / 32768) if rms > 0 else -999.0
    return max(dbfs(i0,q0), dbfs(i1,q1))


if __name__ == "__main__":
    main()
