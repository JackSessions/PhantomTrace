"""Browser-based GUI for PhantomTrace. Standard library only.

`phantom-trace --gui` (or `phantom-trace-gui`) starts a tiny web server on 127.0.0.1 and opens your browser.
It only listens on this computer, needs a random one-time token in the address, and only ever reads.
Created by Jack Sessions | MIT licence | https://github.com/JackSessions/PhantomTrace
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import phantom_trace as pt

JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
MAX_BODY = 8192


def _run_job(job_id: str, path: str, partition: int, heuristics: bool) -> None:
    job = JOBS[job_id]
    notes: list[str] = []
    try:
        res = pt.scan(path, None, partition, heuristics, progress=lambda i, n: job.update(progress=round(i / max(n, 1), 3)), notify=notes.append)
        job.update(state="done", result=res, notes=notes, progress=1.0)
    except PermissionError:
        job.update(state="error", error="Permission denied. Run PhantomTrace as Administrator/root, or point it at a raw image instead.")
    except FileNotFoundError:
        job.update(state="error", error=f"File not found: {path}")
    except IsADirectoryError:
        job.update(state="error", error="That is a folder. Choose an image file or a device.")
    except pt.NtfsError as e:
        job.update(state="error", error=str(e))
    except Exception as e:                      # keep the UI alive whatever the input is
        job.update(state="error", error=f"Unexpected error: {e}")


def _status(job: dict) -> dict:
    out = {"state": job["state"], "progress": job.get("progress", 0), "error": job.get("error", "")}
    if job["state"] == "done":
        r: pt.ScanResult = job["result"]
        out.update(info=r.info, offset=r.offset, elapsed=round(r.elapsed, 3), notes=job.get("notes", []), cmap=r.cmap,
                   findings=[f.as_dict() for f in r.findings], version=pt.__version__)
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "PhantomTraceGUI"
    token = ""

    def log_message(self, *a) -> None:
        pass

    # ---- helpers
    def _host_ok(self) -> bool:
        return self.headers.get("Host", "").rsplit(":", 1)[0] in ("127.0.0.1", "localhost")

    def _token_ok(self, query: dict) -> bool:
        given = self.headers.get("X-PT-Token") or (query.get("token") or [""])[0]
        return secrets.compare_digest(given.encode(), self.token.encode())

    def _send(self, code: int, body: bytes, ctype: str = "application/json", extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; img-src 'self' data:")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode())

    def _guard(self, query: dict) -> bool:
        if not self._host_ok():
            self._json(403, {"error": "bad host header"})
            return False
        if not self._token_ok(query):
            self._json(403, {"error": "missing or wrong token"})
            return False
        return True

    # ---- routes
    def do_GET(self) -> None:
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if not self._guard(q):
            return
        if u.path == "/":
            self._send(200, PAGE.replace("__VERSION__", pt.__version__).encode(), "text/html; charset=utf-8")
        elif u.path == "/api/ls":
            self._ls((q.get("path") or [""])[0])
        elif u.path == "/api/volumes":
            self._volumes((q.get("path") or [""])[0])
        elif u.path == "/api/status":
            job = JOBS.get((q.get("job") or [""])[0])
            self._json(200, _status(job)) if job else self._json(404, {"error": "unknown job"})
        elif u.path == "/api/report":
            self._report(q)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        u = urllib.parse.urlparse(self.path)
        if not self._guard(urllib.parse.parse_qs(u.query)):
            return
        n = int(self.headers.get("Content-Length") or 0)
        if u.path != "/api/scan" or n > MAX_BODY:
            return self._json(404 if u.path != "/api/scan" else 413, {"error": "bad request"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
            path = str(body["path"]).strip().strip('"')
            partition, heuristics = int(body.get("partition", 1)), bool(body.get("heuristics", False))
        except (KeyError, ValueError, TypeError):
            return self._json(400, {"error": "need a JSON body with a path"})
        if not path:
            return self._json(400, {"error": "choose an image or device first"})
        job_id = secrets.token_hex(6)
        with JOBS_LOCK:
            JOBS[job_id] = {"state": "running", "progress": 0.0}
            for old in list(JOBS)[:-20]:                        # keep memory bounded
                JOBS.pop(old, None)
        threading.Thread(target=_run_job, args=(job_id, path, partition, heuristics), daemon=True).start()
        self._json(200, {"job": job_id})

    def _ls(self, path: str) -> None:
        path = os.path.abspath(os.path.expanduser(path or "~"))
        try:
            entries = []
            with os.scandir(path) as it:
                for e in it:
                    try:
                        isdir = e.is_dir()
                        entries.append({"name": e.name, "dir": isdir, "size": 0 if isdir else e.stat().st_size})
                    except OSError:
                        continue
            entries.sort(key=lambda x: (not x["dir"], x["name"].lower()))
            self._json(200, {"path": path, "parent": os.path.dirname(path), "entries": entries[:2000], "sep": os.sep})
        except OSError as e:
            self._json(200, {"path": path, "parent": os.path.dirname(path), "entries": [], "error": str(e.strerror or e), "sep": os.sep})

    def _volumes(self, path: str) -> None:
        try:
            with open(path, "rb") as fh:
                vols = pt.locate_volumes(fh)
            self._json(200, {"volumes": [{"offset": o, "desc": d} for o, d in vols]})
        except OSError as e:
            self._json(200, {"volumes": [], "error": str(e.strerror or e)})

    def _report(self, q: dict) -> None:
        job = JOBS.get((q.get("job") or [""])[0])
        if not job or job.get("state") != "done":
            return self._json(404, {"error": "no finished scan"})
        r: pt.ScanResult = job["result"]
        fmt = (q.get("fmt") or ["html"])[0]
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if fmt == "csv":
            body, ctype, name = pt.csv_text(r.findings).encode(), "text/csv", f"phantomtrace-{stamp}.csv"
        elif fmt == "json":
            body, ctype, name = pt.json_text(r).encode(), "application/json", f"phantomtrace-{stamp}.json"
        else:
            body, ctype, name = pt.report_html(r.info, r.findings, r.target, r.cmap).encode(), "text/html; charset=utf-8", f"phantomtrace-{stamp}.html"
        self._send(200, body, ctype, {"Content-Disposition": f'attachment; filename="{name}"'})


def make_server(port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    token = secrets.token_urlsafe(18)
    handler = type("BoundHandler", (Handler,), {"token": token})
    return ThreadingHTTPServer(("127.0.0.1", port), handler), token


def serve(port: int = 0, open_browser: bool = True, target: str | None = None) -> int:
    httpd, token = make_server(port)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/?token={token}"
    if target:
        url += "&path=" + urllib.parse.quote(os.path.abspath(target)) + "&scan=1"
    print(f"PhantomTrace GUI running at:\n  {url}\nListening on this computer only. Press Ctrl+C to stop.", flush=True)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="phantom-trace-gui", description="Browser-based GUI for PhantomTrace (runs only on this computer).")
    ap.add_argument("target", nargs="?", help="optional image to scan straight away")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args(argv)
    return serve(a.port, not a.no_browser, a.target)


PAGE = r"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhantomTrace</title>
<style>
:root{color-scheme:dark;--bg:#07090c;--panel:#0d1217;--line:#1c252d;--text:#d7e3ea;--mut:#7fa7b5;--cy:#38d6ff;--am:#ffb02e;--red:#ff4d5e;--grn:#4af0a2}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}
main{max-width:70rem;margin:0 auto;padding:1.4rem 1rem 3rem}
h1{margin:0;font:800 clamp(1.6rem,4vw,2.4rem) ui-monospace,monospace;letter-spacing:.04em;background:linear-gradient(90deg,#ff5f6d,#ffb02e,#ffe14a,#4af0a2,#38d6ff,#8b7bff,#e04aff);-webkit-background-clip:text;background-clip:text;color:transparent;display:inline-block}
.sub{color:var(--mut);font:13px ui-monospace,monospace;margin:.2rem 0 1.2rem}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:1rem}
.row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}.row+.row{margin-top:.7rem}
input[type=text],select{background:#05080b;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:.55rem .7rem;font:14px ui-monospace,monospace}
input[type=text]{flex:1 1 20rem}
button{background:transparent;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:.5rem .9rem;font:inherit;cursor:pointer}
button:hover{border-color:var(--cy);color:var(--cy)}button.go{background:var(--cy);color:#03141a;border-color:var(--cy);font-weight:700}button.go:hover{color:#03141a;filter:brightness(1.1)}button:disabled{opacity:.5;cursor:default}
label{color:var(--mut);font-size:.9rem}
.bar{height:6px;background:#10181e;border-radius:3px;overflow:hidden;margin-top:.8rem;display:none}.bar i{display:block;height:100%;width:0;background:linear-gradient(90deg,#ff5f6d,#ffb02e,#4af0a2,#38d6ff,#e04aff);transition:width .15s}
.verdict{border-left:4px solid var(--grn);background:var(--panel);padding:.8rem 1rem;margin:1rem 0;border-radius:0 8px 8px 0}.verdict.bad{border-color:var(--red)}.verdict.med{border-color:var(--am)}.verdict.low{border-color:var(--cy)}
.tiles{display:flex;gap:.7rem;margin:.2rem 0 1rem}.tile{flex:1;border:1px solid var(--c);border-radius:8px;padding:.6rem;text-align:center}.tile b{display:block;font-size:1.7rem;color:var(--c)}.tile span{color:var(--mut);font-size:.8rem;text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.55rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}th{font:12px ui-monospace,monospace;color:var(--mut);text-transform:uppercase}
tr.f{cursor:pointer}tr.f:hover{background:#0b1218}.chip{display:inline-block;border:1px solid var(--c);color:var(--c);border-radius:999px;padding:0 .6rem;font:12px ui-monospace,monospace;text-transform:uppercase}
code{color:var(--am)}.why{color:var(--mut);font-size:.85rem;margin-top:.3rem;display:none}tr.open .why{display:block}
canvas{display:block;max-width:100%;image-rendering:pixelated;border:1px solid var(--line);border-radius:6px;background:#05070a}
h2{font:600 1rem ui-monospace,monospace;color:var(--mut);margin:1.6rem 0 .5rem}
.err{border-left:4px solid var(--red);background:#1a0c10;padding:.7rem 1rem;border-radius:0 8px 8px 0;margin-top:1rem;display:none}
.dl a{color:var(--cy);margin-right:1rem;font:14px ui-monospace,monospace}small,.mut{color:var(--mut)}
#modal{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;place-items:center;z-index:9}#modal .box{width:min(42rem,94vw);max-height:80vh;display:flex;flex-direction:column}
#list{overflow:auto;border:1px solid var(--line);border-radius:6px;margin:.6rem 0}#list div{padding:.35rem .6rem;cursor:pointer;display:flex;justify-content:space-between;gap:1rem;font:13px ui-monospace,monospace}#list div:hover{background:#0b1218}
footer{margin-top:2.5rem;color:var(--mut);font-size:.85rem}footer a{color:var(--cy)}
</style>
<main>
<h1>PhantomTrace</h1><div class="sub">v__VERSION__ | read-only NTFS cross-layer consistency checker | everything runs on this computer</div>
<div class="panel">
  <div class="row"><input id="path" type="text" placeholder="Path to a raw NTFS image, disk image or device (e.g. /home/you/disk.img or \\.\C:)" spellcheck="false"><button id="browse">Browse…</button></div>
  <div class="row"><label>NTFS volume <select id="part"><option value="1">auto</option></select></label>
    <label><input type="checkbox" id="heur"> include weak timestamp heuristics</label>
    <button id="scan" class="go">Scan</button><span id="note" class="mut"></span></div>
  <div class="bar" id="bar"><i></i></div>
</div>
<div class="err" id="err"></div>
<div id="out" style="display:none">
  <div class="verdict" id="verdict"></div>
  <div class="tiles" id="tiles"></div>
  <div class="dl" id="dl"></div>
  <h2>Volume map</h2><canvas id="map" height="10"></canvas>
  <p><small id="mapnote"></small></p>
  <h2>Findings</h2><table id="tbl"><tr><th>Severity</th><th>Check</th><th>Record</th><th>Name</th><th>Finding</th></tr></table>
  <p><small>Click a finding to see why it matters. Findings are leads, not proof: confirm with a second tool (for example The Sleuth Kit).</small></p>
</div>
<footer>Created by <a href="https://github.com/JackSessions/PhantomTrace" target="_blank" rel="noopener">Jack Sessions</a> | PhantomTrace __VERSION__ | MIT licence</footer>
</main>
<div id="modal"><div class="panel box"><div class="row"><b>Choose an image</b><span class="mut" id="cwd" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></span><button id="close">Close</button></div><div id="list"></div><small>Click a folder to open it, a file to select it.</small></div></div>
<script>
const Q=new URLSearchParams(location.search),TOKEN=Q.get('token'),$=id=>document.getElementById(id),H={'X-PT-Token':TOKEN};
const api=(u,o={})=>fetch(u,{...o,headers:{...H,...(o.headers||{})}}).then(r=>r.json());
const COL={high:'#ff4d5e',medium:'#ffb02e',low:'#38d6ff'};let job=null,timer=null;
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function volumes(){const p=$('path').value.trim();const sel=$('part');sel.innerHTML='<option value="1">auto</option>';if(!p)return;
  const r=await api('/api/volumes?path='+encodeURIComponent(p));
  if(r.volumes&&r.volumes.length){sel.innerHTML=r.volumes.map((v,i)=>`<option value="${i+1}">${i+1}) ${esc(v.desc)} @ ${v.offset}</option>`).join('')}
  $('note').textContent=r.error?r.error:(r.volumes&&r.volumes.length?r.volumes.length+' NTFS volume(s) found':'no NTFS volume found here');}
$('path').addEventListener('change',volumes);
$('path').addEventListener('keydown',e=>{if(e.key==='Enter'){volumes().then(()=>$('scan').click())}});
$('scan').onclick=async()=>{const p=$('path').value.trim();$('err').style.display='none';
  if(!p){return showErr('Choose an image or device first (type a path, or use Browse…).')}
  $('scan').disabled=true;$('out').style.display='none';$('bar').style.display='block';$('bar').firstChild.style.width='2%';
  const r=await api('/api/scan',{method:'POST',body:JSON.stringify({path:p,partition:+$('part').value,heuristics:$('heur').checked})});
  if(r.error){done();return showErr(r.error)}job=r.job;poll();};
function showErr(m){const e=$('err');e.textContent=m;e.style.display='block'}
function done(){clearTimeout(timer);$('scan').disabled=false;$('bar').style.display='none'}
async function poll(){const s=await api('/api/status?job='+job);
  if(s.state==='running'){$('bar').firstChild.style.width=Math.max(2,Math.round(s.progress*100))+'%';timer=setTimeout(poll,200);return}
  done();if(s.state==='error'){return showErr(s.error)}render(s)}
function render(s){const f=s.findings,n={high:0,medium:0,low:0};f.forEach(x=>n[x.severity]++);
  const v=$('verdict');v.className='verdict '+(n.high?'bad':n.medium?'med':f.length?'low':'');
  v.innerHTML='<b>Verdict.</b> '+(n.high?`${n.high} high-severity inconsistenc${n.high==1?'y':'ies'} found. Verify with a second tool before drawing conclusions.`:n.medium?`${n.medium} medium-severity issue(s) found.`:f.length?'Only low-confidence notes.':'No cross-layer inconsistencies found.')+`<div class="mut" style="font-size:.85rem;margin-top:.2rem">${s.info.cluster_size} B clusters | ${s.info.record_size} B records | ${s.info.records} MFT records | ${s.info.clusters} clusters | ${s.elapsed}s${s.notes.length?' | '+esc(s.notes.join(' | ')):''}</div>`;
  $('tiles').innerHTML=['high','medium','low'].map(k=>`<div class="tile" style="--c:${COL[k]}"><b>${n[k]}</b><span>${k}</span></div>`).join('');
  const T=encodeURIComponent(TOKEN);$('dl').innerHTML=['html','csv','json'].map(k=>`<a href="/api/report?job=${job}&fmt=${k}&token=${T}">Download ${k.toUpperCase()}</a>`).join('');
  const order={high:0,medium:1,low:2};const rows=f.slice().sort((a,b)=>order[a.severity]-order[b.severity]).map(x=>`<tr class="f"><td><span class="chip" style="--c:${COL[x.severity]}">${x.severity}</span></td><td><code>${esc(x.check)}</code></td><td>${x.record??''}</td><td>${esc(x.name)}</td><td>${esc(x.message)}<div class="why">${esc(x.why)}</div></td></tr>`).join('');
  $('tbl').innerHTML='<tr><th>Severity</th><th>Check</th><th>Record</th><th>Name</th><th>Finding</th></tr>'+(rows||'<tr><td colspan="5" class="mut">No findings.</td></tr>');
  document.querySelectorAll('tr.f').forEach(r=>r.onclick=()=>r.classList.toggle('open'));
  $('out').style.display='block';
  const M=s.cmap,cv=$('map');if(M&&M.cells){const cols=M.cols,sz=Math.max(3,Math.floor(Math.min(1000,cv.parentElement.clientWidth)/cols)),rws=Math.ceil(M.cells/cols);cv.width=sz*cols;cv.height=sz*rws;const g=cv.getContext('2d');
    for(let i=0;i<M.cells;i++){const x=(i%cols)*sz,y=Math.floor(i/cols)*sz;g.fillStyle=`rgba(56,214,255,${(0.07+0.85*M.frac[i]/100).toFixed(2)})`;g.fillRect(x,y,sz-1,sz-1);if(M.flag[i]){g.strokeStyle='#ff4d5e';g.lineWidth=2;g.strokeRect(x+1,y+1,sz-3,sz-3)}}
    $('mapnote').textContent=`Each square is ${M.per} cluster(s). Brightness is how full that slice is according to the volume bitmap. Red outlines contain clusters named in findings.`}
}
let cwd='';async function ls(p){const r=await api('/api/ls?path='+encodeURIComponent(p||''));cwd=r.path;$('cwd').textContent=r.path;
  const up=r.parent&&r.parent!==r.path?`<div data-p="${esc(r.parent)}" data-d="1"><span>⬑ ..</span></div>`:'';
  $('list').innerHTML=up+(r.error?`<div class="mut">${esc(r.error)}</div>`:'')+r.entries.map(e=>`<div data-p="${esc(r.path+(r.path.endsWith(r.sep)?'':r.sep)+e.name)}" data-d="${e.dir?1:0}"><span>${e.dir?'📁 ':'📄 '}${esc(e.name)}</span><span class="mut">${e.dir?'':(e.size/1048576).toFixed(1)+' MB'}</span></div>`).join('');
  $('list').querySelectorAll('div[data-p]').forEach(d=>d.onclick=()=>{if(d.dataset.d==='1')ls(d.dataset.p);else{$('path').value=d.dataset.p;$('modal').style.display='none';volumes()}})}
$('browse').onclick=()=>{$('modal').style.display='grid';ls($('path').value.trim().replace(/[\\/][^\\/]*$/,'')||'')};$('close').onclick=()=>$('modal').style.display='none';
if(Q.get('path')){$('path').value=Q.get('path');volumes().then(()=>{if(Q.get('scan'))$('scan').click()})}
</script></html>"""


if __name__ == "__main__":
    raise SystemExit(main())
