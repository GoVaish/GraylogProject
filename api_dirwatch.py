# api_dirwatch.py — Windows-friendly API that watches a CSV folder, uses rt_monitor, and forwards to Graylog
import os, json, time, socket, sqlite3, threading, glob
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

import pandas as pd
from fastapi import FastAPI, HTTPException, Header, Body

import rt_monitor as RT

# -------- CONFIG (env) --------
WATCH_DIR      = os.environ.get("WATCH_DIR", r"C:\Users\Vaishnavi Gobade\PycharmProjects\CIC-DOS2019\CICFlowMeter_Output_Dir")  # <-- FIXED PATH
STATE_DB       = os.environ.get("STATE_DB", r"C:\Users\Vaishnavi Gobade\PycharmProjects\CIC-DOS2019\identifier.sqlite")
BATCH_SIZE     = int(os.environ.get("BATCH_SIZE", "500"))

GRAYLOG_HOST   = os.environ.get("GRAYLOG_HOST", "192.168.56.10")   # empty disables sending while you test
GRAYLOG_PORT   = int(os.environ.get("GRAYLOG_PORT", "12201"))
GRAYLOG_MODE   = os.environ.get("GRAYLOG_MODE", "gelf")  # 'raw' | 'gelf'
GRAYLOG_TRANSPORT = os.environ.get("GRAYLOG_TRANSPORT", "udp")  # 'udp' or 'tcp'

API_KEY        = os.environ.get("API_KEY", "u39_VZkeC7-arVl6qmqE3mFCAxtu-tQzR1doKk3gbCY")

NDJSON_DIR     = os.environ.get("NDJSON_DIR", "logs")  # consider absolute path if PyCharm WD differs
NDJSON_FILE    = os.environ.get("NDJSON_FILE", "graylog_input.json")

SCAN_INTERVAL  = float(os.environ.get("SCAN_INTERVAL", "2.0"))
STABLE_CHECKS  = int(os.environ.get("STABLE_CHECKS", "3"))
# ---------------------------------------

# Load artifacts once
EXPECTED, LABEL_ENCODER, RF_PIPE, XGB_PIPE = RT.load_artifacts()

# ---------- SQLite ----------
def db():
    c = sqlite3.connect(STATE_DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS progress (
            file_path TEXT PRIMARY KEY,
            rows_done INTEGER NOT NULL DEFAULT 0,
            last_size INTEGER NOT NULL DEFAULT 0,
            last_mtime INTEGER NOT NULL DEFAULT 0
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at INTEGER NOT NULL,
            file_path TEXT,
            flow_index INTEGER,
            rf_prob REAL, rf_label TEXT,
            xgb_prob REAL, xgb_label TEXT,
            decision TEXT,
            payload_json TEXT
        )""")
init_db()

def get_progress(path: str) -> int:
    with db() as c:
        r = c.execute("SELECT rows_done FROM progress WHERE file_path=?", (path,)).fetchone()
        return int(r["rows_done"]) if r else 0

def set_progress(path: str, rows_done: int, size: int, mtime: int):
    with db() as c:
        c.execute("""INSERT INTO progress(file_path, rows_done, last_size, last_mtime)
                     VALUES(?,?,?,?)
                     ON CONFLICT(file_path) DO UPDATE SET rows_done=excluded.rows_done,
                                                         last_size=excluded.last_size,
                                                         last_mtime=excluded.last_mtime""",
                  (path, rows_done, size, mtime))

def insert_results(rows: List[Dict[str, Any]]):
    ts = int(time.time())
    with db() as c:
        for r in rows:
            c.execute("""INSERT INTO results (created_at, file_path, flow_index, rf_prob, rf_label,
                                              xgb_prob, xgb_label, decision, payload_json)
                         VALUES (?,?,?,?,?,?,?,?,?)""",
                      (ts, r.get("source_file"), r.get("flow_index"),
                       r.get("rf_prob"), r.get("rf_label"),
                       r.get("xgb_prob"), r.get("xgb_label"),
                       r.get("decision"), json.dumps(r)))

def write_ndjson(d: dict):
    os.makedirs(NDJSON_DIR, exist_ok=True)
    with open(os.path.join(NDJSON_DIR, NDJSON_FILE), "a", encoding="utf-8") as f:
        f.write(json.dumps(d) + "\n")

# def send_graylog(payload: dict):
#     if not GRAYLOG_HOST or not GRAYLOG_PORT:
#         return
#     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     try:
#         if GRAYLOG_MODE.lower() == "gelf":
#             gelf = {
#                 "version": "1.1",
#                 "host": os.environ.get("COMPUTERNAME", "windows-host"),
#                 "short_message": payload.get("decision","") + " DNS flow",
#                 "timestamp": time.time(),
#                 "level": 5,
#                 "_rf_prob": payload.get("rf_prob"),
#                 "_xgb_prob": payload.get("xgb_prob"),
#                 "_rf_label": payload.get("rf_label"),
#                 "_xgb_label": payload.get("xgb_label"),
#                 "_decision": payload.get("decision"),
#                 "_source_file": payload.get("source_file"),
#                 "_flow_index": payload.get("flow_index"),
#                 "_ts": payload.get("timestamp"),
#                 "_source": "ml-monitor",
#             }
#             s.sendto(json.dumps(gelf).encode("utf-8"), (GRAYLOG_HOST, GRAYLOG_PORT))
#         else:
#             s.sendto(json.dumps(payload).encode("utf-8"), (GRAYLOG_HOST, GRAYLOG_PORT))
#     finally:
#         s.close()

# --- CHANGE 2: GELF helpers + sender ---
def _gelf_payload(payload: dict) -> dict:
    # Minimal valid GELF with custom fields (must start with "_")
    return {
        "version": "1.1",
        "host": os.environ.get("COMPUTERNAME") or socket.gethostname() or "windows-host",
        "short_message": f"{payload.get('decision','')} DNS flow",
        "timestamp": time.time(),  # seconds since epoch (float)
        "level": 5,                # 1=alert … 7=debug; 5=notice
        "facility": "ml-monitor",
        "_rf_prob": payload.get("rf_prob"),
        "_xgb_prob": payload.get("xgb_prob"),
        "_rf_label": payload.get("rf_label"),
        "_xgb_label": payload.get("xgb_label"),
        "_decision": payload.get("decision"),
        "_source_file": payload.get("source_file"),
        "_flow_index": payload.get("flow_index"),
        "_ts": payload.get("timestamp"),
        "_source": "ml-monitor",
    }

def send_graylog(payload: dict):
    if not GRAYLOG_HOST or not GRAYLOG_PORT:
        return

    mode = (GRAYLOG_MODE or "").lower()
    transport = (GRAYLOG_TRANSPORT or "").lower()

    try:
        if mode == "gelf":
            data = json.dumps(_gelf_payload(payload)).encode("utf-8")

            if transport == "tcp":
                # GELF TCP requires null-terminated frames
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((GRAYLOG_HOST, GRAYLOG_PORT))
                s.sendall(data + b"\x00")
                s.close()
            else:
                # default: UDP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(data, (GRAYLOG_HOST, GRAYLOG_PORT))
                s.close()
        else:
            # RAW/Plaintext UDP: just send the original payload JSON
            data = json.dumps(payload).encode("utf-8")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(data, (GRAYLOG_HOST, GRAYLOG_PORT))
            s.close()

    except Exception as e:
        # Don't crash pipeline on logging error
        print(f"[graylog] send failed: {e}")

def stable_file(path: str) -> bool:
    prev = -1
    for _ in range(STABLE_CHECKS):
        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            return False
        if size == prev and size > 0:
            return True
        prev = size
        time.sleep(0.2)
    return False

# ---------- Core processing ----------
def process_file(path: str):
    if not path.lower().endswith(".csv") or not os.path.isfile(path):
        return
    if not stable_file(path):
        return

    try:
        df_all = pd.read_csv(path)
    except Exception as e:
        print(f"[X] Failed to read {path}: {e}")
        return

    nrows = len(df_all)
    start = get_progress(path)
    if start >= nrows:
        return

    df_tail_raw = df_all.iloc[start:].copy()
    if df_tail_raw.empty:
        return

    df = RT.prep_frame(df_tail_raw, EXPECTED)
    if df.empty:
        set_progress(path, nrows, os.path.getsize(path), int(os.path.getmtime(path)))
        return

    results_batch = []
    ts = datetime.now(timezone.utc).isoformat()
    idx_offset = start

    for i in range(0, len(df), BATCH_SIZE):
        chunk = df.iloc[i:i+BATCH_SIZE]
        rf_prob, rf_label, xgb_prob, xgb_label = RT.predict_batch(chunk, LABEL_ENCODER, RF_PIPE, XGB_PIPE)
        for j in range(len(chunk)):
            p_r, p_x = float(rf_prob[j]), float(xgb_prob[j])
            dec = RT.decide_attack(p_r, p_x)
            out = {
                "timestamp": ts,
                "source_file": path,
                "flow_index": int(idx_offset + i + j),
                "rf_prob": p_r, "rf_label": str(rf_label[j]),
                "xgb_prob": p_x, "xgb_label": str(xgb_label[j]),
                "decision": dec,
                "source": "ml-monitor",
            }
            results_batch.append(out)
            write_ndjson(out)
            send_graylog(out)

    insert_results(results_batch)
    set_progress(path, nrows, os.path.getsize(path), int(os.path.getmtime(path)))
    print(f"[✓] {path}: processed {len(results_batch)} new rows (total rows: {nrows})")

# ---------- Watch loop ----------
_stop = threading.Event()

def scan_once():
    for p in sorted(glob.glob(os.path.join(WATCH_DIR, "*.csv"))):
        try:
            process_file(p)
        except Exception as e:
            print(f"[!] Error processing {p}: {e}")

def watch_loop():
    print(f"Watching {WATCH_DIR} … batch={BATCH_SIZE}, mode={GRAYLOG_MODE}")
    while not _stop.is_set():
        scan_once()
        _stop.wait(SCAN_INTERVAL)

# ---------- FastAPI lifespan (replaces on_event) ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(WATCH_DIR, exist_ok=True)
    t = threading.Thread(target=watch_loop, name="dirwatch", daemon=True)
    t.start()
    try:
        yield
    finally:
        _stop.set()
        t.join(timeout=2)

app = FastAPI(title="CFM Dirwatch API (Windows)", version="1.2", lifespan=lifespan)

# ---------- API ----------
def _require_api_key(x_api_key: Optional[str]):
    if API_KEY and (x_api_key or "") != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

@app.get("/health")
def health():
    return {"ok": True, "watch_dir": WATCH_DIR, "graylog": {"host": GRAYLOG_HOST, "port": GRAYLOG_PORT, "mode": GRAYLOG_MODE}}

@app.get("/stats")
def stats(x_api_key: Optional[str] = Header(None, convert_underscores=False)):
    _require_api_key(x_api_key)
    with db() as c:
        total = c.execute("SELECT COUNT(*) as cnt FROM results").fetchone()["cnt"]
        attacks = c.execute("SELECT COUNT(*) as cnt FROM results WHERE decision='ATTACK'").fetchone()["cnt"]
        files = c.execute("SELECT COUNT(*) as cnt FROM progress").fetchone()["cnt"]
    return {"results_total": total, "attacks_total": attacks, "files_tracked": files}

@app.post("/rescan")
def rescan(x_api_key: Optional[str] = Header(None, convert_underscores=False), path: Optional[str] = Body(None)):
    _require_api_key(x_api_key)
    if path:
        process_file(path); return {"ok": True, "rescanned": path}
    scan_once(); return {"ok": True, "rescanned": "all"}

# Optional: plain watcher mode (no HTTP) if you run this file directly
if __name__ == "__main__":
    os.makedirs(WATCH_DIR, exist_ok=True)
    print(f"[plain] Watching {WATCH_DIR} … batch={BATCH_SIZE}, mode={GRAYLOG_MODE}")
    try:
        watch_loop()
    except KeyboardInterrupt:
        _stop.set()