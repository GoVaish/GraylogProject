# rt_monitor.py
# Reusable real-time utilities for CICFlowMeter CSVs (Windows-friendly)
# Now with a directory watcher that prints alerts to the console (PyCharm)

import os, json, time, socket, logging, re
from datetime import datetime
from typing import Dict, Any, List, Tuple
from collections import defaultdict

import numpy as np
import pandas as pd
import joblib

# --- NEW: watcher imports ---
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# -------- Config defaults (overridable by env / caller) --------
# Directory to watch for CICFlowMeter CSVs
WATCH_DIR = os.environ.get(
    "WATCH_DIR",
    r"C:\Users\Vaishnavi Gobade\PycharmProjects\CIC-DOS2019\CICFlowMeter_Output_Dir"
)
ALERT_LOG = os.environ.get("ALERT_LOG", "alerts.log")

THRESH_RF = float(os.environ.get("THRESH_RF", "0.50"))
THRESH_XGB = float(os.environ.get("THRESH_XGB", "0.50"))
ENSEMBLE_RULE = os.environ.get("ENSEMBLE_RULE", "any")  # any | majority | all

FEATURES_FILE = os.environ.get("FEATURES_FILE", "features_list.joblib")
LABEL_ENCODER_FILE = os.environ.get("LABEL_ENCODER_FILE", "label_encoder.joblib")
RF_PIPE_FILE = os.environ.get("RF_PIPE_FILE", "rf_pipeline.joblib")
XGB_PIPE_FILE = os.environ.get("XGB_PIPE_FILE", "xgb_pipeline.joblib")

NDJSON_OUT_DIR = os.environ.get("NDJSON_OUT_DIR", "logs")
NDJSON_FILE    = os.environ.get("NDJSON_FILE", "graylog_input.json")

# Optional Graylog (keep disabled here to avoid duplication with API)
GRAYLOG_UDP_HOST = os.environ.get("GRAYLOG_UDP_HOST")  # e.g., "127.0.0.1" (None to disable)
GRAYLOG_UDP_PORT = int(os.environ.get("GRAYLOG_UDP_PORT", "12201"))

# Columns dropped during training (kept as-is)
DROP_COLS = {
    'Unnamed: 0','Flow ID','Source IP','Destination IP','Timestamp',
    'Fwd Header Length.1','SimillarHTTP','Inbound',
    'Fwd PSH Flags','Bwd PSH Flags','Fwd URG Flags','Bwd URG Flags',
    'Fwd Avg Bytes/Bulk','Fwd Avg Packets/Bulk','Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk','Bwd Avg Packets/Bulk','Bwd Avg Bulk Rate',
    'Init_Win_bytes_forward','Init_Win_bytes_backward',
    'act_data_pkt_fwd','min_seg_size_forward','Source Port',
    'Destination Port','Protocol'
}
SYNONYMS = {
    "Src IP": "Source IP",
    "Dst IP": "Destination IP",
    "Src Port": "Source Port",
    "Dst Port": "Destination Port",
    "Fwd Header Len": "Fwd Header Length",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min":  "min_seg_size_forward",
    "Fwd Byts/b Avg":    "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg":    "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg":  "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg":    "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg":    "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg":  "Bwd Avg Bulk Rate",
}

def canon_col(n: str) -> str:
    n = re.sub(r"\s+", " ", str(n).strip())
    n = n.replace("Hdr Len", "Header Length").replace("Header Len", "Header Length")
    return SYNONYMS.get(n, n)

def load_artifacts() -> Tuple[pd.Index, Any, Any, Any]:
    label_encoder = joblib.load(LABEL_ENCODER_FILE)
    expected_features = joblib.load(FEATURES_FILE)
    rf_pipeline = joblib.load(RF_PIPE_FILE)
    xgb_pipeline = joblib.load(XGB_PIPE_FILE)
    return pd.Index(expected_features), label_encoder, rf_pipeline, xgb_pipeline

def prep_frame(df_raw: pd.DataFrame, expected_features: pd.Index) -> pd.DataFrame:
    df = df_raw.copy()
    df.columns = [canon_col(c) for c in df.columns]
    if 'Label' in df.columns:
        df = df.drop(columns=['Label'])
    # drop exclusions (safe if absent)
    df = df.drop(columns=[c for c in DROP_COLS if c in df.columns], errors="ignore")
    # numeric coercion
    for c in df.columns:
        if not np.issubdtype(df[c].dtype, np.number):
            df[c] = pd.to_numeric(df[c], errors='coerce')
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(how='all', axis=1).dropna(axis=0)
    df = df.reindex(columns=expected_features, fill_value=0.0)
    return df.astype(float, copy=False)

def decide_attack(p_rf: float, p_xgb: float) -> str:
    votes = int(p_rf >= THRESH_RF) + int(p_xgb >= THRESH_XGB)
    if ENSEMBLE_RULE == "any": return "ATTACK" if votes >= 1 else "BENIGN"
    if ENSEMBLE_RULE == "majority": return "ATTACK" if votes >= 2 else "BENIGN"
    if ENSEMBLE_RULE == "all": return "ATTACK" if votes == 2 else "BENIGN"
    return "ATTACK" if votes >= 1 else "BENIGN"

def predict_batch(df_features: pd.DataFrame, label_encoder, rf_pipeline, xgb_pipeline):
    rf_prob = rf_pipeline.predict_proba(df_features)[:, 1]
    xgb_prob = xgb_pipeline.predict_proba(df_features)[:, 1]
    rf_pred = (rf_prob >= THRESH_RF).astype(int)
    xgb_pred = (xgb_prob >= THRESH_XGB).astype(int)
    rf_label = label_encoder.inverse_transform(rf_pred)
    xgb_label = label_encoder.inverse_transform(xgb_pred)
    return rf_prob, rf_label, xgb_prob, xgb_label

def write_json_log(data, filename=NDJSON_FILE, output_dir=NDJSON_OUT_DIR):
    os.makedirs(output_dir, exist_ok=True)
    fp = os.path.join(output_dir, filename)
    with open(fp, "a", encoding="utf-8") as f:
        f.write(json.dumps(data) + "\n")

def send_gelf_udp(host, port, payload: dict):
    if not host or not port:
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(json.dumps(payload).encode("utf-8"), (host, port))
    finally:
        s.close()

def stable_filesize(path, retries=5, sleep_s=0.5):
    """Wait until file size stops changing."""
    prev = -1
    for _ in range(retries):
        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            return False
        if size == prev and size > 0:
            return True
        prev = size
        time.sleep(sleep_s)
    return False

# -------------- Logging setup --------------
logging.basicConfig(
    filename=ALERT_LOG,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ------- NEW: directory watcher that reuses your logic -------
class FlowCSVHandler(FileSystemEventHandler):
    """Tail new/modified CSV files and classify appended flows."""
    def __init__(self, expected, label_encoder, rf_pipeline, xgb_pipeline):
        super().__init__()
        self.seen_rows = defaultdict(int)
        self.expected = expected
        self.le = label_encoder
        self.rf = rf_pipeline
        self.xgb = xgb_pipeline

    def on_created(self, event):
        if not event.is_directory and event.src_path.lower().endswith(".csv"):
            self._process(event.src_path)

    def on_modified(self, event):
        # In case CICFlowMeter appends to existing CSVs
        if not event.is_directory and event.src_path.lower().endswith(".csv"):
            self._process(event.src_path)

    def _process(self, path):
        if not stable_filesize(path):
            return
        try:
            df_new = pd.read_csv(path)
        except Exception as e:
            print(f"❌ Failed to read {path}: {e}")
            return

        df_new = prep_frame(df_new, self.expected)
        if df_new.empty:
            return

        # only new rows since last time
        start_idx = self.seen_rows[path]
        if start_idx >= len(df_new):
            return

        batch = df_new.iloc[start_idx:].copy()
        self.seen_rows[path] = len(df_new)

        # ---- Batch predictions (fast) ----
        rf_prob, rf_label, xgb_prob, xgb_label = predict_batch(batch, self.le, self.rf, self.xgb)
        ts = datetime.utcnow().isoformat() + "Z"

        for i, (p_r, l_r, p_x, l_x) in enumerate(zip(rf_prob, rf_label, xgb_prob, xgb_label), start=start_idx):
            is_attack = decide_attack(float(p_r), float(p_x))
            out = {
                "timestamp": ts,
                "source_file": path,
                "flow_index": int(i),
                "rf_prob": float(p_r),
                "rf_label": str(l_r),
                "xgb_prob": float(p_x),
                "xgb_label": str(l_x),
                "decision": "ATTACK" if is_attack else "BENIGN",
            }

            write_json_log(out)       # NDJSON for Graylog file input
            send_gelf_udp(GRAYLOG_UDP_HOST, GRAYLOG_UDP_PORT, out)

            if is_attack:
                msg = f"🚨 ALERT [{ts}] {os.path.basename(path)} row {i}: RF={l_r}({float(p_r):.3f}), XGB={l_x}({float(p_x):.3f})"
                print(msg)            # <-- prints in PyCharm console
                logging.info(msg)

# ---------- Script entrypoint ----------
if __name__ == "__main__":
    # Load artifacts once
    expected, le, rf, xgb = load_artifacts()

    # Ensure watch dir exists
    os.makedirs(WATCH_DIR, exist_ok=True)

    handler = FlowCSVHandler(expected, le, rf, xgb)
    observer = Observer()
    observer.schedule(handler, path=WATCH_DIR, recursive=False)
    observer.start()

    try:
        print(f"Monitoring folder: {WATCH_DIR} (press Ctrl+C to stop)")
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
