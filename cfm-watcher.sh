#!/usr/bin/env bash
set -euo pipefail

: "${APP_HOME:=/opt/CICFlowMeter/build/install/CICFlowMeter}"
: "${IN_DIR:=/var/lib/tcpdump}"
: "${OUT_DIR:=/var/log/cicflowmeter}"
: "${LD_LIB_PATH:=/usr/lib:/usr/lib/x86_64-linux-gnu}"
: "${AGE_SEC:=30}"
: "${LOG4J_CFG:=}"

mkdir -p "$OUT_DIR" "$APP_HOME/logs"

# Detect Java 8 if not set
if [ -n "${JAVA_BIN:-}" ]; then
  JAVA="$JAVA_BIN"
elif [ -n "${JAVA_HOME:-}" ]; then
  JAVA="$JAVA_HOME/bin/java"
else
  JAVA="$(update-alternatives --list java | grep -m1 'java-8' || true)"
  [ -z "$JAVA" ] && JAVA="/usr/bin/java"  # fallback
fi

# Build Java opts
JAVA_OPTS=""
if [ -n "$LOG4J_CFG" ] && [ -f "$LOG4J_CFG" ]; then
  JAVA_OPTS="$JAVA_OPTS -Dlog4j.configuration=file:$LOG4J_CFG"
fi
JAVA_OPTS="$JAVA_OPTS -Djava.library.path=$LD_LIB_PATH"

# Prefer the installed launcher, but some builds only expose CLI main
CIC_BIN="$APP_HOME/bin/CICFlowMeter"
CLI_MAIN="cic.cs.unb.ca.ifm.Cmd"

log() { printf "[cfm-watch] %s %s\n" "$(date '+%F %T')" "$*" >&2; }

process_file() {
  local f="$1"
  log "Processing: $f"

  # Try the installed binary first
  if [ -x "$CIC_BIN" ]; then
    # Prefer -r/-c (read pcap, output directory)
    if "$CIC_BIN" -r "$f" -c "$OUT_DIR"; then
      return 0
    fi
    # Fallback to positional form
    if "$CIC_BIN" "$f" "$OUT_DIR"; then
      return 0
    fi
  fi

  # Fallback to calling the main class directly (Java classpath mode)
  if [ -d "$APP_HOME/lib" ]; then
    if "$JAVA" $JAVA_OPTS -cp "$APP_HOME/lib/*" "$CLI_MAIN" -r "$f" -c "$OUT_DIR"; then
      return 0
    fi
    if "$JAVA" $JAVA_OPTS -cp "$APP_HOME/lib/*" "$CLI_MAIN" "$f" "$OUT_DIR"; then
      return 0
    fi
  fi

  log "ERROR: CICFlowMeter execution failed for $f"
  return 1
}

# Main loop
while true; do
  shopt -s nullglob
  for f in "$IN_DIR"/cfm-*.pcap; do
    # Skip if too new
    mtime=$(stat -c %Y "$f"); now=$(date +%s)
    if (( now - mtime < AGE_SEC )); then
      continue
    fi
    # Skip if marked done
    if [ "$USE_DONE_MARKERS" = "true" ] && [ -f "$f.done" ]; then
      continue
    fi

    if process_file "$f"; then
      [ "$USE_DONE_MARKERS" = "true" ] && touch "$f.done"
    fi
  done
  sleep 5
done
