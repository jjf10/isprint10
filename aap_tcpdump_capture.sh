#!/usr/bin/env bash
# =============================================================================
# aap_tcpdump_capture.sh
# Capture and decrypt HTTPS traffic between the API gateway and AAP Controller.
# Run directly on the AAP Controller host (or a hop node in the path).
#
# Usage:
#   chmod +x aap_tcpdump_capture.sh
#   sudo ./aap_tcpdump_capture.sh [OPTIONS]
#
# Options:
#   -i <iface>      Network interface to capture on  (default: auto-detect)
#   -g <ip>         Filter to this gateway IP only   (default: capture all)
#   -p <port>       Port to capture                  (default: 443)
#   -d <dir>        Output directory                 (default: /tmp/aap-capture)
#   -t <seconds>    Stop capture after N seconds     (default: run until Ctrl-C)
#   -k              Enable TLS session key logging for Wireshark decryption
#   -l              Live plaintext decode via strings (quick and dirty, no keys needed)
#   -h              Show this help
#
# Examples:
#   # Basic capture — all traffic on port 443
#   sudo ./aap_tcpdump_capture.sh
#
#   # Filter to gateway IP, run 60 seconds, enable key logging
#   sudo ./aap_tcpdump_capture.sh -g 10.230.50.10 -t 60 -k
#
#   # Live string decode (no Wireshark needed — shows readable text in TLS)
#   sudo ./aap_tcpdump_capture.sh -g 10.230.50.10 -l
#
# Output files (all written to -d directory):
#   aap-capture-<timestamp>.pcap    — Wireshark-compatible packet capture
#   aap-ssl-keys-<timestamp>.log    — TLS session keys (if -k used)
#   aap-strings-<timestamp>.txt     — Printable strings extracted live (if -l used)
#   aap-capture.log                 — Script run log
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
IFACE=""
GATEWAY_IP=""
PORT=443
OUTDIR="/tmp/aap-capture"
DURATION=0          # 0 = run until Ctrl-C
KEY_LOG=false
LIVE_STRINGS=false
TS=$(date +%Y%m%d-%H%M%S)

# ── Parse args ────────────────────────────────────────────────────────────────
usage() {
    sed -n '/^# Usage/,/^# =/p' "$0" | head -n 30
    exit 0
}

while getopts "i:g:p:d:t:klh" opt; do
    case $opt in
        i) IFACE="$OPTARG" ;;
        g) GATEWAY_IP="$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        d) OUTDIR="$OPTARG" ;;
        t) DURATION="$OPTARG" ;;
        k) KEY_LOG=true ;;
        l) LIVE_STRINGS=true ;;
        h) usage ;;
        *) echo "Unknown option -$OPTARG"; usage ;;
    esac
done

# ── Output paths ──────────────────────────────────────────────────────────────
mkdir -p "$OUTDIR"
PCAP="$OUTDIR/aap-capture-${TS}.pcap"
KEYFILE="$OUTDIR/aap-ssl-keys-${TS}.log"
STRFILE="$OUTDIR/aap-strings-${TS}.txt"
LOGFILE="$OUTDIR/aap-capture.log"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOGFILE"; }

# ── Checks ────────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: this script must run as root (sudo)" >&2
    exit 1
fi

if ! command -v tcpdump &>/dev/null; then
    echo "ERROR: tcpdump not found — install with: dnf install tcpdump" >&2
    exit 1
fi

# ── Auto-detect interface ─────────────────────────────────────────────────────
if [[ -z "$IFACE" ]]; then
    # Pick the interface that carries the default route
    IFACE=$(ip route show default 2>/dev/null \
            | awk '/default/ {print $5; exit}')
    if [[ -z "$IFACE" ]]; then
        IFACE="any"
    fi
fi

# ── Build tcpdump filter expression ───────────────────────────────────────────
# Capture full packets (snaplen 65535) so we get the entire HTTP body.
# The filter matches:
#   tcp port <PORT>                   — all HTTPS
#   [and host <GATEWAY_IP>]           — optional source filter
FILTER="tcp port ${PORT}"
[[ -n "$GATEWAY_IP" ]] && FILTER="${FILTER} and host ${GATEWAY_IP}"

# ── Banner ────────────────────────────────────────────────────────────────────
log "================================================="
log " AAP tcpdump capture"
log "================================================="
log " Interface : $IFACE"
log " Filter    : $FILTER"
log " Output    : $PCAP"
log " Duration  : $([ "$DURATION" -eq 0 ] && echo 'until Ctrl-C' || echo "${DURATION}s")"
log " Key log   : $KEY_LOG  →  $([[ $KEY_LOG == true ]] && echo "$KEYFILE" || echo 'disabled')"
log " Live strs : $LIVE_STRINGS"
log "================================================="

# ── Optional: TLS session key export ─────────────────────────────────────────
# Works when the AAP web service is Python/Django (it is).
# Django's urllib3/ssl writes master secrets to SSLKEYLOGFILE if set.
# You must restart the Controller service with this env var for it to take effect.
if [[ $KEY_LOG == true ]]; then
    log ""
    log "KEY LOG MODE — two options:"
    log ""
    log "  Option A (systemd override — requires service restart):"
    log "    sudo systemctl edit automation-controller --force"
    log "    Add under [Service]:"
    log "      Environment=SSLKEYLOGFILE=${KEYFILE}"
    log "    Then: sudo systemctl restart automation-controller"
    log "    Capture traffic, then remove the override and restart again."
    log ""
    log "  Option B (one-shot, no restart — for new processes only):"
    log "    export SSLKEYLOGFILE=${KEYFILE}"
    log "    Run your ansible-playbook or curl commands in that shell."
    log "    The key log only covers TLS sessions opened AFTER the env var is set."
    log ""
    log "  Wireshark decryption (after capture):"
    log "    Edit → Preferences → Protocols → TLS"
    log "    (Pre)-Master-Secret log filename: ${KEYFILE}"
    log "    Open: ${PCAP}"
    log "    Right-click a TLS packet → Follow → HTTP Stream"
    log ""
    export SSLKEYLOGFILE="$KEYFILE"
    touch "$KEYFILE"
    chmod 600 "$KEYFILE"
    log "SSLKEYLOGFILE exported for this shell: $KEYFILE"
fi

# ── Optional: live string decode pipeline ─────────────────────────────────────
# Pipes raw packet bytes through 'strings' to extract printable text.
# Useful for seeing URL paths, JSON fragments, and headers without Wireshark.
# Not a full decode — binary TLS record framing causes noise — but fast.
if [[ $LIVE_STRINGS == true ]]; then
    log ""
    log "LIVE STRINGS MODE — extracting printable text from raw packets"
    log "Output: $STRFILE  (also shown in terminal)"
    log "Note: TLS-encrypted payloads will show only the TLS handshake (SNI,"
    log "      certificate CN) unless key logging is also enabled (-k)."
    log ""

    tcpdump -i "$IFACE" -s 65535 -w - "$FILTER" 2>>"$LOGFILE" \
    | strings -n 8 \
    | grep -E --line-buffered \
        'GET |POST |HTTP/|Authorization|Bearer|Content-Type|api/v2|api/galaxy|job_template|extra_vars|ansible|200 |201 |403 |404 |500 ' \
    | tee "$STRFILE" &
    STRINGS_PID=$!
    log "Live strings PID: $STRINGS_PID"
fi

# ── Main capture ──────────────────────────────────────────────────────────────
log ""
log "Starting capture → $PCAP"
log "Press Ctrl-C to stop."
log ""

TCPDUMP_ARGS=(
    -i "$IFACE"
    -s 65535          # full packet snaplen — needed to capture HTTP body
    -n                # no DNS resolution (faster, no reverse-lookup delays)
    -w "$PCAP"
    "$FILTER"
)

if [[ "$DURATION" -gt 0 ]]; then
    timeout "$DURATION" tcpdump "${TCPDUMP_ARGS[@]}" 2>>"$LOGFILE" || true
else
    tcpdump "${TCPDUMP_ARGS[@]}" 2>>"$LOGFILE" || true
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────
[[ $LIVE_STRINGS == true ]] && kill "$STRINGS_PID" 2>/dev/null || true

log ""
log "Capture complete."
log "  Packets : $PCAP"
log "  Size    : $(du -sh "$PCAP" | cut -f1)"
[[ $KEY_LOG == true ]]     && log "  TLS keys: $KEYFILE"
[[ $LIVE_STRINGS == true ]] && log "  Strings : $STRFILE"

# ── Post-capture: quick plaintext analysis ────────────────────────────────────
log ""
log "================================================="
log " Post-capture analysis"
log "================================================="

if command -v tcpdump &>/dev/null; then
    log ""
    log "--- HTTP request lines found in capture (unencrypted or TLS handshake) ---"
    tcpdump -r "$PCAP" -A -n 2>/dev/null \
    | grep -E '^(GET|POST|PUT|PATCH|DELETE|HTTP/)' \
    | sort | uniq -c | sort -rn \
    | head -40 \
    | tee -a "$LOGFILE" || true

    log ""
    log "--- Authorization header fragments (Bearer token prefix only) ---"
    tcpdump -r "$PCAP" -A -n 2>/dev/null \
    | grep -oE 'Bearer [A-Za-z0-9_.-]{8,20}' \
    | sort | uniq \
    | sed 's/\(Bearer [A-Za-z0-9_.-]\{8\}\).*/\1.../' \
    | tee -a "$LOGFILE" || true

    log ""
    log "--- TCP conversations (source IP : port → destination : port) ---"
    tcpdump -r "$PCAP" -n 'tcp[tcpflags] & tcp-syn != 0' 2>/dev/null \
    | awk '{print $3, "→", $5}' \
    | sort | uniq -c | sort -rn \
    | head -20 \
    | tee -a "$LOGFILE" || true
fi

# ── Next steps reminder ───────────────────────────────────────────────────────
log ""
log "================================================="
log " Next steps"
log "================================================="
log ""
log "1. Copy the pcap to your workstation for Wireshark:"
log "   scp root@<controller-host>:${PCAP} ~/Desktop/"
[[ $KEY_LOG == true ]] && \
log "   scp root@<controller-host>:${KEYFILE} ~/Desktop/"
log ""
log "2. Open in Wireshark:"
log "   File → Open → aap-capture-${TS}.pcap"
[[ $KEY_LOG == true ]] && log "   Edit → Preferences → Protocols → TLS → key log: aap-ssl-keys-${TS}.log"
log "   Filter bar:  http || http2"
log "   Right-click a packet → Follow → HTTP Stream"
log ""
log "3. Quick body search without Wireshark (printable text only):"
log "   tcpdump -r ${PCAP} -A -n | grep -A5 'POST /api/v2'"
log ""
log "4. If payloads are still encrypted (no key log), use mitmproxy instead:"
log "   pip install mitmproxy"
log "   mitmdump --mode reverse:https://<aap-fqdn> --listen-port 8080 --ssl-insecure"
log "   Then point the gateway at port 8080 temporarily."
log ""
