#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ulimit -c unlimited

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Deadlock Interceptor Launcher${NC}"
echo -e "${BLUE}========================================${NC}"

# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------
echo -e "${YELLOW}[BUILD] Compiling deadlock-interceptor...${NC}"
mkdir -p build
cd build || exit 1
cmake .. > /dev/null 2>&1
make > /dev/null 2>&1

if [ ! -f ./deadlock-interceptor ]; then
    echo -e "${RED}[✗] Build failed!${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Build successful${NC}"

# --------------------------------------------------------------------------
# Start Python app
# --------------------------------------------------------------------------
echo -e "${YELLOW}[START] Launching Python app...${NC}"
setsid python ../app.py &
PID=$!
disown "$PID" 2>/dev/null   # so `wait` still works but shell doesn't print job-status noise

if [ -z "$PID" ] || ! kill -0 "$PID" 2>/dev/null; then
    echo -e "${RED}[✗] Failed to start Python app${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Python app started (PID: $PID)${NC}"

# --------------------------------------------------------------------------
# Wait for app to initialize
# --------------------------------------------------------------------------
echo -e "${YELLOW}[WAIT] Waiting for app to initialize...${NC}"
sleep 2

if ! kill -0 "$PID" 2>/dev/null; then
    echo -e "${RED}[✗] Python app died during initialization${NC}"
    wait "$PID" 2>/dev/null
    STATUS=$?
    if [ "$STATUS" -gt 128 ]; then
        SIG=$((STATUS - 128))
        echo -e "${RED}    Killed by signal $SIG ($(kill -l "$SIG" 2>/dev/null))${NC}"
    else
        echo -e "${RED}    Exited with code $STATUS${NC}"
    fi
    exit 1
fi

# --------------------------------------------------------------------------
# Show thread info (before)
# --------------------------------------------------------------------------
echo -e "${BLUE}[INFO] Thread information:${NC}"
if [ -d /proc/$PID/task ]; then
    THREAD_COUNT=$(ls /proc/$PID/task 2>/dev/null | wc -l)
    echo -e "  Thread count: $THREAD_COUNT"
    echo -e "  Thread IDs: $(ls /proc/$PID/task | tr '\n' ' ')"
else
    echo -e "${RED}[✗] Cannot access /proc/$PID/task - process died?${NC}"
    exit 1
fi

# --------------------------------------------------------------------------
# Run the interceptor
# --------------------------------------------------------------------------
echo -e "${YELLOW}[INTERCEPTOR] Running deadlock-interceptor...${NC}"
echo -e "${BLUE}========================================${NC}"

sudo ./deadlock-interceptor "$PID" group
INTERCEPTOR_EXIT=$?

echo -e "${BLUE}========================================${NC}"
echo -e "${YELLOW}[INTERCEPTOR] Exit code: $INTERCEPTOR_EXIT${NC}"

# Give process time to stabilize after interceptor detaches
sleep 1

# --------------------------------------------------------------------------
# Check survival — this is the part that decides whether we succeeded
# --------------------------------------------------------------------------
if kill -0 "$PID" 2>/dev/null; then
    echo -e "${GREEN}[✓] Python process is still running (PID: $PID)${NC}"

    if [ -d /proc/$PID/task ]; then
        NEW_THREAD_COUNT=$(ls /proc/$PID/task 2>/dev/null | wc -l)
        echo -e "  Thread count after interceptor: $NEW_THREAD_COUNT"
        echo -e "  Thread IDs: $(ls /proc/$PID/task | tr '\n' ' ')"

        # Flag any thread left in a stopped/traced state — a common sign
        # the interceptor attached but didn't cleanly detach/resume it.
        for tid in $(ls /proc/$PID/task 2>/dev/null); do
            STATE=$(awk '/^State:/{print $2, $3}' /proc/$PID/task/$tid/status 2>/dev/null)
            if echo "$STATE" | grep -Eq '^(T|t)'; then
                echo -e "${RED}  [!] Thread $tid is in stopped/traced state ($STATE) — interceptor likely left it un-detached${NC}"
            fi
        done
    fi

    echo -e "${GREEN}[✓] Success! Deadlock resolved without killing process${NC}"
    echo -e "${YELLOW}[INFO] You can test with: curl http://localhost:5000${NC}"
else
    echo -e "${RED}[✗] Python process died! (PID: $PID)${NC}"

    # Get the REAL exit status/signal instead of just "it's gone"
    wait "$PID" 2>/dev/null
    STATUS=$?
    if [ "$STATUS" -gt 128 ]; then
        SIG=$((STATUS - 128))
        echo -e "${RED}    Terminated by signal $SIG ($(kill -l "$SIG" 2>/dev/null))${NC}"
        case "$SIG" in
            9)  echo -e "${YELLOW}    -> SIGKILL: check dmesg for OOM-killer activity, or something external killing it.${NC}" ;;
            11) echo -e "${YELLOW}    -> SIGSEGV: interceptor likely resumed a thread with corrupted registers/stack.${NC}" ;;
            5)  echo -e "${YELLOW}    -> SIGTRAP: process was left traced/stopped and mishandled the trap on resume.${NC}" ;;
            6)  echo -e "${YELLOW}    -> SIGABRT: glibc/runtime detected corruption (e.g. malloc/lock state) after resume.${NC}" ;;
        esac
    else
        echo -e "${RED}    Exited with code $STATUS${NC}"
    fi

    echo -e "${YELLOW}[INFO] Checking for clues...${NC}"

    echo -e "${BLUE}Last kernel messages (unfiltered, last 30 lines):${NC}"
    dmesg 2>/dev/null | tail -30 || echo "  dmesg unavailable (try: sudo dmesg, or check journalctl -k)"

    # Core dump via traditional core.* file
    CORE_FILE=$(ls core.* 2>/dev/null | head -1)
    if [ -n "$CORE_FILE" ]; then
        echo -e "${YELLOW}[INFO] Core dump file detected: $CORE_FILE${NC}"
    else
        echo -e "${YELLOW}[INFO] No core.* file in cwd — checking systemd-coredump instead...${NC}"
        echo -e "  Current core_pattern: $(cat /proc/sys/kernel/core_pattern 2>/dev/null)"
        if command -v coredumpctl > /dev/null 2>&1; then
            echo -e "${BLUE}  Recent coredumpctl entries for PID $PID:${NC}"
            coredumpctl list "$PID" 2>/dev/null || echo "    none found for that PID"
            echo -e "${YELLOW}  To pull it: coredumpctl dump $PID -o /tmp/core.$PID.dump${NC}"
        fi
    fi

    exit 1
fi

# --------------------------------------------------------------------------
# Monitor — keep going, and actually notice if it dies later
# --------------------------------------------------------------------------
echo -e "${YELLOW}[MONITOR] Monitoring Python process (Ctrl+C to stop)...${NC}"
while kill -0 "$PID" 2>/dev/null; do
    sleep 5
    echo -ne "\r[$(date '+%H:%M:%S')] Process $PID is running  "
done

echo -e "\n${RED}[INFO] Python process has terminated${NC}"
wait "$PID" 2>/dev/null
STATUS=$?
if [ "$STATUS" -gt 128 ]; then
    SIG=$((STATUS - 128))
    echo -e "${RED}  Terminated by signal $SIG ($(kill -l "$SIG" 2>/dev/null))${NC}"
else
    echo -e "${RED}  Exited with code $STATUS${NC}"
fi