#!/bin/bash
set -e

PYTHON_CMD="python3 ./app.py"
INTERCEPTOR="./build/deadlock-interceptor"

CHECKPOINT_DIR="/tmp/criu_checkpoint"
mkdir -p "$CHECKPOINT_DIR"

PID_FILE="/tmp/py.pid"
INT_PID_FILE="/tmp/int.pid"

log() { echo -e "[SUPERVISOR] $1"; }

checkpoint_python() {
    log "Creating CRIU checkpoint..."

    sudo criu dump \
        -t "$(cat $PID_FILE)" \
        -D "$CHECKPOINT_DIR" \
        -j --leave-running --shell-job \
        || log "Checkpoint failed"
}

restore_python() {
    log "Restoring Python..."

    sudo criu restore \
        -D "$CHECKPOINT_DIR" \
        -j --shell-job \
        &
    sleep 2
}

start_python() {
    log "Starting Python..."
    $PYTHON_CMD &
    echo $! > "$PID_FILE"
    sleep 1
}

start_interceptor() {
    log "Starting interceptor..."

    sudo "$INTERCEPTOR" "$(cat $PID_FILE)" &
    echo $! > "$INT_PID_FILE"
    sleep 1
}

kill_all() {
    log "Killing processes..."

    if [ -f "$INT_PID_FILE" ]; then
        sudo kill -9 "$(cat $INT_PID_FILE)" 2>/dev/null || true
    fi

    if [ -f "$PID_FILE" ]; then
        kill -9 "$(cat $PID_FILE)" 2>/dev/null || true
    fi
}

cleanup_and_restart() {
    log "RECOVERY TRIGGERED"

    kill_all

    sleep 1
    restore_python

    sleep 2
    start_python

    sleep 1
    start_interceptor
}

trap cleanup_and_restart SIGSEGV SIGABRT SIGTERM

# ---------------- MAIN LOOP ----------------

start_python
checkpoint_python
start_interceptor

log "SYSTEM RUNNING"

while true; do
    sleep 2

    # python died
    if ! kill -0 "$(cat $PID_FILE)" 2>/dev/null; then
        log "Python crashed → recovery"
        cleanup_and_restart
    fi

    # interceptor died
    if [ -f "$INT_PID_FILE" ] && ! kill -0 "$(cat $INT_PID_FILE)" 2>/dev/null; then
        log "Interceptor crashed → recovery"
        cleanup_and_restart
    fi
done