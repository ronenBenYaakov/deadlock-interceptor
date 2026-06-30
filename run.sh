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

# Build the project
echo -e "${YELLOW}[BUILD] Compiling deadlock-interceptor...${NC}"
mkdir -p build
cd build
cmake .. > /dev/null 2>&1
make > /dev/null 2>&1

if [ ! -f ./deadlock-interceptor ]; then
    echo -e "${RED}[✗] Build failed!${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Build successful${NC}"

# Start Python app
echo -e "${YELLOW}[START] Launching Python app...${NC}"
setsid python ../app.py &
PID=$!

if [ -z "$PID" ] || ! kill -0 $PID 2>/dev/null; then
    echo -e "${RED}[✗] Failed to start Python app${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Python app started (PID: $PID)${NC}"

# Wait for app to initialize
echo -e "${YELLOW}[WAIT] Waiting for app to initialize...${NC}"
sleep 2

# Verify app is still running
if ! kill -0 $PID 2>/dev/null; then
    echo -e "${RED}[✗] Python app died during initialization${NC}"
    exit 1
fi

# Show thread info
echo -e "${BLUE}[INFO] Thread information:${NC}"
THREAD_COUNT=$(ls /proc/$PID/task 2>/dev/null | wc -l)
if [ -d /proc/$PID/task ]; then
    echo -e "  Thread count: $THREAD_COUNT"
    echo -e "  Thread IDs: $(ls /proc/$PID/task | tr '\n' ' ')"
else
    echo -e "${RED}[✗] Cannot access /proc/$PID/task - process died?${NC}"
    exit 1
fi

# Run the interceptor
echo -e "${YELLOW}[INTERCEPTOR] Running deadlock-interceptor...${NC}"
echo -e "${BLUE}========================================${NC}"

# Run with sudo and capture output
sudo ./deadlock-interceptor $PID group

INTERCEPTOR_EXIT=$?

echo -e "${BLUE}========================================${NC}"
echo -e "${YELLOW}[INTERCEPTOR] Exit code: $INTERCEPTOR_EXIT${NC}"

# Give process time to stabilize
sleep 1

# Check if Python process is still alive
if kill -0 $PID 2>/dev/null; then
    echo -e "${GREEN}[✓] Python process is still running (PID: $PID)${NC}"
    
    # Check process state
    if [ -d /proc/$PID/task ]; then
        NEW_THREAD_COUNT=$(ls /proc/$PID/task 2>/dev/null | wc -l)
        echo -e "  Thread count after interceptor: $NEW_THREAD_COUNT"
        echo -e "  Thread IDs: $(ls /proc/$PID/task | tr '\n' ' ')"
    fi
    
    echo -e "${GREEN}[✓] Success! Deadlock resolved without killing process${NC}"
    echo -e "${YELLOW}[INFO] You can test with: curl http://localhost:5000${NC}"
else
    echo -e "${RED}[✗] Python process died! (PID: $PID)${NC}"
    echo -e "${YELLOW}[INFO] Checking for clues...${NC}"
    
    # Check dmesg for clues
    echo -e "${BLUE}Last kernel messages:${NC}"
    dmesg | tail -5 | grep -i "python\|ptrace\|segfault" || echo "  No relevant kernel messages"
    
    # Check if core dump was created
    if ls core.* 2>/dev/null | head -1; then
        echo -e "${YELLOW}[INFO] Core dump detected: $(ls core.* | head -1)${NC}"
    fi
    
    exit 1
fi

# Optional: Keep running and show live status
echo -e "${YELLOW}[MONITOR] Monitoring Python process (Ctrl+C to stop)...${NC}"
while kill -0 $PID 2>/dev/null; do
    sleep 5
    echo -ne "\r[$(date '+%H:%M:%S')] Process $PID is running  "
done
echo -e "\n${YELLOW}[INFO] Python process has terminated${NC}"