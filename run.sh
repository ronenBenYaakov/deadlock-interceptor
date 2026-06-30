mkdir -p build
cd build
cmake ..
make

setsid python ../app.py &
PID=$!

echo "[*] Started Python PID: $PID"

sleep 1

echo "[*] Thread list (/proc/$PID/task):"
ls /proc/$PID/task

echo "[*] Thread count:"
ls /proc/$PID/task | wc -l

sudo ./deadlock-interceptor $PID group
