mkdir -p build
cd build
cmake ..
make
python ../app.py &
sudo ./deadlock-interceptor $! group
ps -p $!
