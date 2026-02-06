mkdir -p build
cd build
cmake ..
make
python ../app.py &
sudo ./deadlock-interceptor $! 1
ps -p $!