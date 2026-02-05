g++ -std=c++17 -O2 -o agent agent.cpp -pthread
python app.py &
sudo ./agent $!
