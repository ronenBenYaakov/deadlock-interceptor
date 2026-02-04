#include <iostream>
#include <thread>
#include <mutex>
#include <chrono>

// Two global mutexes that will cause a deadlock
std::mutex mutexA;
std::mutex mutexB;

// Thread 1 tries to lock mutexA then mutexB
void threadFunc1() {
    std::cout << "Thread 1: locking mutexA...\n";
    mutexA.lock();
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // simulate work

    std::cout << "Thread 1: locking mutexB...\n";
    mutexB.lock();

    std::cout << "Thread 1: acquired both mutexes!\n";

    mutexB.unlock();
    mutexA.unlock();
}

// Thread 2 tries to lock mutexB then mutexA
void threadFunc2() {
    std::cout << "Thread 2: locking mutexB...\n";
    mutexB.lock();
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // simulate work

    std::cout << "Thread 2: locking mutexA...\n";
    mutexA.lock();

    std::cout << "Thread 2: acquired both mutexes!\n";

    mutexA.unlock();
    mutexB.unlock();
}

int main() {
    std::thread t1(threadFunc1);
    std::thread t2(threadFunc2);

    t1.join();
    t2.join();

    std::cout << "Program finished.\n";
    return 0;
}
