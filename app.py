import threading
import time
import random
from queue import Queue

# -------------------- Shared resources --------------------
lock_a = threading.Lock()
lock_b = threading.Lock()
lock_c = threading.Lock()
lock_d = threading.Lock()
shared_counter = [0]  # simulate memory access
message_queue = Queue()

RUNNING = True

# -------------------- Worker functions --------------------

def worker_a():
    while RUNNING:
        with lock_a:
            shared_counter[0] += 1
            time.sleep(random.uniform(0.001, 0.005))
        # send messages randomly
        if random.random() < 0.3:
            message_queue.put("A->B")
        time.sleep(random.uniform(0.001, 0.01))

def worker_b():
    while RUNNING:
        with lock_b:
            shared_counter[0] += 1
            time.sleep(random.uniform(0.001, 0.005))
        # receive messages
        if not message_queue.empty() and random.random() < 0.5:
            _ = message_queue.get()
        time.sleep(random.uniform(0.001, 0.01))

def worker_c():
    while RUNNING:
        # Acquire two random locks in random order to create contention
        locks = random.sample([lock_a, lock_b, lock_c, lock_d], 2)
        first, second = locks[0], locks[1]
        with first:
            time.sleep(random.uniform(0.001, 0.003))
            with second:
                shared_counter[0] += 1
                time.sleep(random.uniform(0.001, 0.003))

def worker_d():
    while RUNNING:
        # Random lock/unlock pattern
        lock = random.choice([lock_a, lock_b, lock_c, lock_d])
        with lock:
            shared_counter[0] += 1
            time.sleep(random.uniform(0.001, 0.004))

def worker_e():
    while RUNNING:
        # Try to acquire three locks in random order (to increase deadlock chance)
        locks = random.sample([lock_a, lock_b, lock_c, lock_d], 3)
        with locks[0]:
            time.sleep(random.uniform(0.001, 0.002))
            with locks[1]:
                time.sleep(random.uniform(0.001, 0.002))
                with locks[2]:
                    shared_counter[0] += 1
                    time.sleep(random.uniform(0.001, 0.002))

# -------------------- Start threads --------------------
threads = []
for f in [worker_a, worker_b, worker_c, worker_d, worker_e]:
    t = threading.Thread(target=f)
    t.start()
    threads.append(t)

# Run for ~2 minutes
start = time.time()
while time.time() - start < 120:
    time.sleep(0.1)

# Stop threads
RUNNING = False

# Join threads
for t in threads:
    t.join()

print("Done! Shared counter =", shared_counter[0])
