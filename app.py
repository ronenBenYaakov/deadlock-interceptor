import threading
import time

# -------------------- Locks --------------------
lock_a = threading.Lock()
lock_b = threading.Lock()
lock_c = threading.Lock()
lock_d = threading.Lock()

# -------------------- Deadlock scenarios --------------------
def classic_deadlock():
    """Classic AB-BA deadlock between two threads"""
    tid = threading.get_ident()
    if tid % 2 == 0:
        lock_a.acquire()
        time.sleep(0.2)
        lock_b.acquire()
        lock_b.release()
        lock_a.release()
    else:
        lock_b.acquire()
        time.sleep(0.2)
        lock_a.acquire()
        lock_a.release()
        lock_b.release()

def circular_deadlock():
    """Circular deadlock between 4 threads and 4 locks"""
    tid = threading.get_ident() % 1000
    if tid % 4 == 0:
        lock_a.acquire()
        time.sleep(0.1)
        lock_b.acquire()
        time.sleep(0.1)
        lock_c.acquire()
        time.sleep(0.1)
        lock_d.acquire()
        lock_d.release()
        lock_c.release()
        lock_b.release()
        lock_a.release()
    elif tid % 4 == 1:
        lock_b.acquire()
        time.sleep(0.1)
        lock_c.acquire()
        time.sleep(0.1)
        lock_d.acquire()
        time.sleep(0.1)
        lock_a.acquire()
        lock_a.release()
        lock_d.release()
        lock_c.release()
        lock_b.release()
    elif tid % 4 == 2:
        lock_c.acquire()
        time.sleep(0.1)
        lock_d.acquire()
        time.sleep(0.1)
        lock_a.acquire()
        time.sleep(0.1)
        lock_b.acquire()
        lock_b.release()
        lock_a.release()
        lock_d.release()
        lock_c.release()
    else:
        lock_d.acquire()
        time.sleep(0.1)
        lock_a.acquire()
        time.sleep(0.1)
        lock_b.acquire()
        time.sleep(0.1)
        lock_c.acquire()
        lock_c.release()
        lock_b.release()
        lock_a.release()
        lock_d.release()

def nested_deadlock():
    """Nested lock deadlock"""
    def inner1():
        lock_a.acquire()
        time.sleep(0.05)
        lock_b.acquire()
        lock_b.release()
        lock_a.release()

    def inner2():
        lock_b.acquire()
        time.sleep(0.05)
        lock_a.acquire()
        lock_a.release()
        lock_b.release()

    tid = threading.get_ident()
    if tid % 2 == 0:
        inner1()
    else:
        inner2()

# -------------------- Worker threads --------------------
def worker_deadlock():
    while True:
        classic_deadlock()
        circular_deadlock()
        nested_deadlock()
        time.sleep(0.1)

# -------------------- Main --------------------
threads = []

# Start 6 worker threads to generate deadlocks
for _ in range(6):
    t = threading.Thread(target=worker_deadlock, daemon=True)
    t.start()
    threads.append(t)

# Keep main thread alive
while True:
    time.sleep(1)