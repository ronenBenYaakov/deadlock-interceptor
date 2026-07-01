#!/usr/bin/env python3
"""
Deadlock Generator for Testing Deadlock Detector
"""

import threading
import time
import random
import sys
import os
import signal
from contextlib import contextmanager

# -------------------- Global State --------------------
DEADLOCK_COUNTER = 0
RUNNING = True
DEADLOCK_TYPES = ['classic', 'circular', 'nested', 'chain', 'resource']

# -------------------- Locks --------------------
lock_a = threading.Lock()
lock_b = threading.Lock()
lock_c = threading.Lock()
lock_d = threading.Lock()
lock_e = threading.Lock()

locks = [lock_a, lock_b, lock_c, lock_d, lock_e]
lock_names = ['A', 'B', 'C', 'D', 'E']

# -------------------- Helper Functions --------------------
def random_sleep(min_ms=10, max_ms=100):
    time.sleep(random.uniform(min_ms / 1000.0, max_ms / 1000.0))

def acquire_locks_in_order(lock_list, order):
    acquired = []
    try:
        for idx in order:
            lock_list[idx].acquire()
            acquired.append(idx)
            random_sleep(5, 20)
        return True
    except:
        for idx in acquired:
            lock_list[idx].release()
        return False

def release_locks(lock_list, order):
    for idx in reversed(order):
        lock_list[idx].release()

@contextmanager
def acquire_locks(*lock_indices):
    acquired = []
    try:
        for idx in lock_indices:
            locks[idx].acquire()
            acquired.append(idx)
        yield
    finally:
        for idx in reversed(acquired):
            locks[idx].release()

# -------------------- Deadlock Scenarios --------------------

def classic_deadlock(tid):
    if tid % 2 == 0:
        with acquire_locks(0, 1):
            random_sleep(10, 30)
    else:
        with acquire_locks(1, 0):
            random_sleep(10, 30)

def circular_deadlock(tid):
    thread_type = tid % 4
    
    if thread_type == 0:
        with acquire_locks(0, 1, 2, 3):
            random_sleep(5, 15)
    elif thread_type == 1:
        with acquire_locks(1, 2, 3, 0):
            random_sleep(5, 15)
    elif thread_type == 2:
        with acquire_locks(2, 3, 0, 1):
            random_sleep(5, 15)
    else:
        with acquire_locks(3, 0, 1, 2):
            random_sleep(5, 15)

def nested_deadlock(tid):
    def inner1():
        with acquire_locks(0, 1):
            random_sleep(5, 15)
    
    def inner2():
        with acquire_locks(1, 0):
            random_sleep(5, 15)
    
    if tid % 2 == 0:
        inner1()
    else:
        inner2()

def chain_deadlock(tid):
    thread_type = tid % 5
    
    if thread_type == 0:
        with acquire_locks(0):
            random_sleep(10, 20)
            locks[1].acquire()
            locks[1].release()
    elif thread_type == 1:
        with acquire_locks(1):
            random_sleep(10, 20)
            locks[2].acquire()
            locks[2].release()
    elif thread_type == 2:
        with acquire_locks(2):
            random_sleep(10, 20)
            locks[3].acquire()
            locks[3].release()
    elif thread_type == 3:
        with acquire_locks(3):
            random_sleep(10, 20)
            locks[4].acquire()
            locks[4].release()
    else:
        with acquire_locks(4):
            random_sleep(10, 20)
            locks[0].acquire()
            locks[0].release()

def resource_deadlock(tid):
    if tid % 2 == 0:
        with acquire_locks(0):
            random_sleep(5, 10)
            with acquire_locks(1):
                random_sleep(5, 10)
    else:
        with acquire_locks(1):
            random_sleep(5, 10)
            with acquire_locks(0):
                random_sleep(5, 10)

def dining_philosophers(tid):
    num_locks = 5
    left = tid % num_locks
    right = (tid + 1) % num_locks
    
    if tid % 2 == 0:
        with acquire_locks(left, right):
            random_sleep(5, 10)
    else:
        with acquire_locks(right, left):
            random_sleep(5, 10)

# -------------------- Deadlock Orchestrator --------------------

def create_deadlock_scenario(tid, scenario_type):
    global DEADLOCK_COUNTER
    
    try:
        if scenario_type == 'classic':
            classic_deadlock(tid)
        elif scenario_type == 'circular':
            circular_deadlock(tid)
        elif scenario_type == 'nested':
            nested_deadlock(tid)
        elif scenario_type == 'chain':
            chain_deadlock(tid)
        elif scenario_type == 'resource':
            resource_deadlock(tid)
        elif scenario_type == 'philosophers':
            dining_philosophers(tid)
        else:
            scenarios = [classic_deadlock, circular_deadlock, nested_deadlock, 
                        chain_deadlock, resource_deadlock, dining_philosophers]
            random.choice(scenarios)(tid)
            
    except Exception:
        for lock in locks:
            try:
                if lock.locked():
                    lock.release()
            except:
                pass

# -------------------- Worker Threads --------------------

def worker_deadlock():
    global RUNNING, DEADLOCK_COUNTER
    
    tid = threading.get_ident() % 1000
    scenario = DEADLOCK_TYPES[tid % len(DEADLOCK_TYPES)]
    
    while RUNNING:
        try:
            DEADLOCK_COUNTER += 1
            
            if tid % 2 == 0:
                scenario = random.choice(['classic', 'nested', 'philosophers'])
            else:
                scenario = random.choice(['circular', 'chain', 'resource'])
            
            create_deadlock_scenario(tid, scenario)
            time.sleep(random.uniform(0.1, 0.5))
            
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(1)
            continue

# -------------------- Monitoring Thread --------------------

def monitoring_thread():
    global DEADLOCK_COUNTER, RUNNING
    
    last_count = 0
    
    while RUNNING:
        time.sleep(2)
        
        if DEADLOCK_COUNTER == last_count:
            t = threading.Thread(target=worker_deadlock, daemon=True)
            t.start()
        
        last_count = DEADLOCK_COUNTER

# -------------------- Signal Handler --------------------

def signal_handler(sig, frame):
    global RUNNING
    RUNNING = False
    for lock in locks:
        try:
            if lock.locked():
                lock.release()
        except:
            pass
    sys.exit(0)

# -------------------- Main --------------------

def main():
    global RUNNING
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGCONT, signal_handler)
    
    # Start worker threads
    threads = []
    for i in range(8):
        t = threading.Thread(target=worker_deadlock, daemon=True)
        t.start()
        threads.append(t)
    
    # Start monitoring thread
    monitor = threading.Thread(target=monitoring_thread, daemon=True)
    monitor.start()
    
    # Keep main thread alive
    try:
        while RUNNING:
            time.sleep(1)
            
            if random.random() < 0.1:
                t = threading.Thread(target=worker_deadlock, daemon=True)
                t.start()
                
            if random.random() < 0.05:
                for lock in locks:
                    try:
                        if lock.locked():
                            lock.release()
                    except:
                        pass
                        
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())