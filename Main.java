import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Main {
    
    // -------------------- Locks --------------------
    private static final Lock lockA = new ReentrantLock();
    private static final Lock lockB = new ReentrantLock();
    private static final Lock lockC = new ReentrantLock();
    private static final Lock lockD = new ReentrantLock();
    
    // -------------------- Deadlock scenarios --------------------
    
    /**
     * Classic AB-BA deadlock between two threads
     */
    private static void classicDeadlock() {
        long tid = Thread.currentThread().getId();
        
        if (tid % 2 == 0) {
            // Thread 1: Acquire A, then B
            System.out.println("Thread " + Thread.currentThread().getName() + ": Acquiring A");
            lockA.lock();
            System.out.println("Thread " + Thread.currentThread().getName() + ": Acquired A, sleeping...");
            
            try {
                Thread.sleep(100); // Give other thread time to acquire B
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            
            System.out.println("Thread " + Thread.currentThread().getName() + ": Trying to acquire B (will deadlock)");
            lockB.lock(); // This will deadlock!
            System.out.println("Thread " + Thread.currentThread().getName() + ": Acquired B (shouldn't reach here)");
            
            lockB.unlock();
            lockA.unlock();
        } else {
            // Thread 2: Acquire B, then A
            System.out.println("Thread " + Thread.currentThread().getName() + ": Acquiring B");
            lockB.lock();
            System.out.println("Thread " + Thread.currentThread().getName() + ": Acquired B, sleeping...");
            
            try {
                Thread.sleep(100); // Give other thread time to acquire A
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            
            System.out.println("Thread " + Thread.currentThread().getName() + ": Trying to acquire A (will deadlock)");
            lockA.lock(); // This will deadlock!
            System.out.println("Thread " + Thread.currentThread().getName() + ": Acquired A (shouldn't reach here)");
            
            lockA.unlock();
            lockB.unlock();
        }
    }
    
    /**
     * Circular deadlock between 4 threads and 4 locks
     */
    private static void circularDeadlock() {
        int threadNum = Integer.parseInt(Thread.currentThread().getName().replace("Thread-", "")) % 4;
        
        try {
            switch (threadNum) {
                case 0:
                    System.out.println("Thread " + Thread.currentThread().getName() + ": A->B->C->D");
                    lockA.lock();
                    Thread.sleep(50);
                    lockB.lock();
                    Thread.sleep(50);
                    lockC.lock();
                    Thread.sleep(50);
                    lockD.lock(); // Will deadlock!
                    System.out.println("Thread " + Thread.currentThread().getName() + ": Got all locks! (unlikely)");
                    lockD.unlock();
                    lockC.unlock();
                    lockB.unlock();
                    lockA.unlock();
                    break;
                    
                case 1:
                    System.out.println("Thread " + Thread.currentThread().getName() + ": B->C->D->A");
                    lockB.lock();
                    Thread.sleep(50);
                    lockC.lock();
                    Thread.sleep(50);
                    lockD.lock();
                    Thread.sleep(50);
                    lockA.lock(); // Will deadlock!
                    System.out.println("Thread " + Thread.currentThread().getName() + ": Got all locks! (unlikely)");
                    lockA.unlock();
                    lockD.unlock();
                    lockC.unlock();
                    lockB.unlock();
                    break;
                    
                case 2:
                    System.out.println("Thread " + Thread.currentThread().getName() + ": C->D->A->B");
                    lockC.lock();
                    Thread.sleep(50);
                    lockD.lock();
                    Thread.sleep(50);
                    lockA.lock();
                    Thread.sleep(50);
                    lockB.lock(); // Will deadlock!
                    System.out.println("Thread " + Thread.currentThread().getName() + ": Got all locks! (unlikely)");
                    lockB.unlock();
                    lockA.unlock();
                    lockD.unlock();
                    lockC.unlock();
                    break;
                    
                case 3:
                    System.out.println("Thread " + Thread.currentThread().getName() + ": D->A->B->C");
                    lockD.lock();
                    Thread.sleep(50);
                    lockA.lock();
                    Thread.sleep(50);
                    lockB.lock();
                    Thread.sleep(50);
                    lockC.lock(); // Will deadlock!
                    System.out.println("Thread " + Thread.currentThread().getName() + ": Got all locks! (unlikely)");
                    lockC.unlock();
                    lockB.unlock();
                    lockA.unlock();
                    lockD.unlock();
                    break;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // -------------------- Simple guaranteed deadlock --------------------
    
    public static void guaranteedDeadlock() {
        final Object lock1 = new Object();
        final Object lock2 = new Object();
        
        Thread t1 = new Thread(() -> {
            synchronized(lock1) {
                System.out.println("Thread 1: Holding lock 1...");
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                System.out.println("Thread 1: Waiting for lock 2...");
                synchronized(lock2) {
                    System.out.println("Thread 1: Got both locks! (won't happen)");
                }
            }
        });
        
        Thread t2 = new Thread(() -> {
            synchronized(lock2) {
                System.out.println("Thread 2: Holding lock 2...");
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                System.out.println("Thread 2: Waiting for lock 1...");
                synchronized(lock1) {
                    System.out.println("Thread 2: Got both locks! (won't happen)");
                }
            }
        });
        
        t1.start();
        t2.start();
        
        // Wait for deadlock to occur
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // Check for deadlock
        checkForDeadlocks();
    }
    
    // -------------------- Main --------------------
    
    public static void main(String[] args) {
        System.out.println("=== STARTING DEADLOCK SIMULATION ===");
        System.out.println("This program will create guaranteed deadlocks.");
        System.out.println("It will run for 20 seconds, then check for deadlocks.\n");
        
        // First, demonstrate a simple guaranteed deadlock
        System.out.println("1. Demonstrating simple AB-BA deadlock:");
        guaranteedDeadlock();
        
        System.out.println("\n2. Starting multiple thread deadlock simulation:");
        
        // Create threads that will definitely deadlock
        Thread[] threads = new Thread[4];
        
        for (int i = 0; i < 4; i++) {
            final int threadId = i;
            threads[i] = new Thread(() -> {
                System.out.println("Worker " + threadId + " started");
                while (!Thread.currentThread().isInterrupted()) {
                    classicDeadlock();
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
                System.out.println("Worker " + threadId + " interrupted");
            }, "Thread-" + i);
            threads[i].setDaemon(false); // Non-daemon threads
        }
        
        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }
        
        // Let threads run for 10 seconds to create deadlocks
        System.out.println("\nThreads running for 10 seconds...");
        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        System.out.println("\nChecking for deadlocks...");
        checkForDeadlocks();
        
        System.out.println("\nInterrupting threads...");
        for (Thread thread : threads) {
            thread.interrupt();
        }
        
        // Wait for threads to finish
        for (Thread thread : threads) {
            try {
                thread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        System.out.println("\n=== PROGRAM COMPLETE ===");
    }
    
    private static void checkForDeadlocks() {
        try {
            java.lang.management.ThreadMXBean mxBean = 
                java.lang.management.ManagementFactory.getThreadMXBean();
            
            long[] deadlockedThreads = mxBean.findDeadlockedThreads();
            if (deadlockedThreads != null && deadlockedThreads.length > 0) {
                System.out.println("\n!!! DEADLOCK DETECTED !!!");
                System.out.println(deadlockedThreads.length + " threads are deadlocked:");
                
                for (long threadId : deadlockedThreads) {
                    java.lang.management.ThreadInfo threadInfo = mxBean.getThreadInfo(threadId);
                    System.out.println("  - Thread ID: " + threadId + 
                                     ", Name: " + threadInfo.getThreadName() +
                                     ", State: " + threadInfo.getThreadState());
                    
                    // Print lock information
                    System.out.println("    Waiting for lock: " + threadInfo.getLockName());
                    System.out.println("    Lock held by: " + threadInfo.getLockOwnerName());
                }
            } else {
                System.out.println("No deadlocks detected (yet).");
            }
        } catch (Exception e) {
            System.out.println("Error checking for deadlocks: " + e.getMessage());
        }
    }
}
