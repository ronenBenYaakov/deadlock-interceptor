import java.util.concurrent.locks.ReentrantLock;

public class Main {

    // -------------------- Locks --------------------
    static final ReentrantLock lockA = new ReentrantLock();
    static final ReentrantLock lockB = new ReentrantLock();
    static final ReentrantLock lockC = new ReentrantLock();
    static final ReentrantLock lockD = new ReentrantLock();

    // -------------------- Deadlock scenarios --------------------

    // Classic AB–BA deadlock
    static void classicDeadlock() {
        long tid = Thread.currentThread().getId();

        if (tid % 2 == 0) {
            lockA.lock();
            sleep(200);
            lockB.lock();

            lockB.unlock();
            lockA.unlock();
        } else {
            lockB.lock();
            sleep(200);
            lockA.lock();

            lockA.unlock();
            lockB.unlock();
        }
    }

    // Circular deadlock with 4 threads & 4 locks
    static void circularDeadlock() {
        long tid = Thread.currentThread().getId() % 4;

        if (tid == 0) {
            lockA.lock();
            sleep(100);
            lockB.lock();
            sleep(100);
            lockC.lock();
            sleep(100);
            lockD.lock();

            lockD.unlock();
            lockC.unlock();
            lockB.unlock();
            lockA.unlock();

        } else if (tid == 1) {
            lockB.lock();
            sleep(100);
            lockC.lock();
            sleep(100);
            lockD.lock();
            sleep(100);
            lockA.lock();

            lockA.unlock();
            lockD.unlock();
            lockC.unlock();
            lockB.unlock();

        } else if (tid == 2) {
            lockC.lock();
            sleep(100);
            lockD.lock();
            sleep(100);
            lockA.lock();
            sleep(100);
            lockB.lock();

            lockB.unlock();
            lockA.unlock();
            lockD.unlock();
            lockC.unlock();

        } else {
            lockD.lock();
            sleep(100);
            lockA.lock();
            sleep(100);
            lockB.lock();
            sleep(100);
            lockC.lock();

            lockC.unlock();
            lockB.unlock();
            lockA.unlock();
            lockD.unlock();
        }
    }

    // Nested deadlock
    static void nestedDeadlock() {
        Runnable inner1 = () -> {
            lockA.lock();
            sleep(50);
            lockB.lock();

            lockB.unlock();
            lockA.unlock();
        };

        Runnable inner2 = () -> {
            lockB.lock();
            sleep(50);
            lockA.lock();

            lockA.unlock();
            lockB.unlock();
        };

        long tid = Thread.currentThread().getId();
        if (tid % 2 == 0) {
            inner1.run();
        } else {
            inner2.run();
        }
    }

    // -------------------- Worker --------------------
    static void workerDeadlock() {
        while (true) {
            classicDeadlock();
            circularDeadlock();
            nestedDeadlock();
            sleep(100);
        }
    }

    // -------------------- Utils --------------------
    static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {}
    }

    // -------------------- Main --------------------
    public static void main(String[] args) {
        // Start 6 worker threads
        for (int i = 0; i < 6; i++) {
            Thread t = new Thread(Main::workerDeadlock);
            t.setDaemon(true);
            t.start();
        }

        // Keep main thread alive
        while (true) {
            sleep(1000);
        }
    }
}
