public class Main {
    private static final Object lock = new Object();

    public static void main(String[] args) throws Exception {
        long pid = ProcessHandle.current().pid();
        System.out.println("Java Process PID: " + pid);

        Thread t1 = new Thread(() -> {
            synchronized (lock) {
                try {
                    System.out.println("Worker-1 acquired lock, waiting...");
                    lock.wait(); // WAIT on lock
                    System.out.println("Worker-1 resumed!");
                } catch (InterruptedException e) {}
            }
        }, "Worker-1");

        Thread t2 = new Thread(() -> {
            try { Thread.sleep(1000); } catch (InterruptedException e) {}
            synchronized (lock) {
                System.out.println("Worker-2 acquired lock, notifying...");
                lock.notify(); // WAKE Worker-1
            }
        }, "Worker-2");

        t1.start();
        t2.start();

        // Keep main thread alive for 20 seconds so agent can attach
        Thread.sleep(20000);
    }
}
