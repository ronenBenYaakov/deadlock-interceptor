import java.util.concurrent.locks.*;

public class Main {
    static final Lock A = new ReentrantLock();
    static final Lock B = new ReentrantLock();
    static volatile boolean run = true;
    static int count = 0;
    
    public static void main(String[] args) throws Exception {
        // Thread 1: A -> B
        new Thread(() -> {
            while (run) {
                A.lock();
                try { Thread.sleep(10); } catch (Exception e) {}
                B.lock();
                count++;
                B.unlock();
                A.unlock();
            }
        }).start();
        
        // Thread 2: B -> A  
        new Thread(() -> {
            while (run) {
                B.lock();
                try { Thread.sleep(10); } catch (Exception e) {}
                A.lock();
                count++;
                A.unlock();
                B.unlock();
            }
        }).start();
        
        Thread.sleep(10000);
        run = false;
        Thread.sleep(1000);
        System.out.println("Count: " + count);
    }
}