#pragma once

#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <functional>
#include <random>
#include <string>
#include <climits>
#include <vector>
#include <algorithm>
#include <atomic>
#include <cstdarg>

// Helper function to convert address to hex string
inline std::string to_hex_string(uint64_t addr) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%016lx", addr);
    return std::string(buf);
}

/**
 * FutexUnlocker - Unlock futexes in another process
 * 
 * Uses only cross-process methods:
 * 1. process_vm_writev (fastest, Linux 3.2+)
 * 2. /proc/{pid}/mem (fallback)
 * 3. ptrace (most compatible, but slower)
 * 
 * No mprotect usage - that only works on local process memory.
 */
class FutexUnlocker {
private:
    pid_t target_pid;
    bool ptrace_attached;
    std::mt19937 rng;
    bool verbose_enabled;
    int total_attempts;
    int successful_unlocks;
    
    // Read process memory using process_vm_readv
    bool read_process_memory(uint64_t addr, uint32_t& value) {
        struct iovec local_iov = { .iov_base = &value, .iov_len = sizeof(uint32_t) };
        struct iovec remote_iov = { .iov_base = (void*)addr, .iov_len = sizeof(uint32_t) };
        
        ssize_t result = process_vm_readv(target_pid, &local_iov, 1, &remote_iov, 1, 0);
        if (result == sizeof(uint32_t)) {
            return true;
        }
        
        // If process_vm_readv fails, try reading via /proc/mem
        char mem_path[256];
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", target_pid);
        int mem_fd = open(mem_path, O_RDONLY);
        if (mem_fd != -1) {
            ssize_t bytes = pread(mem_fd, &value, sizeof(uint32_t), addr);
            close(mem_fd);
            return (bytes == sizeof(uint32_t));
        }
        
        return false;
    }
    
    // Method 1: process_vm_writev (fastest cross-process method)
    bool unlock_with_process_vm(uint64_t lock_addr) {
        uint32_t zero = 0;
        struct iovec local_iov = { .iov_base = &zero, .iov_len = sizeof(uint32_t) };
        struct iovec remote_iov = { .iov_base = (void*)lock_addr, .iov_len = sizeof(uint32_t) };
        
        ssize_t nwritten = process_vm_writev(target_pid, &local_iov, 1, &remote_iov, 1, 0);
        if (nwritten == sizeof(uint32_t)) {
            wake_futex(lock_addr);
            return true;
        }
        return false;
    }
    
    // Method 2: /proc/{pid}/mem (reliable fallback)
    bool unlock_with_proc_mem(uint64_t lock_addr) {
        char mem_path[256];
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", target_pid);
        
        int mem_fd = open(mem_path, O_RDWR);
        if (mem_fd == -1) {
            return false;
        }
        
        uint32_t zero = 0;
        bool success = (pwrite(mem_fd, &zero, sizeof(uint32_t), lock_addr) == sizeof(uint32_t));
        close(mem_fd);
        
        if (success) {
            wake_futex(lock_addr);
        }
        return success;
    }
    
    // Method 3: ptrace (most compatible, handles permission issues)
    bool unlock_with_ptrace(uint64_t lock_addr) {
        if (!ptrace_attached) {
            // Try to attach with retries
            bool attached = false;
            for (int attempt = 0; attempt < 3; attempt++) {
                errno = 0;
                if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == 0) {
                    int status;
                    waitpid(target_pid, &status, 0);
                    attached = true;
                    break;
                }
                if (errno == EPERM) {
                    // Already attached to us or permission denied
                    // Check if it's already attached to us
                    char path[256];
                    snprintf(path, sizeof(path), "/proc/%d/status", target_pid);
                    FILE* fp = fopen(path, "r");
                    if (fp) {
                        char line[256];
                        int tracer_pid = 0;
                        while (fgets(line, sizeof(line), fp)) {
                            if (strncmp(line, "TracerPid:", 10) == 0) {
                                tracer_pid = atoi(line + 10);
                                break;
                            }
                        }
                        fclose(fp);
                        if (tracer_pid == getpid()) {
                            attached = true;
                            break;
                        }
                    }
                }
                usleep(10000 * (attempt + 1));
            }
            
            if (!attached) {
                return false;
            }
            ptrace_attached = true;
        }
        
        uint32_t zero = 0;
        bool success = false;
        
        // Try writing 4 bytes at once
        errno = 0;
        if (ptrace(PTRACE_POKEDATA, target_pid, (void*)lock_addr, (void*)(uintptr_t)zero) != -1) {
            success = true;
        } else {
            // Fallback: write byte by byte
            for (size_t i = 0; i < sizeof(uint32_t); i++) {
                errno = 0;
                uint8_t byte = ((uint8_t*)&zero)[i];
                if (ptrace(PTRACE_POKEDATA, target_pid, 
                          (void*)(lock_addr + i), 
                          (void*)(uintptr_t)byte) == -1) {
                    if (errno != 0) {
                        success = false;
                        break;
                    }
                }
                success = true;
            }
        }
        
        if (success) {
            wake_futex(lock_addr);
        }
        
        return success;
    }
    
    // Wake up any futex waiters
    void wake_futex(uint64_t lock_addr) {
        long ret = syscall(SYS_futex, (void*)lock_addr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        if (verbose_enabled && ret > 0) {
            printf("    Woke %ld waiters on %s\n", ret, to_hex_string(lock_addr).c_str());
        }
    }
    
    // Check if lock is unlocked
    bool is_unlocked(uint64_t lock_addr) {
        uint32_t value;
        if (read_process_memory(lock_addr, value)) {
            return (value == 0);
        }
        // If we can't read the memory, assume it's locked
        return false;
    }
    
    // Sleep with jitter (exponential backoff)
    void sleep_with_jitter(int base_ms, int attempt) {
        int delay = std::min(base_ms * (1 << attempt), 2000);
        std::uniform_int_distribution<int> dist(-delay/4, delay/4);
        int jitter = dist(rng);
        delay = std::max(1, delay + jitter);
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    }
    
    // Log with timestamp
    void log_verbose(const char* format, ...) {
        if (!verbose_enabled) return;
        
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }

public:
    /**
     * Constructor
     * @param pid Process ID of the target process
     */
    FutexUnlocker(pid_t pid) 
        : target_pid(pid), 
          ptrace_attached(false),
          rng(std::chrono::steady_clock::now().time_since_epoch().count()),
          verbose_enabled(true),
          total_attempts(0),
          successful_unlocks(0) {
    }
    
    /**
     * Destructor - Clean up ptrace attachment
     */
    ~FutexUnlocker() {
        if (ptrace_attached) {
            ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        }
    }
    
    /**
     * Enable/disable verbose output
     */
    void set_verbose(bool enabled) {
        verbose_enabled = enabled;
    }
    
    /**
     * Get statistics
     */
    void get_stats(int& attempts, int& successes) const {
        attempts = total_attempts;
        successes = successful_unlocks;
    }
    
    /**
     * Unlock a single futex with exponential backoff
     * @param lock_addr Address of the futex to unlock
     * @param max_attempts Maximum number of attempts (default: 5)
     * @return true if successfully unlocked, false otherwise
     */
    bool unlock(uint64_t lock_addr, int max_attempts = 5) {
        total_attempts++;
        
        // Check if already unlocked
        if (is_unlocked(lock_addr)) {
            log_verbose("  ✓ %s already unlocked\n", to_hex_string(lock_addr).c_str());
            successful_unlocks++;
            return true;
        }
        
        // Try each method in order with backoff
        for (int attempt = 0; attempt < max_attempts; attempt++) {
            // Method 1: process_vm_writev (fastest)
            if (unlock_with_process_vm(lock_addr) && is_unlocked(lock_addr)) {
                log_verbose("  ✓ Unlocked %s (process_vm, attempt %d)\n", 
                           to_hex_string(lock_addr).c_str(), attempt + 1);
                successful_unlocks++;
                return true;
            }
            
            // Method 2: /proc/mem (reliable)
            if (unlock_with_proc_mem(lock_addr) && is_unlocked(lock_addr)) {
                log_verbose("  ✓ Unlocked %s (/proc/mem, attempt %d)\n", 
                           to_hex_string(lock_addr).c_str(), attempt + 1);
                successful_unlocks++;
                return true;
            }
            
            // Method 3: ptrace (most compatible)
            if (unlock_with_ptrace(lock_addr) && is_unlocked(lock_addr)) {
                log_verbose("  ✓ Unlocked %s (ptrace, attempt %d)\n", 
                           to_hex_string(lock_addr).c_str(), attempt + 1);
                successful_unlocks++;
                return true;
            }
            
            // If not the last attempt, wait and retry
            if (attempt < max_attempts - 1) {
                log_verbose("  ⏳ Retry %d/%d for %s\n", 
                           attempt + 1, max_attempts, to_hex_string(lock_addr).c_str());
                sleep_with_jitter(10, attempt);
            }
        }
        
        log_verbose("  ✗ Failed to unlock %s after %d attempts\n", 
                   to_hex_string(lock_addr).c_str(), max_attempts);
        return false;
    }
    
    /**
     * Unlock multiple futexes with aggressive retry
     * @param lock_addrs Vector of addresses to unlock
     * @param max_attempts Maximum attempts per address
     * @return Number of successfully unlocked futexes
     */
    int unlock_multiple(const std::vector<uint64_t>& lock_addrs, int max_attempts = 5) {
        if (lock_addrs.empty()) {
            log_verbose("  No locks to unlock\n");
            return 0;
        }
        
        log_verbose("  Attempting to unlock %zu locks in process %d\n", 
                    lock_addrs.size(), target_pid);
        
        int success_count = 0;
        int failed_count = 0;
        
        // Try each lock
        for (size_t i = 0; i < lock_addrs.size(); i++) {
            uint64_t addr = lock_addrs[i];
            
            if (verbose_enabled) {
                printf("  [%zu/%zu] Unlocking %s\n", 
                       i + 1, lock_addrs.size(), to_hex_string(addr).c_str());
            }
            
            if (unlock(addr, max_attempts)) {
                success_count++;
            } else {
                failed_count++;
            }
        }
        
        if (verbose_enabled) {
            printf("  Summary: %d unlocked, %d failed out of %zu total\n", 
                   success_count, failed_count, lock_addrs.size());
        }
        
        return success_count;
    }
    
    /**
     * Unlock with aggressive mode - tries harder with more attempts
     */
    int unlock_aggressive(const std::vector<uint64_t>& lock_addrs) {
        return unlock_multiple(lock_addrs, 10);
    }
    
    /**
     * Unlock with fast mode - fewer attempts, less waiting
     */
    int unlock_fast(const std::vector<uint64_t>& lock_addrs) {
        return unlock_multiple(lock_addrs, 3);
    }
    
    /**
     * Check if a lock is currently locked
     */
    bool is_locked(uint64_t lock_addr) {
        return !is_unlocked(lock_addr);
    }
    
    /**
     * Get the current lock value
     */
    bool get_lock_value(uint64_t lock_addr, uint32_t& value) {
        return read_process_memory(lock_addr, value);
    }
    
    /**
     * Force unlock using all methods in parallel (best effort)
     * Tries each method once without retries
     */
    bool unlock_best_effort(uint64_t lock_addr) {
        // Check if already unlocked
        if (is_unlocked(lock_addr)) {
            return true;
        }
        
        // Try all methods once
        if (unlock_with_process_vm(lock_addr) && is_unlocked(lock_addr)) {
            return true;
        }
        if (unlock_with_proc_mem(lock_addr) && is_unlocked(lock_addr)) {
            return true;
        }
        if (unlock_with_ptrace(lock_addr) && is_unlocked(lock_addr)) {
            return true;
        }
        
        return false;
    }
};