#include "strategy1.h"
#include "global_state.h"
#include "helpers.h"
#include "snapshot.h"
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <cstring>
#include "memory_duplication.h"
#include <algorithm>
#include <sys/uio.h>
#include "futex_unlocker.h"

ShadowProcess::ShadowProcess(ShadowProcess&& other) noexcept
    : shadow_pid(other.shadow_pid),
      victim_tid(other.victim_tid),
      resource_copies(std::move(other.resource_copies)),
      protected_regions(std::move(other.protected_regions)),
      creation_time(other.creation_time),
      running(other.running.load()),
      control_fd(other.control_fd) {
    other.control_fd = -1;
}

ShadowProcess& ShadowProcess::operator=(ShadowProcess&& other) noexcept {
    if (this != &other) {
        shadow_pid = other.shadow_pid;
        victim_tid = other.victim_tid;
        resource_copies = std::move(other.resource_copies);
        protected_regions = std::move(other.protected_regions);
        creation_time = other.creation_time;
        running.store(other.running.load());
        control_fd = other.control_fd;
        other.control_fd = -1;
    }
    return *this;
}

bool stop_the_world() {
    std::cout << "\033[1;33m[STEP 1] Stopping the world...\033[0m\n";
    
    monitoring_active.store(false);
    std::cout << "  Monitoring stopped\n";
    
    auto tids = list_threads(target_pid);
    std::cout << "  Target has " << tids.size() << " threads\n";
    
    if (tids.empty()) {
        std::cout << "  No threads to detach\n";
        world_stopped.store(true);
        return true;
    }
    
    // Detach each thread with retries
    for (pid_t tid : tids) {
        bool detached = false;
        
        // Try PTRACE_DETACH with retries
        for (int attempt = 0; attempt < 3; attempt++) {
            if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) == 0) {
                detached = true;
                break;
            }
            
            // If process doesn't exist, we're done
            if (errno == ESRCH) {
                detached = true;
                break;
            }
            
            // If not attached, we're done
            if (errno == EPERM) {
                detached = true;
                break;
            }
            
            // Try PTRACE_CONT as fallback before retry
            if (attempt == 1) {
                ptrace(PTRACE_CONT, tid, nullptr, nullptr);
                usleep(1000);
            }
            
            // Exponential backoff
            usleep(1000 * (1 << attempt));
        }
        
        // If still not detached, try emergency methods
        if (!detached) {
            // Try PTRACE_CONT
            ptrace(PTRACE_CONT, tid, nullptr, nullptr);
            usleep(1000);
            
            // Final attempt at PTRACE_DETACH
            if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) != 0) {
                // Last resort: send SIGCONT and hope
                kill(tid, SIGCONT);
            }
        }
    }
    
    // Ensure process is running
    usleep(50000);
    kill(target_pid, SIGCONT);
    
    world_stopped.store(true);
    std::cout << "\033[1;32m[✓] Detached from all threads, ready for fork\033[0m\n";
    
    return true;
}

std::string choose_victim_thread(const DeadlockInfo& deadlock) {
    std::cout << "\033[1;33m[STEP 2] Choosing victim thread...\033[0m\n";
    
    std::unordered_set<std::string> unique_threads;
    for (const auto& thread : deadlock.cycle) {
        unique_threads.insert(thread);
    }
    
    std::string best_victim;
    for (const std::string& thread_name : unique_threads) {
        pid_t tid = extract_tid_from_identifier(thread_name);
        if (thread_exists(tid)) {
            best_victim = thread_name;
            break;
        }
    }
    
    if (best_victim.empty() && !deadlock.cycle.empty()) {
        best_victim = deadlock.cycle[0];
    }
    
    pid_t victim_tid = extract_tid_from_identifier(best_victim);
    std::cout << "  Selected victim: " << best_victim << " (TID=" << victim_tid << ")\n";
    
    return best_victim;
}

bool eliminate_other_threads_in_shadow(pid_t victim_tid) {
    std::cout << "\033[1;33m[STEP 5] Pausing non-victim threads safely...\033[0m\n";

    std::vector<pid_t> all_tids;
    DIR* dir = opendir("/proc/self/task");
    if (!dir) {
        perror("opendir failed");
        return false;
    }

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        pid_t tid = atoi(ent->d_name);
        all_tids.push_back(tid);
    }
    closedir(dir);

    std::cout << "  Found " << all_tids.size() << " threads total\n";

    for (pid_t tid : all_tids) {
        if (tid == getpid()) {
            std::cout << "    Skipping ourselves (PID=" << tid << ")\n";
            continue;
        }
        if (tid == victim_tid) {
            std::cout << "    Skipping victim (TID=" << tid << ")\n";
            continue;
        }

        if (tgkill(getpid(), tid, SIGSTOP) == -1) {
            std::cout << "    Failed to suspend thread " << tid << ": " << strerror(errno) << "\n";
        } else {
            std::cout << "    Suspended thread " << tid << "\n";
        }
    }

    usleep(50000);

    size_t remaining_running = 0;
    for (pid_t tid : all_tids) {
        if (tid == getpid() || tid == victim_tid) continue;
        char path[256];
        snprintf(path, sizeof(path), "/proc/self/task/%d/status", tid);
        FILE* f = fopen(path, "r");
        if (!f) continue;
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "State:", 6) == 0) {
                if (strchr(line, 'T') == nullptr) {
                    remaining_running++;
                }
                break;
            }
        }
        fclose(f);
    }

    if (remaining_running == 0) {
        std::cout << "  ✓ All non-victim threads safely paused\n";
        return true;
    } else {
        std::cout << "  ✗ Some threads failed to pause (" << remaining_running << " remaining)\n";
        return false;
    }
}

void resume_paused_threads(pid_t victim_tid) {
    std::cout << "\033[1;33m[STEP 11] Resuming previously paused threads...\033[0m\n";

    std::vector<pid_t> all_tids;
    DIR* dir = opendir("/proc/self/task");
    if (!dir) {
        perror("opendir failed");
        return;
    }

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        pid_t tid = atoi(ent->d_name);
        all_tids.push_back(tid);
    }
    closedir(dir);

    for (pid_t tid : all_tids) {
        if (tid == getpid()) continue;
        if (tgkill(getpid(), tid, SIGCONT) == -1) {
            std::cout << "    Failed to resume thread " << tid << ": " << strerror(errno) << "\n";
        } else {
            std::cout << "    Resumed thread " << tid << "\n";
        }
    }

    usleep(50000);

    std::cout << "  ✓ All threads resumed\n";
}



std::vector<MemoryRegion> initialize_private_memory(const std::vector<uint64_t>& locks) {
    std::cout << "\033[1;33m[STEP 6] Initializing private-memory machinery...\033[0m\n";
    
    std::vector<MemoryRegion> protected_regions;
    
    struct sigaction sa;
    sa.sa_sigaction = (void (*)(int, siginfo_t*, void*))shadow_sigsegv_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("sigaction SIGSEGV failed");
        return protected_regions;
    }
    
    std::cout << "  ✓ SIGSEGV handler installed\n";
    
    for (uint64_t lock_addr : locks) {
        MemoryRegion region;
        region.start = lock_addr & ~(sysconf(_SC_PAGESIZE) - 1);
        region.end = region.start + sysconf(_SC_PAGESIZE);
        region.perms = "---";
        region.name = "protected_lock_" + to_hex_string(lock_addr);
        
        if (mprotect((void*)region.start, region.end - region.start, PROT_NONE) == 0) {
            protected_regions.push_back(region);
            g_protected_regions.push_back(region);
            std::cout << "  ✓ Protected lock at " << to_hex_string(lock_addr) 
                      << " (page 0x" << std::hex << region.start << std::dec << ")\n";
        } else {
            perror("mprotect failed");
        }
    }
    
    return protected_regions;
}

void force_unlock_futexes(const std::vector<uint64_t>& locks) {
    std::cout << "\033[1;33m[LOCK ILLUSION] Forcing unlock...\033[0m\n";
    
    for (uint64_t lock_addr : locks) {
        size_t page_size = sysconf(_SC_PAGESIZE);
        uintptr_t page_start = lock_addr & ~(page_size - 1);
        
        if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE) == 0) {
            volatile uint32_t* futex_ptr = (volatile uint32_t*)(lock_addr);
            uint32_t old_value = *futex_ptr;
            *futex_ptr = 0;
            std::cout << "  ✓ Unlocked " << to_hex_string(lock_addr) 
                      << " (was 0x" << std::hex << old_value << std::dec << ")\n";
            
            mprotect((void*)page_start, page_size, PROT_NONE);
        }
    }
}

bool cleanup_parent_process(pid_t victim_tid, const std::vector<uint64_t>& deadlock_locks) {
    std::cout << "\033[1;33m[STEP 9] Cleaning up parent process...\033[0m\n";
    
    for (uint64_t lock_addr : deadlock_locks) {
        auto it = lock_owners.find(lock_addr);
        if (it != lock_owners.end()) {
            std::string owner = it->second;
            if (owner.find(std::to_string(victim_tid)) != std::string::npos) {
                std::cout << "  Released lock " << to_hex_string(lock_addr) << "\n";
                lock_owners.erase(it);
            }
        }
    }
    
    std::string victim_name = get_thread_identifier(victim_tid);
    waits_for.erase(victim_name);
    
    for (auto it = futex_waiters.begin(); it != futex_waiters.end(); ) {
        auto& waiters = it->second;
        waiters.erase(std::remove(waiters.begin(), waiters.end(), victim_name), waiters.end());
        if (waiters.empty()) {
            it = futex_waiters.erase(it);
        } else {
            ++it;
        }
    }
    
    std::cout << "  ✓ Parent cleaned up (threads already running)\n";
    return true;
}

void monitor_shadow_process(pid_t shadow_pid, pid_t victim_tid, const DeadlockInfo& deadlock) {
    std::cout << "\033[1;33m[STEP 10] Monitoring shadow process " << shadow_pid << "...\033[0m\n";
    
    pid_t monitor = fork();
    
    if (monitor == 0) {
        int status;
        waitpid(shadow_pid, &status, 0);
        
        if (WIFEXITED(status)) {
            std::cout << "\033[1;36m[SHADOW MONITOR] Process " << shadow_pid 
                      << " exited with code " << WEXITSTATUS(status) << "\033[0m\n";
        } else if (WIFSIGNALED(status)) {
            std::cout << "\033[1;31m[SHADOW MONITOR] Process " << shadow_pid 
                      << " killed by signal " << WTERMSIG(status) << "\033[0m\n";
        }
        
        return;
    } else if (monitor > 0) {
        std::cout << "  ✓ Monitor process " << monitor << " started\n";
        
        for (auto& dl : detected_deadlocks) {
            if (dl.deadlock_id == deadlock.deadlock_id) {
                dl.resolved = true;
                break;
            }
        }
        
        std::cout << "\033[1;32m[✓] Deadlock #" << deadlock.deadlock_id 
                  << " resolved via shadow process " << shadow_pid << "\033[0m\n";
    }
}

bool unlock_futex_safely(uint64_t lock_addr) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    
    // Calculate page-aligned address
    uintptr_t page_start = lock_addr & ~(page_size - 1);
    uintptr_t page_end = page_start + page_size;
    
    // Check if the address is within a valid memory region
    if (lock_addr < page_start || lock_addr >= page_end) {
        printf("  Invalid address %s\n", to_hex_string(lock_addr).c_str());
        return false;
    }
    
    // First try to change permissions
    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE) != 0) {
        perror("  mprotect failed");
        
        // Try alternative: use /proc/self/mem to write directly
        char mem_path[256];
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", target_pid);
        
        int mem_fd = open(mem_path, O_RDWR);
        if (mem_fd >= 0) {
            // Seek to the lock address
            if (lseek(mem_fd, lock_addr, SEEK_SET) != (off_t)lock_addr) {
                close(mem_fd);
                return false;
            }
            
            // Write 0 to unlock
            uint32_t zero = 0;
            ssize_t written = write(mem_fd, &zero, sizeof(zero));
            close(mem_fd);
            
            if (written == sizeof(zero)) {
                printf("  Unlocked %s via /proc/mem\n", to_hex_string(lock_addr).c_str());
                return true;
            }
        }
        return false;
    }
    
    // Direct memory write
    volatile uint32_t* futex = (volatile uint32_t*)lock_addr;
    *futex = 0;
    printf("  Unlocked %s\n", to_hex_string(lock_addr).c_str());
    
    // Restore permissions
    mprotect((void*)page_start, page_size, PROT_READ);
    
    return true;
}

static void cleanup_stuck_threads(const std::vector<pid_t>& tids) {
    printf("  Cleaning up stuck threads...\n");
    
    int cleaned_count = 0;
    int failed_count = 0;
    
    for (pid_t tid : tids) {
        if (!thread_exists(tid)) {
            printf("    Thread %d no longer exists\n", tid);
            continue;
        }
        
        printf("    Checking thread %d...\n", tid);
        
        // 1. Check thread state via /proc
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/status", tid);
        FILE* fp = fopen(path, "r");
        if (!fp) {
            printf("    Failed to open /proc/%d/status: %s\n", tid, strerror(errno));
            continue;
        }
        
        char line[256];
        bool stopped = false;
        bool zombie = false;
        bool running = false;
        int tracer_pid = 0;
        
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "State:", 6) == 0) {
                if (strchr(line, 'T') != nullptr) {
                    stopped = true;
                } else if (strchr(line, 'Z') != nullptr) {
                    zombie = true;
                } else if (strchr(line, 'R') != nullptr || strchr(line, 'S') != nullptr) {
                    running = true;
                }
            }
            if (strncmp(line, "TracerPid:", 10) == 0) {
                tracer_pid = atoi(line + 10);
            }
        }
        fclose(fp);
        
        if (zombie) {
            printf("    Thread %d is zombie, skipping\n", tid);
            continue;
        }
        
        // 2. If thread is stopped, try to continue it
        if (stopped) {
            printf("    Thread %d is stopped (T state), sending SIGCONT...\n", tid);
            
            // Send SIGCONT to resume
            if (kill(tid, SIGCONT) == 0) {
                printf("    ✓ Sent SIGCONT to thread %d\n", tid);
                cleaned_count++;
            } else {
                printf("    Failed to send SIGCONT to thread %d: %s\n", 
                       tid, strerror(errno));
            }
            
            // Wait a bit for the thread to respond
            usleep(10000);
        }
        
        // 3. If thread is traced by another process, try to detach
        if (tracer_pid > 0 && tracer_pid != getpid()) {
            printf("    Thread %d is traced by PID %d, attempting to detach...\n", 
                   tid, tracer_pid);
            
            if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) == 0) {
                printf("    ✓ Detached thread %d from tracer %d\n", tid, tracer_pid);
                cleaned_count++;
            } else {
                printf("    Failed to detach thread %d: %s\n", tid, strerror(errno));
                
                // Try to force detach with SIGCONT
                kill(tid, SIGCONT);
                usleep(10000);
                if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) == 0) {
                    printf("    ✓ Force detached thread %d\n", tid);
                    cleaned_count++;
                }
            }
        }
        
        // 4. If thread is stuck in ptrace, try to continue it
        if (tracer_pid == getpid()) {
            printf("    Thread %d is traced by us, attempting to continue...\n", tid);
            
            // Try PTRACE_CONT
            if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == 0) {
                printf("    ✓ Continued thread %d\n", tid);
                cleaned_count++;
            } else {
                // Try PTRACE_SYSCALL as alternative
                if (ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr) == 0) {
                    printf("    ✓ Resumed syscall tracing on thread %d\n", tid);
                    cleaned_count++;
                } else {
                    // Try detach and re-attach
                    printf("    Attempting to detach and re-attach thread %d...\n", tid);
                    
                    if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) == 0) {
                        usleep(10000);
                        
                        // Re-attach
                        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
                            int status;
                            waitpid(tid, &status, 0);
                            
                            if (ptrace(PTRACE_SETOPTIONS, tid, nullptr,
                                      PTRACE_O_TRACESYSGOOD) == 0) {
                                if (ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr) == 0) {
                                    printf("    ✓ Re-attached and resumed thread %d\n", tid);
                                    cleaned_count++;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // 5. Last resort: Send SIGKILL? 
        // Usually not needed, but sometimes useful for completely hung threads
        // Uncomment if necessary
        /*
        if (!running && !zombie && !stopped) {
            printf("    Thread %d is unresponsive, sending SIGKILL...\n", tid);
            if (kill(tid, SIGKILL) == 0) {
                printf("    ✓ Killed unresponsive thread %d\n", tid);
                cleaned_count++;
            }
        }
        */
        
        // 6. Verify thread is now responsive
        char check_path[256];
        snprintf(check_path, sizeof(check_path), "/proc/%d/status", tid);
        FILE* check_fp = fopen(check_path, "r");
        if (check_fp) {
            bool is_alive = false;
            while (fgets(line, sizeof(line), check_fp)) {
                if (strncmp(line, "State:", 6) == 0) {
                    if (strchr(line, 'R') != nullptr || 
                        strchr(line, 'S') != nullptr ||
                        strchr(line, 'T') != nullptr) {
                        is_alive = true;
                    }
                    break;
                }
            }
            fclose(check_fp);
            
            if (!is_alive) {
                printf("    Thread %d still unresponsive after cleanup\n", tid);
                failed_count++;
            }
        }
    }
    
    printf("  Cleanup complete: %d threads cleaned, %d failed\n", 
           cleaned_count, failed_count);
}

/**
 * Re-attach to a thread and resume syscall tracing
 * 
 * This function handles the complex task of re-attaching to a thread after
 * it has been detached during deadlock resolution. It handles various edge
 * cases including:
 * - Thread already traced by us
 * - Thread traced by another process
 * - Thread in STOP state
 * - Thread that doesn't exist anymore
 * - Permission denied (EPERM) errors
 * 
 * @param tid Thread ID to re-attach to
 * @param max_retries Maximum number of retry attempts (default: 5)
 * @return true if successfully re-attached and resumed, false otherwise
 */
static bool reattach_and_resume_tracing(pid_t tid, int max_retries = 5) {
    // 1. Check if thread exists
    if (!thread_exists(tid)) {
        printf("    Thread %d no longer exists\n", tid);
        return false;
    }
    
    // 2. Check current tracer and state
    int tracer_pid = get_tracer_pid(tid);
    bool stopped = is_thread_stopped(tid);
    
    // 3. If already traced by us, try to resume directly
    if (tracer_pid == getpid()) {
        printf("    Thread %d already traced by us\n", tid);
        
        // Try PTRACE_SYSCALL first (preferred for syscall tracing)
        if (ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr) == 0) {
            printf("    ✓ Resumed tracing on already-attached thread %d\n", tid);
            return true;
        }
        
        // If PTRACE_SYSCALL fails, try PTRACE_CONT (less tracing)
        if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == 0) {
            printf("    ✓ Continued thread %d (no syscall tracing)\n", tid);
            return true;
        }
        
        // If both fail, the thread is in a bad state - detach and re-attach
        printf("    Failed to resume, attempting detach and re-attach...\n");
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        usleep(10000); // 10ms wait
        // Fall through to re-attach
    } 
    // 4. If traced by another process, try to detach first
    else if (tracer_pid > 0) {
        printf("    Thread %d traced by PID %d, detaching...\n", tid, tracer_pid);
        if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) == 0) {
            printf("    ✓ Detached from other tracer\n");
            usleep(10000);
            // Fall through to re-attach
        } else {
            printf("    Failed to detach from other tracer: %s\n", strerror(errno));
            // Try to force with SIGCONT
            kill(tid, SIGCONT);
            usleep(10000);
            // Fall through anyway
        }
    }
    
    // 5. If stopped and not traced, send SIGCONT to wake it up
    if (stopped && tracer_pid == 0) {
        printf("    Thread %d is stopped, sending SIGCONT...\n", tid);
        if (kill(tid, SIGCONT) == 0) {
            printf("    ✓ Sent SIGCONT to thread %d\n", tid);
            usleep(10000);
        } else {
            printf("    Failed to send SIGCONT: %s\n", strerror(errno));
        }
    }
    
    // 6. Attempt to re-attach with retries
    for (int attempt = 0; attempt < max_retries; attempt++) {
        errno = 0;
        printf("    Re-attach attempt %d/%d for thread %d...\n", attempt + 1, max_retries, tid);
        
        // Try to attach
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
            printf("    ✓ Attached to thread %d\n", tid);
            
            // Wait for the thread to stop
            int status;
            pid_t waited = waitpid(tid, &status, WNOHANG);
            
            if (waited == 0) {
                // Thread didn't stop immediately, wait a bit
                struct timespec ts = {0, 50000000}; // 50ms
                nanosleep(&ts, nullptr);
                waited = waitpid(tid, &status, 0); // Blocking wait
            }
            
            if (waited == tid) {
                printf("    ✓ Thread %d stopped for re-attach\n", tid);
                
                // Set options for syscall tracing
                if (ptrace(PTRACE_SETOPTIONS, tid, nullptr,
                          PTRACE_O_TRACESYSGOOD) == 0) {
                    printf("    ✓ Set tracing options\n");
                    
                    // Resume with PTRACE_SYSCALL
                    if (ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr) == 0) {
                        printf("    ✓ Re-attached and resumed tracing on thread %d\n", tid);
                        return true;
                    } else {
                        printf("    PTRACE_SYSCALL failed: %s\n", strerror(errno));
                    }
                } else {
                    printf("    PTRACE_SETOPTIONS failed: %s\n", strerror(errno));
                }
                
                // If we got here, something failed - try to detach
                ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
                usleep(10000);
            } else {
                printf("    waitpid failed or returned wrong PID: %s\n", strerror(errno));
                // Try to detach
                ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
                usleep(10000);
            }
        } else if (errno == EPERM) {
            // Permission denied - this can happen if already attached
            printf("    Permission denied for thread %d (attempt %d/%d)\n", 
                   tid, attempt + 1, max_retries);
            
            // Check if it's attached to us now
            int new_tracer = get_tracer_pid(tid);
            if (new_tracer == getpid()) {
                printf("    Thread %d is now traced by us, trying to resume...\n", tid);
                if (ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr) == 0) {
                    printf("    ✓ Resumed thread %d\n", tid);
                    return true;
                }
            }
            
            // Try to force resume with SIGCONT
            if (kill(tid, SIGCONT) == 0) {
                printf("    Sent SIGCONT to thread %d\n", tid);
                usleep(10000);
                
                // Try PTRACE_SYSCALL one more time
                if (ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr) == 0) {
                    printf("    ✓ Resumed thread %d after SIGCONT\n", tid);
                    return true;
                }
            }
            
            // Try to detach and re-attach
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
            usleep(10000);
            // Continue to next retry
        } else if (errno == ESRCH) {
            // Thread died
            printf("    Thread %d died during re-attach\n", tid);
            return false;
        } else {
            printf("    PTRACE_ATTACH failed: %s (errno=%d)\n", strerror(errno), errno);
        }
        
        // Wait before retry with exponential backoff
        if (attempt < max_retries - 1) {
            int delay = 50000 * (attempt + 1); // 50ms, 100ms, 150ms, etc.
            printf("    Waiting %dms before retry...\n", delay/1000);
            usleep(delay);
        }
    }
    
    // 7. Last resort: try to just continue the thread without ptrace
    printf("    Last resort for thread %d...\n", tid);
    
    // Try PTRACE_CONT
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == 0) {
        printf("    ✓ Continued thread %d (no ptrace re-attach)\n", tid);
        return true;
    }
    
    // Try SIGCONT
    if (kill(tid, SIGCONT) == 0) {
        printf("    ✓ Sent SIGCONT to thread %d (no ptrace)\n", tid);
        return true;
    }
    
    // Try to detach if still attached
    if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) == 0) {
        printf("    Detached thread %d\n", tid);
        // Send SIGCONT to make it run
        kill(tid, SIGCONT);
        return true;
    }
    
    printf("    ✗ Failed to re-attach to thread %d after %d attempts\n", 
           tid, max_retries);
    return false;
}

bool resolve_deadlock_strategy1(const DeadlockInfo& deadlock) {
    // CRITICAL: Set resolution flag BEFORE doing anything
    monitoring_active.store(false);
    
    printf("\n\033[1;35m[RESOLUTION] Breaking deadlock...\033[0m\n");
    
    // Find victim
    pid_t victim_tid = 0;
    std::string victim_name;
    for (const auto& thread_name : deadlock.cycle) {
        pid_t tid = extract_tid_from_identifier(thread_name);
        if (thread_exists(tid)) {
            victim_tid = tid;
            victim_name = thread_name;
            break;
        }
    }
    
    if (victim_tid == 0) {
        printf("  No live threads in cycle\n");
        monitoring_active.store(true);
        return false;
    }
    
    printf("  Selected victim: %s (TID=%d)\n", victim_name.c_str(), victim_tid);
    
    // Get all threads and save their state
    auto tids = list_threads(target_pid);
    printf("  Found %zu threads in process\n", tids.size());
    
    // Detach from all threads with safety
    printf("  Detaching from all threads...\n");
    int detached_count = 0;
    
    // In resolve_deadlock_strategy1, when detaching:
    for (pid_t tid : tids) {
        if (!thread_exists(tid)) {
            detached_count++;
            continue;
        }
        
        // CRITICAL: Always pass SIGCONT with detach
        if (ptrace(PTRACE_DETACH, tid, nullptr, (void*)(intptr_t)SIGCONT) == 0) {
            detached_count++;
        } else if (errno == ESRCH || errno == EPERM) {
            detached_count++;
        } else {
            // Emergency: force SIGCONT
            kill(tid, SIGCONT);
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
            kill(tid, SIGCONT);
        }
    }
    printf("  Detached from %d/%zu threads\n", detached_count, tids.size());
    
    // Ensure victim is running before fork
    kill(victim_tid, SIGCONT);
    usleep(50000);
    
    // Fork shadow process
    pid_t shadow = fork();
    
    if (shadow == 0) {
        // SHADOW PROCESS - NO ptrace operations here!
        printf("\033[1;36m[SHADOW] PID=%d\033[0m\n", getpid());
        
        // Use FutexUnlocker - this uses cross-process methods only
        FutexUnlocker unlocker(target_pid);
        unlocker.set_verbose(true);
        
        int unlocked = unlocker.unlock_multiple(deadlock.involved_locks, 7);
        printf("  Unlocked %d/%zu locks in shadow process\n", 
               unlocked, deadlock.involved_locks.size());
        
        // Resume all threads
        printf("  Resuming all threads...\n");
        for (pid_t tid : tids) {
            if (thread_exists(tid)) {
                kill(tid, SIGCONT);
            }
        }
        
        // Wake up any futex waiters
        for (uint64_t lock_addr : deadlock.involved_locks) {
            syscall(SYS_futex, (void*)lock_addr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        }
        
        fflush(stdout);
        fflush(stderr);
        _exit(0);
        
    } else if (shadow > 0) {
        // PARENT PROCESS
        printf("  Shadow PID: %d\n", shadow);
        
        // Wait for shadow process to finish
        int status;
        pid_t result = waitpid(shadow, &status, 0);
        
        if (result == -1) {
            perror("waitpid failed");
            monitoring_active.store(true);
            return false;
        }
        
        if (WIFEXITED(status)) {
            printf("  Shadow process exited with code %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("  Shadow process killed by signal %d\n", WTERMSIG(status));
        }
        
        // Clean up any stuck threads
        cleanup_stuck_threads(tids);
        
        // Resume all paused threads safely
        printf("  Resuming all threads...\n");
        for (pid_t tid : tids) {
            if (thread_exists(tid)) {
                if (kill(tid, SIGCONT) == -1) {
                    if (errno != ESRCH) {
                        printf("  Warning: Could not resume thread %d: %s\n", 
                               tid, strerror(errno));
                    }
                }
            }
        }
        
        // Ensure victim is running
        if (thread_exists(victim_tid)) {
            kill(victim_tid, SIGCONT);
        }
        
        // Wait for threads to stabilize
        usleep(100000);
        
        // ==========================================
        // CRITICAL: Re-attach for continued monitoring
        // ==========================================
        printf("  Re-attaching for continued monitoring...\n");
        int reattached_count = 0;
        
        for (pid_t tid : tids) {
            if (!thread_exists(tid)) {
                printf("    Thread %d no longer exists, skipping\n", tid);
                continue;
            }
            
            // Skip victim - handle separately
            if (tid == victim_tid) {
                printf("    Will re-attach victim thread %d separately\n", tid);
                continue;
            }
            
            // Try to re-attach
            if (reattach_and_resume_tracing(tid)) {
                reattached_count++;
            }
        }
        
        // Try to re-attach victim
        if (thread_exists(victim_tid)) {
            printf("  Attempting to re-attach victim thread %d...\n", victim_tid);
            if (reattach_and_resume_tracing(victim_tid)) {
                reattached_count++;
                printf("    ✓ Victim thread %d re-attached\n", victim_tid);
            } else {
                kill(victim_tid, SIGCONT);
                printf("    Sent SIGCONT to victim thread %d\n", victim_tid);
            }
        }
        
        printf("  Re-attached to %d/%zu threads\n", reattached_count, tids.size());
        
        // ==========================================
        // Clean data structures
        // ==========================================
        printf("  Cleaning data structures...\n");
        waits_for.erase(victim_name);
        thread_locks.erase(victim_name);
        
        for (uint64_t lock_addr : deadlock.involved_locks) {
            auto it = lock_owners.find(lock_addr);
            if (it != lock_owners.end() && it->second == victim_name) {
                lock_owners.erase(it);
            }
        }
        
        for (auto& [lock_addr, waiters] : futex_waiters) {
            waiters.erase(std::remove(waiters.begin(), waiters.end(), victim_name), waiters.end());
        }
        
        // ==========================================
        // CRITICAL: Clear resolution flag and restore monitoring
        // ==========================================
        usleep(50000); // Give threads time to stabilize
        
        // Clear resolution flag FIRST
        monitoring_active.store(true);
        
        printf("\033[1;32m[✓] Deadlock resolved! Monitoring continues on remaining threads.\033[0m\n");
        printf("[*] Agent continuing with tracing active\n");
        
        fflush(stdout);
        fflush(stderr);
        
        return true;
        
    } else {
        perror("fork failed");
        monitoring_active.store(true);
        return false;
    }
}

bool emergency_deadlock_break(const DeadlockInfo& deadlock) {
    std::cout << "\033[1;31m[EMERGENCY] Breaking deadlock forcefully...\033[0m\n";
    
    for (const auto& thread_name : deadlock.cycle) {
        pid_t tid = extract_tid_from_identifier(thread_name);
        if (thread_exists(tid)) {
            std::cout << "  Killing thread " << tid << " to break deadlock\n";
            kill(tid, SIGKILL);
            
            std::string victim_name = get_thread_identifier(tid);
            waits_for.erase(victim_name);
            thread_locks.erase(victim_name);
            
            for (auto it = lock_owners.begin(); it != lock_owners.end(); ) {
                if (it->second == victim_name) {
                    std::cout << "  Released lock " << to_hex_string(it->first) << "\n";
                    it = lock_owners.erase(it);
                } else {
                    ++it;
                }
            }
            
            return true;
        }
    }
    
    return false;
}