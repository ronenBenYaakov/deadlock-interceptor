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

bool resolve_deadlock_strategy1(const DeadlockInfo& deadlock) {
    printf("\n\033[1;35m[RESOLUTION] Breaking deadlock...\033[0m\n");
    
    monitoring_active.store(false);
    
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
    
    printf("  Selected victim: %s\n", victim_name.c_str());
    
    // Detach from all threads with safety
    auto tids = list_threads(target_pid);
    printf("  Detaching from %zu threads\n", tids.size());
    
    for (pid_t tid : tids) {
        bool detached = false;
        
        // Try PTRACE_DETACH with retries
        for (int attempt = 0; attempt < 3; attempt++) {
            if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) == 0) {
                detached = true;
                break;
            }
            
            if (errno == ESRCH || errno == EPERM) {
                detached = true;
                break;
            }
            
            // Try PTRACE_CONT as fallback
            if (attempt == 1) {
                ptrace(PTRACE_CONT, tid, nullptr, nullptr);
                usleep(1000);
            }
            
            usleep(1000 * (1 << attempt));
        }
        
        // Emergency detach if still attached
        if (!detached) {
            ptrace(PTRACE_CONT, tid, nullptr, nullptr);
            usleep(1000);
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
            kill(tid, SIGCONT);
        }
    }
    
    // Ensure victim is running before fork
    kill(victim_tid, SIGCONT);
    usleep(50000);
    
    // Fork shadow
    pid_t shadow = fork();
    
    if (shadow == 0) {
        // SHADOW PROCESS
        printf("\033[1;36m[SHADOW] PID=%d\033[0m\n", getpid());
        
        // Unlock futexes
        for (uint64_t lock_addr : deadlock.involved_locks) {            
            uint32_t zero = 0;
            struct iovec local_iov = {
                .iov_base = &zero,
                .iov_len = sizeof(uint32_t)
            };
            struct iovec remote_iov = {
                .iov_base = (void*)lock_addr,
                .iov_len = sizeof(uint32_t)
            };
            
            ssize_t nwritten = process_vm_writev(target_pid, &local_iov, 1, &remote_iov, 1, 0);
            
            if (nwritten == sizeof(uint32_t)) {
                printf("  ✓ Unlocked %s\n", to_hex_string(lock_addr).c_str());
            } else {
                printf("  ✗ Failed to unlock %s (errno: %d)\n", 
                    to_hex_string(lock_addr).c_str(), errno);
            }
        }
        
        // Resume victim
        if (thread_exists(victim_tid)) {
            kill(victim_tid, SIGCONT);
        }
        
        // Resume all threads (just in case)
        for (pid_t tid : tids) {
            if (thread_exists(tid)) {
                kill(tid, SIGCONT);
            }
        }
        
        return true;
        
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
        
        // Resume all paused threads safely
        printf("  Resuming all threads...\n");
        for (pid_t tid : tids) {
            if (thread_exists(tid)) {
                // Send SIGCONT to ensure threads are running
                if (kill(tid, SIGCONT) == -1) {
                    if (errno != ESRCH) {
                        printf("  Warning: Could not resume thread %d\n", tid);
                    }
                }
            }
        }
        
        // Ensure victim is running
        if (thread_exists(victim_tid)) {
            kill(victim_tid, SIGCONT);
        }
        
        // Wait a bit for threads to stabilize
        usleep(100000);
        
        // Clean data structures
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
        
        printf("\033[1;32m[✓] Deadlock resolved! Program continues without tracing.\033[0m\n");
        printf("[*] Agent exiting after successful resolution\n");
        
        // Final cleanup
        fflush(stdout);
        fflush(stderr);
        
        return true;
        
    } else {
        perror("fork failed");
        monitoring_active.store(true);
        return false;
    }
    
    return true;  // Never reached
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