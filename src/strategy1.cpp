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
    
    for (pid_t tid : tids) {
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    }
    
    usleep(50000);
    
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
        
        exit(0);
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
    
    // Snapshot (optional)
    ThreadSnapshot victim_snap = snapshot_thread_state(victim_tid);
    
    // Detach from all threads
    auto tids = list_threads(target_pid);
    for (pid_t tid : tids) {
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    }
    
    usleep(100000);  // 100ms
    
    // Fork shadow
    pid_t shadow = fork();
    
    if (shadow == 0) {
        // SHADOW PROCESS
        printf("\033[1;36m[SHADOW] PID=%d\033[0m\n", getpid());
        
        // Unlock futexes
        for (uint64_t lock_addr : deadlock.involved_locks) {
            size_t page_size = sysconf(_SC_PAGESIZE);
            uintptr_t page_start = lock_addr & ~(page_size - 1);
            
            if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE) == 0) {
                volatile uint32_t* futex = (volatile uint32_t*)lock_addr;
                *futex = 0;
                printf("  Unlocked %s\n", to_hex_string(lock_addr).c_str());
            }
        }
        
        // Resume victim
        if (thread_exists(victim_tid)) {
            kill(victim_tid, SIGCONT);
        }
        
        // Quick exit
        _exit(0);
        
    } else if (shadow > 0) {
        // PARENT PROCESS
        printf("  Shadow PID: %d\n", shadow);

        // Wait for shadow process to finish
        int status;
        waitpid(shadow, &status, 0);

        // --- Add this line ---
        resume_paused_threads(victim_tid);
        // --- Resume paused threads safely ---

        // Clean data structures
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

        // Exit cleanly
        printf("[*] Agent exiting after successful resolution\n");
        exit(0);
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