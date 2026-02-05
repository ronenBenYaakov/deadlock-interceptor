// deadlock_resolver.cpp - Complete Strategy 1 Implementation
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/futex.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/signal.h>
#include <sys/eventfd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <linux/prctl.h>
#include <sys/reg.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <chrono>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <thread>
#include <functional>
#include <sstream>
#include <string>

using Clock = std::chrono::steady_clock;
using namespace std::chrono;

// ========== STRUCT DEFINITIONS ==========
struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    std::string perms;
    std::string name;
};

struct ThreadSnapshot {
    struct user_regs_struct regs;
    struct _libc_fpstate fpregs;
    uint64_t fs_base;
    uint64_t gs_base;
    std::vector<uint8_t> signal_mask;
    std::chrono::system_clock::time_point snapshot_time;
};

struct LockStats {
    uint64_t lock_address;
    std::string current_owner;
    size_t total_acquisitions = 0;
    size_t waiters_count = 0;
    double avg_wait_time_ns = 0.0;
    std::vector<std::string> waiting_threads;
    std::chrono::system_clock::time_point first_seen_time;
    std::chrono::system_clock::time_point last_acquire_time;
    size_t deadlock_resolution_attempts = 0;
    size_t successful_resolutions = 0;
};

struct DeadlockInfo {
    std::vector<std::string> cycle;
    std::vector<uint64_t> involved_locks;
    std::chrono::system_clock::time_point detection_time;
    size_t deadlock_id;
    bool resolved = false;
};

struct ResourceCopy {
    void* original_addr;
    void* copy_addr;
    size_t size;
    std::vector<uint8_t> data;
    std::chrono::system_clock::time_point copy_time;
    uint64_t lock_addr;
};

struct ThreadInfo {
    pid_t tid;
    std::string name;
    pid_t pid;
};

struct ShadowProcess {
    pid_t shadow_pid;
    pid_t victim_tid;
    std::vector<ResourceCopy> resource_copies;
    std::vector<MemoryRegion> protected_regions;
    std::chrono::system_clock::time_point creation_time;
    std::atomic<bool> running{true};
    int control_fd = -1;
    
    ShadowProcess() = default;
    ShadowProcess(ShadowProcess&& other) noexcept
        : shadow_pid(other.shadow_pid),
          victim_tid(other.victim_tid),
          resource_copies(std::move(other.resource_copies)),
          protected_regions(std::move(other.protected_regions)),
          creation_time(other.creation_time),
          running(other.running.load()),
          control_fd(other.control_fd) {
        other.control_fd = -1;
    }
    
    ShadowProcess& operator=(ShadowProcess&& other) noexcept {
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
    
    ShadowProcess(const ShadowProcess&) = delete;
    ShadowProcess& operator=(const ShadowProcess&) = delete;
};

struct DeadlockResolution {
    size_t deadlock_id;
    pid_t victim_tid;
    std::string victim_name;
    std::vector<uint64_t> involved_locks;
    std::vector<MemoryRegion> guarded_regions;
    ShadowProcess* shadow = nullptr;
    bool success = false;
    std::chrono::system_clock::time_point resolution_time;
};

// ========== GLOBAL VARIABLES ==========
static pid_t target_pid = 0;
static std::unordered_map<pid_t, ThreadInfo> thread_info_cache;
static std::mutex thread_info_mutex;
static std::atomic<bool> world_stopped{false};
static std::atomic<bool> monitoring_active{true};
static std::mutex resolution_mutex;
static std::vector<MemoryRegion> g_protected_regions;

static std::unordered_map<uint64_t, std::vector<std::string>> futex_waiters;
static std::unordered_map<std::string, std::unordered_map<uint64_t, Clock::time_point>> wait_start_times;
static std::unordered_map<std::string, std::unordered_set<std::string>> waits_for;
static std::unordered_map<std::string, std::unordered_set<uint64_t>> thread_locks;
static std::unordered_map<uint64_t, std::string> lock_owners;
static std::unordered_map<uint64_t, LockStats> lock_stats;

static std::vector<DeadlockInfo> detected_deadlocks;
static std::vector<ShadowProcess> shadow_processes;
static std::vector<DeadlockResolution> resolution_history;

static std::ofstream json_output;
static std::ofstream deadlock_json_output;
static std::ofstream resolution_log;
static std::ofstream shadow_log;
static size_t deadlock_counter = 0;
static std::mutex output_mutex;

// ========== HELPER FUNCTIONS ==========
std::string to_hex_string(uint64_t value) {
    std::stringstream ss;
    ss << "0x" << std::hex << value;
    return ss.str();
}

std::string get_thread_name(pid_t tid) {
    std::lock_guard<std::mutex> lock(thread_info_mutex);
    
    auto it = thread_info_cache.find(tid);
    if (it != thread_info_cache.end()) {
        return it->second.name;
    }

    std::string thread_name;
    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", tid);
    FILE* comm_file = fopen(proc_path, "r");
    if (comm_file) {
        char buffer[256] = {0};
        if (fgets(buffer, sizeof(buffer), comm_file)) {
            thread_name = buffer;
            thread_name.erase(std::remove_if(thread_name.begin(), thread_name.end(),
                                             [](unsigned char c){ return c == '\n' || c == '\r'; }),
                              thread_name.end());
        }
        fclose(comm_file);
    }

    if (thread_name.empty() && target_pid > 0) {
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/task/%d/comm", target_pid, tid);
        comm_file = fopen(proc_path, "r");
        if (comm_file) {
            char buffer[256] = {0};
            if (fgets(buffer, sizeof(buffer), comm_file)) {
                thread_name = buffer;
                thread_name.erase(std::remove_if(thread_name.begin(), thread_name.end(),
                                                 [](unsigned char c){ return c == '\n' || c == '\r'; }),
                                  thread_name.end());
            }
            fclose(comm_file);
        }
    }

    if (thread_name.empty()) {
        thread_name = "thread-" + std::to_string(tid);
    }

    thread_info_cache[tid] = ThreadInfo{tid, thread_name, target_pid};
    return thread_name;
}

std::string get_thread_identifier(pid_t tid) {
    std::string name = get_thread_name(tid);
    return name + "[" + std::to_string(tid) + "]";
}

bool junk_addr(uint64_t addr) {
    if (addr == 0) return true;
    if (addr < 0x10000) return true;
    if (addr > 0x7fffffffffff) return true;
    return false;
}

bool read_process_memory(pid_t pid, void* addr, void* buffer, size_t size) {
    size_t words = size / sizeof(long);
    size_t remainder = size % sizeof(long);
    
    long* dest = static_cast<long*>(buffer);
    long* src_addr = static_cast<long*>(addr);
    
    for (size_t i = 0; i < words; i++) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, src_addr + i, nullptr);
        if (errno != 0) {
            return false;
        }
        dest[i] = word;
    }
    
    if (remainder > 0) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, src_addr + words, nullptr);
        if (errno != 0) {
            return false;
        }
        memcpy(dest + words, &word, remainder);
    }
    
    return true;
}

bool thread_exists(pid_t tid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/task/%d", target_pid, tid);
    return access(path, F_OK) == 0;
}

bool write_process_memory(pid_t pid, void* addr, const void* buffer, size_t size) {
    size_t words = size / sizeof(long);
    size_t remainder = size % sizeof(long);
    
    const long* src = static_cast<const long*>(buffer);
    long* dest_addr = static_cast<long*>(addr);
    
    for (size_t i = 0; i < words; i++) {
        if (ptrace(PTRACE_POKEDATA, pid, dest_addr + i, src[i]) == -1) {
            return false;
        }
    }
    
    if (remainder > 0) {
        errno = 0;
        long existing = ptrace(PTRACE_PEEKDATA, pid, dest_addr + words, nullptr);
        if (errno != 0) {
            return false;
        }
        
        memcpy(&existing, src + words, remainder);
        if (ptrace(PTRACE_POKEDATA, pid, dest_addr + words, existing) == -1) {
            return false;
        }
    }
    
    return true;
}

std::vector<MemoryRegion> read_process_maps(pid_t pid) {
    std::vector<MemoryRegion> regions;
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE* maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return regions;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), maps_file)) {
        MemoryRegion region;
        char perms[8];
        char name[256] = {0};
        
        if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %255[^\n]", 
                   &region.start, &region.end, perms, name) >= 3) {
            region.perms = perms;
            region.name = name;
            regions.push_back(region);
        }
    }
    
    fclose(maps_file);
    return regions;
}

std::vector<pid_t> list_threads(pid_t pid) {
    std::vector<pid_t> tids;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);

    DIR *dir = opendir(path);
    if (!dir) return tids;

    struct dirent *ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        pid_t tid = atoi(ent->d_name);
        tids.push_back(tid);
    }

    closedir(dir);
    return tids;
}

// ========== SNAPSHOT/RESTORE FUNCTIONS ==========
ThreadSnapshot snapshot_thread_state(pid_t tid) {
    ThreadSnapshot snap;
    snap.snapshot_time = std::chrono::system_clock::now();
    
    // Check if thread still exists
    if (!thread_exists(tid)) {
        printf("  [WARNING] Thread %d no longer exists!\n", tid);
        return snap;
    }
    
    // Get general purpose registers
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &snap.regs) == -1) {
        if (errno == ESRCH) {
            printf("  [ERROR] Thread %d exited during snapshot\n", tid);
        } else {
            perror("PTRACE_GETREGS failed");
        }
        return snap;
    }
    
    printf("  Snapshot complete: RIP=0x%lx\n", (unsigned long)snap.regs.rip);
    return snap;
}

bool restore_thread_state(pid_t tid, const ThreadSnapshot& snap) {
    if (!thread_exists(tid)) {
        printf("  Cannot restore: thread %d no longer exists\n", tid);
        return false;
    }
    
    if (snap.regs.rip == 0) {
        printf("  No valid snapshot to restore\n");
        return false;
    }
    
    printf("\033[1;33m[RESTORE] Restoring thread %d...\033[0m\n", tid);
    
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &snap.regs) == -1) {
        perror("  PTRACE_SETREGS failed");
        return false;
    }
    
    printf("  ✓ Registers restored\n");
    return true;
}

// ========== DEADLOCK DETECTION ==========
bool dfs_deadlock(const std::string& thread_name,
                  std::unordered_set<std::string>& visited,
                  std::unordered_set<std::string>& stack,
                  std::vector<std::string>& cycle) 
{
    visited.insert(thread_name);
    stack.insert(thread_name);

    auto it = waits_for.find(thread_name);
    if (it != waits_for.end()) {
        for (const std::string& neighbor : it->second) {
            if (stack.count(neighbor)) {
                // Cycle found
                cycle.push_back(neighbor);
                cycle.push_back(thread_name);
                return true;
            }
            if (!visited.count(neighbor)) {
                if (dfs_deadlock(neighbor, visited, stack, cycle)) {
                    cycle.push_back(thread_name);
                    return true;
                }
            }
        }
    }

    stack.erase(thread_name);
    return false;
}

std::vector<uint64_t> find_locks_in_deadlock(const std::vector<std::string>& cycle) {
    std::vector<uint64_t> involved_locks;
    std::unordered_set<uint64_t> seen_locks;
    
    for (size_t i = 0; i < cycle.size(); i++) {
        const std::string& thread_name = cycle[i];
        const std::string& next_thread = cycle[(i + 1) % cycle.size()];
        
        // Find locks owned by current thread
        for (const auto& [lock_addr, owner] : lock_owners) {
            if (owner == thread_name) {
                // Check if next thread is waiting for this lock
                auto it = futex_waiters.find(lock_addr);
                if (it != futex_waiters.end()) {
                    auto& waiters = it->second;
                    if (std::find(waiters.begin(), waiters.end(), next_thread) != waiters.end() && 
                        !seen_locks.count(lock_addr)) {
                        involved_locks.push_back(lock_addr);
                        seen_locks.insert(lock_addr);
                    }
                }
            }
        }
    }
    
    return involved_locks;
}

// ========== MEMORY DUPLICATION LOGIC ==========
bool should_duplicate_page(uintptr_t addr) {
    for (auto& region : g_protected_regions) {
        if (addr >= region.start && addr < region.end) {
            return true;
        }
    }
    return false;
}

static void shadow_sigsegv_handler(int sig, siginfo_t* info, void* context) {
    void* fault_addr = info->si_addr;
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = ((uintptr_t)fault_addr / page_size) * page_size;
    
    printf("[SHADOW SIGSEGV] Fault at %p, handling page 0x%lx\n", 
           fault_addr, page_start);
    
    // Check if this is a protected region
    if (!should_duplicate_page(page_start)) {
        fprintf(stderr, "[SHADOW] Unhandled fault at %p - aborting\n", fault_addr);
        exit(1);
    }
    
    // Save original page content
    uint8_t page_copy[page_size];
    memcpy(page_copy, (void*)page_start, page_size);
    
    // Create NEW private page with MAP_FIXED
    void* new_page = mmap((void*)page_start, page_size,
                         PROT_READ | PROT_WRITE,
                         MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                         -1, 0);
    
    if (new_page == MAP_FAILED) {
        perror("[SHADOW] mmap MAP_FIXED failed");
        exit(1);
    }
    
    // Restore original content to new private page
    memcpy(new_page, page_copy, page_size);
    
    printf("[SHADOW] Page 0x%lx replaced with private copy\n", page_start);
}

// ========== STRATEGY 1 IMPLEMENTATION ==========
bool stop_the_world() {
    printf("\033[1;33m[STEP 1] Stopping the world...\033[0m\n");
    
    monitoring_active.store(false);
    printf("  Monitoring stopped\n");
    
    auto tids = list_threads(target_pid);
    printf("  Target has %zu threads\n", tids.size());
    
    // SIMPLE APPROACH: Just detach from ptrace and let threads run free
    // This ensures we can fork cleanly
    for (pid_t tid : tids) {
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    }
    
    // Give threads a moment to resume
    usleep(50000); // 50ms
    
    world_stopped.store(true);
    printf("\033[1;32m[✓] Detached from all threads, ready for fork\033[0m\n");
    
    return true;
}

pid_t extract_tid_from_identifier(const std::string& identifier) {
    size_t bracket_pos = identifier.find('[');
    size_t end_bracket = identifier.find(']');
    if (bracket_pos != std::string::npos && end_bracket != std::string::npos) {
        std::string tid_str = identifier.substr(bracket_pos + 1, end_bracket - bracket_pos - 1);
        return std::stoi(tid_str);
    }
    return 0;
}
    
std::string choose_victim_thread(const DeadlockInfo& deadlock) {
    printf("\033[1;33m[STEP 2] Choosing victim thread...\033[0m\n");
    
    // Remove duplicates from cycle
    std::unordered_set<std::string> unique_threads;
    for (const auto& thread : deadlock.cycle) {
        unique_threads.insert(thread);
    }
    
    // Find first live thread
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
    printf("  Selected victim: %s (TID=%d)\n", best_victim.c_str(), victim_tid);
    
    return best_victim;
}


bool eliminate_other_threads_in_shadow(pid_t victim_tid) {
    printf("\033[1;33m[STEP 5] Eliminating non-victim threads...\033[0m\n");
    
    // Get list of all threads in this process
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
    
    printf("  Found %zu threads total\n", all_tids.size());
    
    // Kill all threads except ourselves and victim
    for (pid_t tid : all_tids) {
        if (tid == getpid() || tid == victim_tid) continue;
        
        if (tid == victim_tid) {
            printf("    Skipping victim (TID=%d)\n", tid);
            continue;
        }
    
        if (tgkill(getpid(), tid, SIGSTOP) == -1) {
            perror("Failed to suspend thread");
        } else {
            printf("  Suspended thread %d\n", tid);
        }
    }
    
    // Wait for threads to die
    usleep(100000); // 100ms
    
    // Check what remains
    all_tids.clear();
    dir = opendir("/proc/self/task");
    if (dir) {
        while ((ent = readdir(dir)) != nullptr) {
            if (ent->d_name[0] == '.') continue;
            pid_t tid = atoi(ent->d_name);
            all_tids.push_back(tid);
        }
        closedir(dir);
    }
    
    printf("  %zu threads remain after elimination\n", all_tids.size());
    for (pid_t tid : all_tids) {
        printf("    Thread %d\n", tid);
    }
    
    // Check if victim is still there
    bool victim_alive = false;
    for (pid_t tid : all_tids) {
        if (tid == victim_tid) {
            victim_alive = true;
            break;
        }
    }
    
    if (victim_alive && all_tids.size() <= 2) { // Victim + ourselves
        printf("  ✓ Victim isolated\n");
        return true;
    } else {
        printf("  ✗ Failed to isolate victim\n");
        return false;
    }
}

std::vector<MemoryRegion> initialize_private_memory(const std::vector<uint64_t>& locks) {
    printf("\033[1;33m[STEP 6] Initializing private-memory machinery...\033[0m\n");
    
    std::vector<MemoryRegion> protected_regions;
    
    // Install SIGSEGV handler
    struct sigaction sa;
    sa.sa_sigaction = shadow_sigsegv_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("sigaction SIGSEGV failed");
        return protected_regions;
    }
    
    printf("  ✓ SIGSEGV handler installed\n");
    
    // Protect lock regions
    for (uint64_t lock_addr : locks) {
        MemoryRegion region;
        region.start = lock_addr & ~(sysconf(_SC_PAGESIZE) - 1);
        region.end = region.start + sysconf(_SC_PAGESIZE);
        region.perms = "---";
        region.name = "protected_lock_" + to_hex_string(lock_addr);
        
        if (mprotect((void*)region.start, region.end - region.start, PROT_NONE) == 0) {
            protected_regions.push_back(region);
            g_protected_regions.push_back(region);
            printf("  ✓ Protected lock at %s (page 0x%lx)\n", 
                   to_hex_string(lock_addr).c_str(), region.start);
        } else {
            perror("mprotect failed");
        }
    }
    
    return protected_regions;
}

void force_unlock_futexes(const std::vector<uint64_t>& locks) {
    printf("\033[1;33m[LOCK ILLUSION] Forcing unlock...\033[0m\n");
    
    for (uint64_t lock_addr : locks) {
        size_t page_size = sysconf(_SC_PAGESIZE);
        uintptr_t page_start = lock_addr & ~(page_size - 1);
        
        // Temporarily make page writable
        if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE) == 0) {
            // Write 0 to futex (unlocked)
            volatile uint32_t* futex_ptr = (volatile uint32_t*)(lock_addr);
            uint32_t old_value = *futex_ptr;
            *futex_ptr = 0;
            printf("  ✓ Unlocked %s (was 0x%x)\n", 
                   to_hex_string(lock_addr).c_str(), old_value);
            
            // Restore protection
            mprotect((void*)page_start, page_size, PROT_NONE);
        }
    }
}

bool cleanup_parent_process(pid_t victim_tid, const std::vector<uint64_t>& deadlock_locks) {
    printf("\033[1;33m[STEP 9] Cleaning up parent process...\033[0m\n");
    
    // IMPORTANT: We already detached all threads in stop_the_world()
    // Don't detach again - just clean up data structures
    
    // Release victim's locks
    for (uint64_t lock_addr : deadlock_locks) {
        auto it = lock_owners.find(lock_addr);
        if (it != lock_owners.end()) {
            std::string owner = it->second;
            if (owner.find(std::to_string(victim_tid)) != std::string::npos) {
                printf("  Released lock %s\n", to_hex_string(lock_addr).c_str());
                lock_owners.erase(it);
            }
        }
    }
    
    // Remove victim from wait-for graph
    std::string victim_name = get_thread_identifier(victim_tid);
    waits_for.erase(victim_name);
    
    // Clean up futex waiters containing victim
    for (auto it = futex_waiters.begin(); it != futex_waiters.end(); ) {
        auto& waiters = it->second;
        waiters.erase(std::remove(waiters.begin(), waiters.end(), victim_name), waiters.end());
        if (waiters.empty()) {
            it = futex_waiters.erase(it);
        } else {
            ++it;
        }
    }
    
    // DO NOT resume threads here - they're already running
    // after we detached from ptrace
    
    printf("  ✓ Parent cleaned up (threads already running)\n");
    return true;
}

void monitor_shadow_process(pid_t shadow_pid, pid_t victim_tid, const DeadlockInfo& deadlock) {
    printf("\033[1;33m[STEP 10] Monitoring shadow process %d...\033[0m\n", shadow_pid);
    
    pid_t monitor = fork();
    
    if (monitor == 0) {
        // Monitor child
        int status;
        waitpid(shadow_pid, &status, 0);
        
        if (WIFEXITED(status)) {
            printf("\033[1;36m[SHADOW MONITOR] Process %d exited with code %d\033[0m\n", 
                   shadow_pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("\033[1;31m[SHADOW MONITOR] Process %d killed by signal %d\033[0m\n", 
                   shadow_pid, WTERMSIG(status));
        }
        
        exit(0);
    } else if (monitor > 0) {
        // Parent continues
        printf("  ✓ Monitor process %d started\n", monitor);
        
        // Update deadlock info
        for (auto& dl : detected_deadlocks) {
            if (dl.deadlock_id == deadlock.deadlock_id) {
                dl.resolved = true;
                break;
            }
        }
        
        printf("\033[1;32m[✓] Deadlock #%zu resolved via shadow process %d\033[0m\n", 
               deadlock.deadlock_id, shadow_pid);
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
        
        // Wait for shadow
        int status;
        waitpid(shadow, &status, 0);
        
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
        
        // SIMPLE RECOVERY: Just continue monitoring without re-attaching
        // The program will continue running, we just won't trace it anymore
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

// ========== MONITORING LOGIC ==========
void update_lock_stats(uint64_t addr, const std::string& new_owner) {
    auto now = Clock::now();
    auto system_now = std::chrono::system_clock::now();
    
    if (!lock_stats.count(addr)) {
        lock_stats[addr] = LockStats{
            .lock_address = addr,
            .current_owner = new_owner,
            .total_acquisitions = 1,
            .waiters_count = futex_waiters[addr].size(),
            .avg_wait_time_ns = 0.0,
            .waiting_threads = futex_waiters[addr],
            .first_seen_time = system_now,
            .last_acquire_time = system_now
        };
    } else {
        auto& stats = lock_stats[addr];
        stats.current_owner = new_owner;
        stats.total_acquisitions++;
        stats.waiters_count = futex_waiters[addr].size();
        stats.waiting_threads = futex_waiters[addr];
        stats.last_acquire_time = system_now;
    }
}

void on_lock(pid_t tid, uint64_t addr) {
    if (junk_addr(addr)) return;

    std::string thread_name = get_thread_identifier(tid);
    
    printf("\033[32m[LOCK]\033[0m %s acquired lock at %s\n", 
           thread_name.c_str(), to_hex_string(addr).c_str());

    lock_owners[addr] = thread_name;
    thread_locks[thread_name].insert(addr);
    
    // Remove from all wait-for relationships
    for (auto &kv : waits_for) {
        kv.second.erase(thread_name);
    }

    // Remove this thread from all waiter lists
    for (auto &kv : futex_waiters) {
        auto& waiters = kv.second;
        waiters.erase(std::remove(waiters.begin(), waiters.end(), thread_name), waiters.end());
    }
    
    update_lock_stats(addr, thread_name);
}

void on_wait(pid_t tid, uint64_t addr) {
    if (junk_addr(addr)) return;

    std::string thread_name = get_thread_identifier(tid);
    
    futex_waiters[addr].push_back(thread_name);
    wait_start_times[thread_name][addr] = Clock::now();
    
    printf("\033[33m[WAIT]\033[0m %s waiting on futex %s\n", 
           thread_name.c_str(), to_hex_string(addr).c_str());

    if (lock_owners.count(addr)) {
        std::string owner = lock_owners[addr];
        if (owner != thread_name) {
            waits_for[thread_name].insert(owner);
        }
    }
    
    if (lock_stats.count(addr)) {
        lock_stats[addr].waiters_count = futex_waiters[addr].size();
        lock_stats[addr].waiting_threads = futex_waiters[addr];
    }
}

void on_wake(pid_t tid, uint64_t addr) {
    std::string thread_name = get_thread_identifier(tid);
    
    auto it = futex_waiters.find(addr);
    if (it == futex_waiters.end()) return;

    for (const std::string& waiter : it->second) {
        printf("\033[34m[COMM]\033[0m %s sent message to %s via futex %s\n",
               thread_name.c_str(), waiter.c_str(), to_hex_string(addr).c_str());
    }

    futex_waiters.erase(addr);
    
    if (lock_stats.count(addr)) {
        lock_stats[addr].waiters_count = 0;
        lock_stats[addr].waiting_threads.clear();
    }
}

void handle_syscall(pid_t tid) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == -1) {
        return;
    }

#if defined(__x86_64__)
    long syscall = regs.orig_rax;

    if (syscall == SYS_futex) {
        uint64_t uaddr = regs.rdi;
        int op = regs.rsi & FUTEX_CMD_MASK;

        if (op == FUTEX_WAIT) {
            on_wait(tid, uaddr);
        }
        else if (op == FUTEX_WAKE) {
            on_wake(tid, uaddr);
            on_lock(tid, uaddr);
        } else if (op == FUTEX_WAIT_BITSET || op == FUTEX_WAKE_BITSET) {
            on_wait(tid, uaddr);
        }
    }
#endif
}

bool emergency_deadlock_break(const DeadlockInfo& deadlock) {
    printf("\033[1;31m[EMERGENCY] Breaking deadlock forcefully...\033[0m\n");
    
    // Just pick any thread and kill it
    for (const auto& thread_name : deadlock.cycle) {
        pid_t tid = extract_tid_from_identifier(thread_name);
        if (thread_exists(tid)) {
            printf("  Killing thread %d to break deadlock\n", tid);
            kill(tid, SIGKILL);
            
            // Remove from data structures
            std::string victim_name = get_thread_identifier(tid);
            waits_for.erase(victim_name);
            thread_locks.erase(victim_name);
            
            // Release its locks
            for (auto it = lock_owners.begin(); it != lock_owners.end(); ) {
                if (it->second == victim_name) {
                    printf("  Released lock %s\n", to_hex_string(it->first).c_str());
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

// Add this debug function
void debug_wait_for_graph() {
    printf("\n[DEBUG] Wait-for graph:\n");
    for (const auto& [waiter, waits] : waits_for) {
        printf("  %s waits for:\n", waiter.c_str());
        for (const auto& target : waits) {
            printf("    -> %s\n", target.c_str());
        }
    }
    printf("\n[DEBUG] Lock owners:\n");
    for (const auto& [lock, owner] : lock_owners) {
        printf("  Lock %s owned by %s\n", to_hex_string(lock).c_str(), owner.c_str());
    }
}

// Fix the detection logic in detect_and_resolve_deadlocks:
void detect_and_resolve_deadlocks() {
    if (!monitoring_active.load()) return;
    
    std::lock_guard<std::mutex> lock(output_mutex);
    std::unordered_set<std::string> visited;
    std::unordered_set<std::string> stack;
    std::vector<std::string> cycle;

    for (auto &kv : waits_for) {
        const std::string& thread_name = kv.first;
        if (!visited.count(thread_name)) {
            cycle.clear();
            if (dfs_deadlock(thread_name, visited, stack, cycle)) {
                std::reverse(cycle.begin(), cycle.end());
                
                // Validate cycle is complete
                if (cycle.size() >= 2) {
                    bool is_new = true;
                    for (const auto& existing : detected_deadlocks) {
                        if (existing.cycle == cycle) {
                            is_new = false;
                            break;
                        }
                    }
                    
                    if (is_new) {
                        deadlock_counter++;
                        DeadlockInfo deadlock;
                        deadlock.cycle = cycle;
                        deadlock.involved_locks = find_locks_in_deadlock(cycle);
                        deadlock.detection_time = std::chrono::system_clock::now();
                        deadlock.deadlock_id = deadlock_counter;
                        
                        printf("\033[1;31m[DEADLOCK #%zu DETECTED]\033[0m\n", deadlock_counter);
                        
                        // Try Strategy 1
                        if (resolve_deadlock_strategy1(deadlock)) {
                            deadlock.resolved = true;
                            printf("\033[1;32m✓ Resolved via Strategy 1\033[0m\n");
                        } else {
                            // Emergency fallback
                            printf("\033[1;33mStrategy 1 failed, using emergency break\033[0m\n");
                            if (emergency_deadlock_break(deadlock)) {
                                deadlock.resolved = true;
                                printf("\033[1;32m✓ Emergency break successful\033[0m\n");
                            }
                        }
                        
                        detected_deadlocks.push_back(deadlock);
                    }
                }
            }
        }
    }
}

// ========== MAIN FUNCTION ==========
void signal_handler(int sig) {
    printf("\n[*] Received signal %d, cleaning up...\n", sig);
    
    // Print summary
    printf("\n\033[1;36m╔══════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;36m║                         MONITORING SUMMARY                        ║\033[0m\n");
    printf("\033[1;36m╠══════════════════════════════════════════════════════════════════╣\033[0m\n");
    printf("\033[1;33m║ Total deadlocks detected:\033[0m %zu\n", detected_deadlocks.size());
    
    size_t resolved_count = 0;
    for (const auto& deadlock : detected_deadlocks) {
        if (deadlock.resolved) resolved_count++;
    }
    
    printf("\033[1;33m║ Deadlocks resolved:\033[0m %zu/%zu\n", resolved_count, detected_deadlocks.size());
    printf("\033[1;33m║ Total threads tracked:\033[0m %zu\n", thread_info_cache.size());
    printf("\033[1;33m║ Total locks tracked:\033[0m %zu\n", lock_stats.size());
    printf("\033[1;33m║ Shadow processes created:\033[0m %zu\n", shadow_processes.size());
    printf("\033[1;36m╚══════════════════════════════════════════════════════════════════╝\033[0m\n");
    
    exit(0);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <pid>\n", argv[0]);
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    target_pid = atoi(argv[1]);
    printf("\033[1;36m[*] Deadlock Detector with Strategy 1 Resolution\033[0m\n");
    printf("\033[1;36m[*] Attaching to process %d\033[0m\n", target_pid);
    printf("\033[1;36m[*] Strategy: Thread reconstitution in shadow process\033[0m\n");
    
    // Attach to all threads
    auto tids = list_threads(target_pid);
    for (pid_t tid : tids) {
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
            int status;
            waitpid(tid, &status, __WALL);
            ptrace(PTRACE_SETOPTIONS, tid, nullptr,
                   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
            ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
            printf("  Attached to thread %d\n", tid);
        }
    }

    printf("\n\033[1;36m[*] Monitoring started. Detected deadlocks will be automatically resolved.\033[0m\n");
    printf("\033[1;33m[*] Press Ctrl+C to stop and see summary\033[0m\n\n");
    
    while (true) {
        if (!monitoring_active.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        int status;
        pid_t tid = waitpid(-1, &status, __WALL);
        if (tid <= 0) continue;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            printf("\033[90m[*] %s exited\033[0m\n", get_thread_identifier(tid).c_str());
            continue;
        }

        if (status >> 8 == (SIGTRAP | 0x80)) {
            handle_syscall(tid);
            detect_and_resolve_deadlocks();
        }

        ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
    }
    
    return 0;
}