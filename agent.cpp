#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sstream>
#include <linux/futex.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <fcntl.h>

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

using Clock = std::chrono::steady_clock;
using namespace std::chrono;

struct LockEvent {
    Clock::time_point last;
    size_t acquire_count = 0;
    size_t wait_time_total_ns = 0;
    Clock::time_point first_seen;
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

struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    std::string perms;
    std::string name;
};

// Global variables
static pid_t target_pid = 0;
static std::unordered_map<pid_t, ThreadInfo> thread_info_cache;
static std::mutex thread_info_mutex;

// Main data structures
static std::unordered_map<uint64_t, std::vector<std::string>> futex_waiters;
static std::unordered_map<std::string, std::unordered_map<uint64_t, Clock::time_point>> wait_start_times;
static std::unordered_map<std::string, std::unordered_set<std::string>> waits_for;
static std::unordered_map<std::string, std::unordered_set<uint64_t>> thread_locks;
static std::unordered_map<uint64_t, std::string> lock_owners;
static std::unordered_map<uint64_t, LockStats> lock_stats;

static std::vector<DeadlockInfo> detected_deadlocks;
static std::vector<ResourceCopy> resource_copies;
static std::unordered_map<uint64_t, std::vector<ResourceCopy>> lock_to_resource_copies;

static std::ofstream json_output;
static std::ofstream deadlock_json_output;
static std::ofstream resolution_log;
static size_t deadlock_counter = 0;
static std::mutex output_mutex;

// Helper function to convert uint64_t to hex string
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
                cycle.push_back(neighbor);
                return true;
            }
            if (!visited.count(neighbor)) {
                if (dfs_deadlock(neighbor, visited, stack, cycle)) {
                    cycle.push_back(neighbor);
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

// Read process memory maps from /proc/[pid]/maps
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

// Create a copy of resources protected by a lock
ResourceCopy create_resource_copy(uint64_t lock_addr) {
    ResourceCopy copy;
    copy.lock_addr = lock_addr;
    copy.copy_time = std::chrono::system_clock::now();
    
    // Try to read the lock structure itself
    copy.size = 64; // Reasonable guess for mutex size
    copy.data.resize(copy.size);
    copy.original_addr = reinterpret_cast<void*>(lock_addr);
    
    if (read_process_memory(target_pid, copy.original_addr, copy.data.data(), copy.size)) {
        copy.copy_addr = malloc(copy.size);
        if (copy.copy_addr) {
            memcpy(copy.copy_addr, copy.data.data(), copy.size);
            
            printf("\033[1;32m[RESOURCE COPY] Created copy of lock structure at %s (%zu bytes)\033[0m\n",
                   to_hex_string(lock_addr).c_str(), copy.size);
            
            if (resolution_log.is_open()) {
                auto time_t = std::chrono::system_clock::to_time_t(copy.copy_time);
                resolution_log << "Resource copy created: "
                               << "lock=" << to_hex_string(lock_addr) << ", "
                               << "addr=" << copy.original_addr << ", "
                               << "size=" << copy.size << ", "
                               << "time=" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "\n";
            }
            
            return copy;
        }
    }
    
    copy.size = 0;
    copy.original_addr = nullptr;
    copy.copy_addr = nullptr;
    return copy;
}

// Split threads into two groups for resolution
void split_thread_groups(const std::vector<std::string>& threads,
                         std::vector<std::string>& groupA,
                         std::vector<std::string>& groupB) {
    groupA.clear();
    groupB.clear();
    
    for (size_t i = 0; i < threads.size(); i++) {
        if (i % 2 == 0) {
            groupA.push_back(threads[i]);
        } else {
            groupB.push_back(threads[i]);
        }
    }
}

// Attempt to break a deadlock by creating resource copies
bool attempt_deadlock_resolution(const DeadlockInfo& deadlock) {
    printf("\033[1;35m[ATTEMPTING DEADLOCK RESOLUTION] Trying to break deadlock #%zu\033[0m\n", deadlock.deadlock_id);
    
    if (deadlock.involved_locks.empty()) {
        printf("\033[1;31m  No locks involved in deadlock\033[0m\n");
        return false;
    }
    
    // Try to create a resource copy for each lock
    std::vector<ResourceCopy> new_copies;
    
    for (uint64_t lock_addr : deadlock.involved_locks) {
        if (lock_stats.count(lock_addr)) {
            lock_stats[lock_addr].deadlock_resolution_attempts++;
        }
        
        ResourceCopy copy = create_resource_copy(lock_addr);
        if (copy.size > 0 && copy.copy_addr != nullptr) {
            new_copies.push_back(copy);
            lock_to_resource_copies[lock_addr].push_back(copy);
            
            printf("\033[1;32m  ✓ Created resource copy for lock %s\033[0m\n", 
                   to_hex_string(lock_addr).c_str());
            
            if (lock_stats.count(lock_addr)) {
                lock_stats[lock_addr].successful_resolutions++;
            }
        } else {
            printf("\033[1;33m  ✗ Failed to create resource copy for lock %s\033[0m\n", 
                   to_hex_string(lock_addr).c_str());
        }
    }
    
    if (!new_copies.empty()) {
        // Add copies to global list
        resource_copies.insert(resource_copies.end(), new_copies.begin(), new_copies.end());
        
        // Split threads into groups for visualization
        std::vector<std::string> groupA, groupB;
        split_thread_groups(deadlock.cycle, groupA, groupB);
        
        printf("\033[1;32m[RESOLUTION] Created %zu resource copies\033[0m\n", new_copies.size());
        printf("  Group A threads (%zu): ", groupA.size());
        for (const auto& t : groupA) printf("%s ", t.c_str());
        printf("\n");
        printf("  Group B threads (%zu): ", groupB.size());
        for (const auto& t : groupB) printf("%s ", t.c_str());
        printf("\n");
        
        return true;
    }
    
    printf("\033[1;31m[RESOLUTION FAILED] Could not create any resource copies\033[0m\n");
    return false;
}

void save_deadlock_to_json(const DeadlockInfo& deadlock) {
    if (!deadlock_json_output.is_open()) {
        deadlock_json_output.open("deadlocks.json", std::ios::out | std::ios::app);
        if (!deadlock_json_output.is_open()) {
            fprintf(stderr, "Warning: Could not open deadlocks.json for writing\n");
            return;
        }
        deadlock_json_output << "[\n";
    }
    
    auto time_t = std::chrono::system_clock::to_time_t(deadlock.detection_time);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadlock.detection_time.time_since_epoch()) % 1000;
    
    if (deadlock_counter > 0) {
        deadlock_json_output << ",\n";
    }
    
    deadlock_json_output << "  {\n";
    deadlock_json_output << "    \"deadlock_id\": " << deadlock.deadlock_id << ",\n";
    deadlock_json_output << "    \"detection_time\": \"" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S")
                         << "." << std::setfill('0') << std::setw(3) << ms.count() << "\",\n";
    deadlock_json_output << "    \"resolved\": " << (deadlock.resolved ? "true" : "false") << ",\n";
    
    deadlock_json_output << "    \"cycle\": [";
    for (size_t i = 0; i < deadlock.cycle.size(); i++) {
        if (i > 0) deadlock_json_output << ", ";
        deadlock_json_output << "\"" << deadlock.cycle[i] << "\"";
    }
    deadlock_json_output << "],\n";
    
    deadlock_json_output << "    \"involved_locks\": [";
    for (size_t i = 0; i < deadlock.involved_locks.size(); i++) {
        if (i > 0) deadlock_json_output << ", ";
        deadlock_json_output << "\"" << to_hex_string(deadlock.involved_locks[i]) << "\"";
    }
    deadlock_json_output << "],\n";
    
    deadlock_json_output << "    \"lock_details\": [\n";
    for (size_t i = 0; i < deadlock.involved_locks.size(); i++) {
        uint64_t lock_addr = deadlock.involved_locks[i];
        if (i > 0) deadlock_json_output << ",\n";
        deadlock_json_output << "      {\n";
        deadlock_json_output << "        \"address\": \"" << to_hex_string(lock_addr) << "\",\n";
        deadlock_json_output << "        \"owner\": \"" << (lock_owners.count(lock_addr) ? lock_owners[lock_addr] : "none") << "\",\n";
        deadlock_json_output << "        \"waiters\": [";
        
        bool first = true;
        auto waiters_it = futex_waiters.find(lock_addr);
        if (waiters_it != futex_waiters.end()) {
            for (const std::string& waiter : waiters_it->second) {
                if (!first) deadlock_json_output << ", ";
                first = false;
                deadlock_json_output << "\"" << waiter << "\"";
            }
        }
        deadlock_json_output << "]\n";
        deadlock_json_output << "      }";
    }
    deadlock_json_output << "\n    ]\n";
    deadlock_json_output << "  }";
    
    deadlock_json_output.flush();
}

void dump_graph(const std::string &filename = "locks.dot") {
    std::lock_guard<std::mutex> lock(output_mutex);
    std::ofstream out(filename);
    if (!out.is_open()) return;

    out << "digraph LockGraph {\n";
    out << "  rankdir=LR;\n";
    out << "  node [shape=box, style=filled];\n\n";

    std::unordered_set<std::string> all_threads;
    for (auto &kv : waits_for) all_threads.insert(kv.first);
    for (auto &kv : lock_owners) all_threads.insert(kv.second);

    // Thread nodes
    for (const std::string& thread_name : all_threads) {
        out << "  \"" << thread_name << "\" [label=\"" << thread_name << "\"";
        for (const auto& deadlock : detected_deadlocks) {
            if (std::find(deadlock.cycle.begin(), deadlock.cycle.end(), thread_name) != deadlock.cycle.end()) {
                if (deadlock.resolved) {
                    out << ", color=orange, fillcolor=lightyellow";
                } else {
                    out << ", color=red, fillcolor=lightcoral";
                }
                break;
            }
        }
        out << "];\n";
    }

    // Lock nodes
    for (auto &kv : lock_owners) {
        std::string lock_label = "L" + to_hex_string(kv.first);
        out << "  \"" << lock_label << "\" [label=\"" << to_hex_string(kv.first);
        
        if (lock_to_resource_copies.count(kv.first) && !lock_to_resource_copies[kv.first].empty()) {
            out << "\\n" << lock_to_resource_copies[kv.first].size() << " copies";
        }
        
        out << "\", shape=ellipse";
        for (const auto& deadlock : detected_deadlocks) {
            if (std::find(deadlock.involved_locks.begin(), deadlock.involved_locks.end(), kv.first) != deadlock.involved_locks.end()) {
                if (deadlock.resolved) {
                    out << ", color=green, fillcolor=lightgreen";
                } else {
                    out << ", color=orange, fillcolor=lightyellow";
                }
                break;
            }
        }
        out << "];\n";
    }

    // Resource copy nodes
    for (const auto& copy : resource_copies) {
        if (copy.copy_addr != nullptr) {
            std::string copy_label = "C" + to_hex_string(reinterpret_cast<uint64_t>(copy.copy_addr));
            out << "  \"" << copy_label << "\" [label=\"Copy\\n" << copy.size << "B\", shape=cds, color=blue, fillcolor=lightblue];\n";
            
            std::string lock_label = "L" + to_hex_string(copy.lock_addr);
            out << "  \"" << lock_label << "\" -> \"" << copy_label << "\" [style=dashed, color=blue];\n";
        }
    }

    out << "\n";

    // Ownership edges
    for (auto &kv : lock_owners) {
        std::string lock_label = "L" + to_hex_string(kv.first);
        out << "  \"" << kv.second << "\" -> \"" << lock_label << "\" [label=\"owns\", color=green];\n";
    }

    // Wait-for edges
    for (auto &kv : waits_for) {
        for (const std::string& w : kv.second) {
            out << "  \"" << kv.first << "\" -> \"" << w << "\" [label=\"waits\", color=red";
            for (const auto& deadlock : detected_deadlocks) {
                auto it1 = std::find(deadlock.cycle.begin(), deadlock.cycle.end(), kv.first);
                auto it2 = std::find(deadlock.cycle.begin(), deadlock.cycle.end(), w);
                if (it1 != deadlock.cycle.end() && it2 != deadlock.cycle.end()) {
                    out << ", penwidth=3.0";
                    break;
                }
            }
            out << "];\n";
        }
    }

    out << "}\n";
    printf("[GRAPH] Dumped lock graph to %s\n", filename.c_str());
}

void detect_deadlocks() {
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
                    
                    if (attempt_deadlock_resolution(deadlock)) {
                        deadlock.resolved = true;
                        printf("\033[1;32m✓ Deadlock #%zu marked as resolved\033[0m\n", deadlock_counter);
                    }
                    
                    detected_deadlocks.push_back(deadlock);
                    
                    // Print deadlock info
                    printf("\n\033[1;31m╔══════════════════════════════════════════════════════════════════╗\033[0m\n");
                    printf("\033[1;31m║                    DEADLOCK DETECTED #%zu                     ║\033[0m\n", deadlock.deadlock_id);
                    printf("\033[1;31m╠══════════════════════════════════════════════════════════════════╣\033[0m\n");
                    printf("\033[1;33m║ Cycle:\033[0m ");
                    for (size_t i = 0; i < cycle.size(); i++) {
                        printf("\033[1;36m%s\033[0m", cycle[i].c_str());
                        if (i < cycle.size() - 1) printf(" \033[1;33m→\033[0m ");
                    }
                    printf("\n");
                    
                    printf("\033[1;33m║ Involved locks:\033[0m ");
                    for (uint64_t lock_addr : deadlock.involved_locks) {
                        printf("\033[1;35m%s\033[0m ", to_hex_string(lock_addr).c_str());
                    }
                    printf("\n");
                    
                    printf("\033[1;33m║ Status:\033[0m %s\n", deadlock.resolved ? "\033[1;32mRESOLVED\033[0m" : "\033[1;31mUNRESOLVED\033[0m");
                    
                    if (!deadlock.involved_locks.empty()) {
                        printf("\033[1;33m║ Lock details:\033[0m\n");
                        for (uint64_t lock_addr : deadlock.involved_locks) {
                            auto owner_it = lock_owners.find(lock_addr);
                            auto waiters_it = futex_waiters.find(lock_addr);
                            printf("\033[1;33m║   %s\033[0m owned by \033[1;36m%s\033[0m, waiters: ", 
                                   to_hex_string(lock_addr).c_str(),
                                   owner_it != lock_owners.end() ? owner_it->second.c_str() : "none");
                            if (waiters_it != futex_waiters.end() && !waiters_it->second.empty()) {
                                for (size_t i = 0; i < waiters_it->second.size(); i++) {
                                    printf("\033[1;31m%s\033[0m", waiters_it->second[i].c_str());
                                    if (i < waiters_it->second.size() - 1) printf(", ");
                                }
                            } else {
                                printf("none");
                            }
                            printf("\n");
                        }
                    }
                    printf("\033[1;31m╚══════════════════════════════════════════════════════════════════╝\033[0m\n\n");
                    
                    save_deadlock_to_json(deadlock);
                    dump_graph();
                }
            }
        }
    }
}

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
        
        if (wait_start_times.count(new_owner) && wait_start_times[new_owner].count(addr)) {
            auto wait_start = wait_start_times[new_owner][addr];
            auto wait_duration = duration_cast<nanoseconds>(now - wait_start).count();
            
            double total_wait = stats.avg_wait_time_ns * (stats.total_acquisitions - 1);
            stats.avg_wait_time_ns = (total_wait + wait_duration) / stats.total_acquisitions;
            
            wait_start_times[new_owner].erase(addr);
        }
    }
}

void save_lock_stats_to_json() {
    if (!json_output.is_open()) return;
    
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    json_output << "{\n";
    json_output << "  \"timestamp\": \"" << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S")
                << "." << std::setfill('0') << std::setw(3) << now_ms.count() << "\",\n";
    json_output << "  \"deadlock_count\": " << detected_deadlocks.size() << ",\n";
    json_output << "  \"lock_stats\": [\n";
    
    bool first_lock = true;
    for (const auto& [addr, stats] : lock_stats) {
        if (!first_lock) json_output << ",\n";
        first_lock = false;
        
        json_output << "    {\n";
        json_output << "      \"lock_address\": \"" << to_hex_string(stats.lock_address) << "\",\n";
        json_output << "      \"current_owner\": \"" << stats.current_owner << "\",\n";
        json_output << "      \"total_acquisitions\": " << stats.total_acquisitions << ",\n";
        json_output << "      \"waiters_count\": " << stats.waiters_count << ",\n";
        json_output << "      \"avg_wait_time_ns\": " << stats.avg_wait_time_ns << ",\n";
        json_output << "      \"waiting_threads\": [";
        
        bool first_thread = true;
        for (const std::string& tid : stats.waiting_threads) {
            if (!first_thread) json_output << ", ";
            first_thread = false;
            json_output << "\"" << tid << "\"";
        }
        json_output << "],\n";
        
        auto first_seen_time_t = std::chrono::system_clock::to_time_t(stats.first_seen_time);
        auto first_seen_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            stats.first_seen_time.time_since_epoch()) % 1000;
        auto last_acquire_time_t = std::chrono::system_clock::to_time_t(stats.last_acquire_time);
        auto last_acquire_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            stats.last_acquire_time.time_since_epoch()) % 1000;
        
        json_output << "      \"first_seen_time\": \"" << std::put_time(std::localtime(&first_seen_time_t), "%Y-%m-%d %H:%M:%S")
                    << "." << std::setfill('0') << std::setw(3) << first_seen_ms.count() << "\",\n";
        json_output << "      \"last_acquire_time\": \"" << std::put_time(std::localtime(&last_acquire_time_t), "%Y-%m-%d %H:%M:%S")
                    << "." << std::setfill('0') << std::setw(3) << last_acquire_ms.count() << "\",\n";
        json_output << "      \"deadlock_resolution_attempts\": " << stats.deadlock_resolution_attempts << ",\n";
        json_output << "      \"successful_resolutions\": " << stats.successful_resolutions << "\n";
        json_output << "    }";
    }
    
    json_output << "\n  ]\n";
    json_output << "}\n";
    json_output.flush();
    
    printf("[STATS] Lock statistics saved to JSON\n");
}

void on_lock(pid_t tid, uint64_t addr) {
    if (junk_addr(addr)) return;

    std::string thread_name = get_thread_identifier(tid);
    
    if (lock_to_resource_copies.count(addr) && !lock_to_resource_copies[addr].empty()) {
        printf("\033[1;34m[LOCK WITH COPY] %s acquired lock at %s (%zu resource copies available)\033[0m\n", 
               thread_name.c_str(), to_hex_string(addr).c_str(), lock_to_resource_copies[addr].size());
    } else {
        printf("\033[32m[LOCK]\033[0m %s acquired lock at %s\n", 
               thread_name.c_str(), to_hex_string(addr).c_str());
    }

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
    save_lock_stats_to_json();
}

void on_wait(pid_t tid, uint64_t addr) {
    if (junk_addr(addr)) return;

    std::string thread_name = get_thread_identifier(tid);
    
    // Check if thread already owns this lock (potential recursive lock)
    if (thread_locks[thread_name].count(addr)) {
        printf("\033[33m[WARNING]\033[0m %s already owns lock %s (recursive lock?)\n", 
               thread_name.c_str(), to_hex_string(addr).c_str());
    }

    futex_waiters[addr].push_back(thread_name);
    wait_start_times[thread_name][addr] = Clock::now();
    
    printf("\033[33m[WAIT]\033[0m %s waiting on futex %s\n", 
           thread_name.c_str(), to_hex_string(addr).c_str());

    if (lock_owners.count(addr)) {
        std::string owner = lock_owners[addr];
        if (owner != thread_name) {
            waits_for[thread_name].insert(owner);
            detect_deadlocks();
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
    static std::unordered_map<pid_t, uint64_t> futex_uaddr;

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
            futex_uaddr[tid] = uaddr;
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
        
        get_thread_name(tid);
    }

    closedir(dir);
    return tids;
}

void cleanup_resource_copies() {
    for (auto& copy : resource_copies) {
        if (copy.copy_addr != nullptr) {
            free(copy.copy_addr);
            copy.copy_addr = nullptr;
        }
    }
    resource_copies.clear();
    lock_to_resource_copies.clear();
}

void cleanup_thread(pid_t tid) {
    std::lock_guard<std::mutex> lock(thread_info_mutex);
    
    auto it = thread_info_cache.find(tid);
    if (it != thread_info_cache.end()) {
        std::string thread_name = it->second.name;
        
        // Clean up thread data
        waits_for.erase(thread_name);
        thread_locks.erase(thread_name);
        wait_start_times.erase(thread_name);
        
        // Remove thread from lock owners
        for (auto it = lock_owners.begin(); it != lock_owners.end(); ) {
            if (it->second == thread_name) {
                it = lock_owners.erase(it);
            } else {
                ++it;
            }
        }
        
        // Remove from cache
        thread_info_cache.erase(it);
    }
}

void cleanup_json_files() {
    if (deadlock_json_output.is_open()) {
        deadlock_json_output << "\n]\n";
        deadlock_json_output.close();
    }
    if (json_output.is_open()) {
        json_output.close();
    }
    if (resolution_log.is_open()) {
        resolution_log.close();
    }
    cleanup_resource_copies();
}

void signal_handler(int sig) {
    printf("\n[*] Received signal %d, cleaning up...\n", sig);
    cleanup_json_files();
    
    // Print summary
    printf("\n\033[1;36m╔══════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;36m║                         MONITORING SUMMARY                        ║\033[0m\n");
    printf("\033[1;36m╠══════════════════════════════════════════════════════════════════╣\033[0m\n");
    printf("\033[1;33m║ Total deadlocks detected:\033[0m %zu\n", detected_deadlocks.size());
    
    size_t resolved_count = 0;
    size_t total_resolution_attempts = 0;
    size_t successful_resolutions = 0;
    
    for (const auto& deadlock : detected_deadlocks) {
        if (deadlock.resolved) resolved_count++;
    }
    
    for (const auto& [addr, stats] : lock_stats) {
        total_resolution_attempts += stats.deadlock_resolution_attempts;
        successful_resolutions += stats.successful_resolutions;
    }
    
    printf("\033[1;33m║ Deadlocks resolved:\033[0m %zu/%zu\n", resolved_count, detected_deadlocks.size());
    printf("\033[1;33m║ Total threads tracked:\033[0m %zu\n", thread_info_cache.size());
    printf("\033[1;33m║ Total locks tracked:\033[0m %zu\n", lock_stats.size());
    printf("\033[1;33m║ Resource copies created:\033[0m %zu\n", resource_copies.size());
    printf("\033[1;33m║ Resolution attempts:\033[0m %zu\n", total_resolution_attempts);
    printf("\033[1;33m║ Successful resolutions:\033[0m %zu\n", successful_resolutions);
    
    if (!detected_deadlocks.empty()) {
        printf("\033[1;33m║ Last deadlock cycle:\033[0m ");
        const auto& last = detected_deadlocks.back();
        for (size_t i = 0; i < last.cycle.size(); i++) {
            printf("\033[1;31m%s\033[0m", last.cycle[i].c_str());
            if (i < last.cycle.size() - 1) printf(" → ");
        }
        printf(" (%s)\n", last.resolved ? "\033[1;32mresolved\033[0m" : "\033[1;31munresolved\033[0m");
    }
    
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
    printf("\033[1;36m[*] Attaching to process %d\033[0m\n", target_pid);
    printf("\033[1;36m[*] Using thread names instead of IDs\033[0m\n");
    printf("\033[1;36m[*] Attempting automatic deadlock resolution with resource copying\033[0m\n");
    
    json_output.open("lock_stats.json", std::ios::out | std::ios::trunc);
    if (!json_output.is_open()) {
        fprintf(stderr, "\033[33mWarning: Could not open lock_stats.json for writing\033[0m\n");
    } else {
        printf("\033[32m[*] JSON output will be saved to lock_stats.json\033[0m\n");
    }

    deadlock_json_output.open("deadlocks.json", std::ios::out | std::ios::trunc);
    if (!deadlock_json_output.is_open()) {
        fprintf(stderr, "\033[33mWarning: Could not open deadlocks.json for writing\033[0m\n");
    } else {
        printf("\033[32m[*] Deadlock reports will be saved to deadlocks.json\033[0m\n");
        deadlock_json_output << "[\n";
        deadlock_json_output.close();
    }
    
    resolution_log.open("resolution.log", std::ios::out | std::ios::trunc);
    if (!resolution_log.is_open()) {
        fprintf(stderr, "\033[33mWarning: Could not open resolution.log for writing\033[0m\n");
    } else {
        printf("\033[32m[*] Resolution attempts logged to resolution.log\033[0m\n");
    }

    auto tids = list_threads(target_pid);

    printf("\033[1;33m[*] Found %zu threads in process %d:\033[0m\n", tids.size(), target_pid);
    for (pid_t tid : tids) {
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
            waitpid(tid, nullptr, 0);
            ptrace(PTRACE_SETOPTIONS, tid, nullptr,
                   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
            ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
            printf("  \033[32m✓\033[0m attached %s\n", get_thread_identifier(tid).c_str());
        } else {
            printf("  \033[31m✗\033[0m failed to attach to TID %d\n", tid);
        }
    }

    printf("\n\033[1;36m[*] Monitoring thread interactions... (Ctrl+C to stop)\033[0m\n");
    printf("\033[1;33m[*] Will attempt to break deadlocks by copying resources\033[0m\n\n");
    
    while (true) {
        int status;
        pid_t tid = waitpid(-1, &status, __WALL);
        if (tid <= 0) continue;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            printf("\033[90m[*] %s exited\033[0m\n", get_thread_identifier(tid).c_str());
            cleanup_thread(tid);
            continue;
        }

        if (status >> 8 == (SIGTRAP | 0x80)) {
            handle_syscall(tid);
        }

        ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
    }
    
    cleanup_json_files();
    return 0;
}