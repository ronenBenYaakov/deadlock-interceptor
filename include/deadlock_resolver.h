#ifndef DEADLOCK_RESOLVER_H
#define DEADLOCK_RESOLVER_H

#include <sys/types.h>
#include <sys/user.h>
#include <chrono>
#include <string>
#include <vector>
#include <helpers.h>
#include <unordered_map>
#include <unordered_set>
#include <atomic>

struct ConflictGroup {
    size_t group_id;
    std::unordered_set<std::string> threads;  // Threads in this group
    std::unordered_set<uint64_t> locks_held;  // Locks held by threads in this group
    std::unordered_set<uint64_t> locks_wanted; // Locks wanted by threads in this group
    std::unordered_set<size_t> conflicting_groups; // Groups that conflict with this one
    
    bool conflicts_with(const ConflictGroup& other) const {
        // Groups conflict if they want locks held by each other
        for (uint64_t lock : locks_held) {
            if (other.locks_wanted.count(lock)) return true;
        }
        for (uint64_t lock : locks_wanted) {
            if (other.locks_held.count(lock)) return true;
        }
        return false;
    }
    
    std::string to_string() const {
        std::string result = "Group " + std::to_string(group_id) + ": ";
        result += "[Threads: ";
        for (const auto& t : threads) {
            result += t + " ";
        }
        result += "] [Held: ";
        for (uint64_t lock : locks_held) {
            result += to_hex_string(lock) + " ";
        }
        result += "] [Wanted: ";
        for (uint64_t lock : locks_wanted) {
            result += to_hex_string(lock) + " ";
        }
        result += "]";
        return result;
    }
};

struct GroupResolution {
    size_t group_id;
    std::unordered_set<std::string> threads;
    std::unordered_set<uint64_t> held_locks;
    std::unordered_set<uint64_t> wanted_locks;
    std::unordered_set<size_t> conflicting_groups;
    std::string selected_victim;
    pid_t victim_tid;
    bool resolved = false;
    std::chrono::system_clock::time_point resolution_time;
};

struct GroupDeadlockInfo {
    std::vector<size_t> group_cycle;
    std::vector<std::string> thread_cycle;
    std::vector<uint64_t> involved_locks;
    std::chrono::system_clock::time_point detection_time;
    size_t deadlock_id;
    bool resolved = false;
    std::vector<GroupResolution> group_resolutions;
};

struct FPUStateWrapper;

using Clock = std::chrono::steady_clock;



struct ThreadSnapshot {
    struct user_regs_struct regs;  // Now complete type
    std::vector<uint8_t> fpregs_data;  // Store FPU as raw bytes
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
    ShadowProcess(ShadowProcess&& other) noexcept;
    ShadowProcess& operator=(ShadowProcess&& other) noexcept;
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

#endif