#ifndef DEADLOCK_RESOLVER_H
#define DEADLOCK_RESOLVER_H

#include <sys/types.h>
#include <sys/user.h>  // Add this for user_regs_struct
#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <atomic>

// Forward declaration for FPU state (platform-specific)
// We'll handle this differently
struct FPUStateWrapper;

using Clock = std::chrono::steady_clock;

struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    std::string perms;
    std::string name;
};

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