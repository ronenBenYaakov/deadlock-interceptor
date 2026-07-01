#include "global_state.h"

/* ---------------- CORE ---------------- */

pid_t target_pid = 0;

std::unordered_map<pid_t, ThreadInfo> thread_info_cache;
std::mutex thread_info_mutex;

std::atomic<bool> world_stopped{false};
std::atomic<bool> monitoring_active{true};

std::mutex resolution_mutex;

std::vector<MemoryRegion> g_protected_regions;

/* ---------------- DEADLOCK GRAPH ---------------- */

std::unordered_map<uint64_t, std::vector<std::string>> futex_waiters;

std::unordered_map<std::string,
    std::unordered_map<uint64_t, Clock::time_point>> wait_start_times;

std::unordered_map<std::string,
    std::unordered_set<std::string>> waits_for;

std::unordered_map<std::string,
    std::unordered_set<uint64_t>> thread_locks;

std::unordered_map<uint64_t, std::string> lock_owners;

std::unordered_map<uint64_t, LockStats> lock_stats;

/* ---------------- OUTPUT ---------------- */

std::vector<DeadlockInfo> detected_deadlocks;
std::vector<ShadowProcess> shadow_processes;
std::vector<DeadlockResolution> resolution_history;

std::ofstream json_output;
std::ofstream deadlock_json_output;
std::ofstream resolution_log;
std::ofstream shadow_log;

size_t deadlock_counter = 0;
std::mutex output_mutex;