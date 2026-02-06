#ifndef GLOBAL_STATE_H
#define GLOBAL_STATE_H

#include "deadlock_resolver.h"
#include <mutex>
#include <vector>
#include <unordered_map>
#include <fstream>

extern pid_t target_pid;
extern std::unordered_map<pid_t, ThreadInfo> thread_info_cache;
extern std::mutex thread_info_mutex;
extern std::atomic<bool> world_stopped;
extern std::atomic<bool> monitoring_active;
extern std::mutex resolution_mutex;
extern std::vector<MemoryRegion> g_protected_regions;

extern std::unordered_map<uint64_t, std::vector<std::string>> futex_waiters;
extern std::unordered_map<std::string, std::unordered_map<uint64_t, Clock::time_point>> wait_start_times;
extern std::unordered_map<std::string, std::unordered_set<std::string>> waits_for;
extern std::unordered_map<std::string, std::unordered_set<uint64_t>> thread_locks;
extern std::unordered_map<uint64_t, std::string> lock_owners;
extern std::unordered_map<uint64_t, LockStats> lock_stats;

extern std::vector<DeadlockInfo> detected_deadlocks;
extern std::vector<ShadowProcess> shadow_processes;
extern std::vector<DeadlockResolution> resolution_history;

extern std::ofstream json_output;
extern std::ofstream deadlock_json_output;
extern std::ofstream resolution_log;
extern std::ofstream shadow_log;
extern size_t deadlock_counter;
extern std::mutex output_mutex;

#endif