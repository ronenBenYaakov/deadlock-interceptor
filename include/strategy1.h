#ifndef STRATEGY1_H
#define STRATEGY1_H
#pragma once

#include "deadlock_resolver.h"
#include <vector>
#include <string>

bool stop_the_world();
std::string choose_victim_thread(const DeadlockInfo& deadlock);
bool eliminate_other_threads_in_shadow(pid_t victim_tid);
void resume_paused_threads(pid_t victim_tid);
std::vector<MemoryRegion> initialize_private_memory(const std::vector<uint64_t>& locks);
void force_unlock_futexes(const std::vector<uint64_t>& locks);
bool cleanup_parent_process(pid_t victim_tid, const std::vector<uint64_t>& deadlock_locks);
void monitor_shadow_process(pid_t shadow_pid, pid_t victim_tid, const DeadlockInfo& deadlock);
bool resolve_deadlock_strategy1(const DeadlockInfo& deadlock);
bool emergency_deadlock_break(const DeadlockInfo& deadlock);

#endif