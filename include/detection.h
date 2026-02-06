#ifndef DETECTION_H
#define DETECTION_H

#include "deadlock_resolver.h"
#include <string>
#include <vector>
#include <unordered_set>

bool dfs_deadlock(const std::string& thread_name,
                  std::unordered_set<std::string>& visited,
                  std::unordered_set<std::string>& stack,
                  std::vector<std::string>& cycle);
std::vector<uint64_t> find_locks_in_deadlock(const std::vector<std::string>& cycle);
void detect_and_resolve_deadlocks();
void debug_wait_for_graph();

#endif