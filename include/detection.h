#ifndef DETECTION_H
#define DETECTION_H

#include "deadlock_resolver.h"
#include <string>
#include <vector>
#include <unordered_set>


// Custom hash function for std::pair<size_t, size_t>
struct PairHash {
    template <typename T1, typename T2>
    std::size_t operator()(const std::pair<T1, T2>& p) const {
        auto h1 = std::hash<T1>{}(p.first);
        auto h2 = std::hash<T2>{}(p.second);
        
        // Simple hash combining (can be improved)
        return h1 ^ (h2 << 1);
    }
};

// Custom equality function (optional, but good practice)
struct PairEqual {
    template <typename T1, typename T2>
    bool operator()(const std::pair<T1, T2>& a, const std::pair<T1, T2>& b) const {
        return a.first == b.first && a.second == b.second;
    }
};

bool dfs_deadlock(const std::string& thread_name,
                  std::unordered_set<std::string>& visited,
                  std::unordered_set<std::string>& stack,
                  std::vector<std::string>& cycle);
std::vector<uint64_t> find_locks_in_deadlock(const std::vector<std::string>& cycle);
void detect_and_resolve_deadlocks();
void debug_wait_for_graph();
std::vector<ConflictGroup> analyze_conflict_groups();
void print_conflict_groups(const std::vector<ConflictGroup>& groups);
std::vector<std::vector<std::string>> find_potential_deadlock_scenarios();
void analyze_lock_dependency_graph();
GroupDeadlockInfo detect_group_deadlock();
bool resolve_group_deadlock(const GroupDeadlockInfo& group_deadlock);
std::vector<size_t> find_group_cycles();
std::vector<std::string> expand_group_cycle_to_threads(const std::vector<size_t>& group_cycle);

#endif