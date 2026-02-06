#include "detection.h"
#include "global_state.h"
#include "strategy1.h"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <helpers.h>

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
        
        for (const auto& [lock_addr, owner] : lock_owners) {
            if (owner == thread_name) {
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


void debug_wait_for_graph() {
    std::cout << "\n[DEBUG] Wait-for graph:\n";
    for (const auto& [waiter, waits] : waits_for) {
        std::cout << "  " << waiter << " waits for:\n";
        for (const auto& target : waits) {
            std::cout << "    -> " << target << "\n";
        }
    }
    std::cout << "\n[DEBUG] Lock owners:\n";
    for (const auto& [lock, owner] : lock_owners) {
        std::cout << "  Lock " << to_hex_string(lock) << " owned by " << owner << "\n";
    }
}



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
                        
                        std::cout << "\033[1;31m[DEADLOCK #" << deadlock_counter << " DETECTED]\033[0m\n";
                        
                        if (resolve_deadlock_strategy1(deadlock)) {
                            deadlock.resolved = true;
                            std::cout << "\033[1;32m✓ Resolved via Strategy 1\033[0m\n";
                        } else {
                            std::cout << "\033[1;33mStrategy 1 failed, using emergency break\033[0m\n";
                            if (emergency_deadlock_break(deadlock)) {
                                deadlock.resolved = true;
                                std::cout << "\033[1;32m✓ Emergency break successful\033[0m\n";
                            }
                        }
                        
                        detected_deadlocks.push_back(deadlock);
                    }
                }
            }
        }
    }
}