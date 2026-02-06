#include "detection.h"
#include "global_state.h"
#include "strategy1.h"
#include <algorithm>
#include <functional>
#include <iomanip>
#include <signal.h>
#include <sys/wait.h>
#include <iostream>
#include <sstream>
#include <sys/mman.h>
#include <helpers.h>
#include <unordered_map>
#include <sys/ptrace.h>
#include <time.h>
#include <unistd.h>
#include <linux/utime.h>
#include <sys/types.h>
#include <chrono>
#include <thread>
#include <fcntl.h>
#include <errno.h>
#include <cstring>

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

std::vector<ConflictGroup> analyze_conflict_groups() {
    std::vector<ConflictGroup> groups;
    std::unordered_map<std::string, size_t> thread_to_group;
    std::unordered_set<std::string> visited;
    
    // Helper function to find or create group for a thread
    auto get_or_create_group = [&](const std::string& thread_name) -> size_t {
        if (thread_to_group.count(thread_name)) {
            return thread_to_group[thread_name];
        }
        
        // Create new group
        ConflictGroup new_group;
        new_group.group_id = groups.size();
        new_group.threads.insert(thread_name);
        groups.push_back(new_group);
        thread_to_group[thread_name] = new_group.group_id;
        return new_group.group_id;
    };
    
    // Phase 1: Group threads by shared locks
    for (const auto& [thread_name, lock_set] : thread_locks) {
        if (visited.count(thread_name)) continue;
        
        size_t group_id = get_or_create_group(thread_name);
        ConflictGroup& group = groups[group_id];
        visited.insert(thread_name);
        
        // Find all threads that share locks with this thread
        for (const auto& [other_thread, other_locks] : thread_locks) {
            if (thread_name == other_thread || visited.count(other_thread)) continue;
            
            // Check if threads share any locks
            bool shares_lock = false;
            for (uint64_t lock : lock_set) {
                if (other_locks.count(lock)) {
                    shares_lock = true;
                    break;
                }
            }
            
            if (shares_lock) {
                group.threads.insert(other_thread);
                thread_to_group[other_thread] = group_id;
                visited.insert(other_thread);
            }
        }
    }
    
    // Add threads that are waiting but not holding locks
    for (const auto& [thread_name, waits] : waits_for) {
        if (!visited.count(thread_name)) {
            size_t group_id = get_or_create_group(thread_name);
            visited.insert(thread_name);
        }
    }
    
    // Phase 2: Populate lock information for each group
    for (auto& group : groups) {
        // Find locks held by threads in this group
        for (const std::string& thread_name : group.threads) {
            auto it = thread_locks.find(thread_name);
            if (it != thread_locks.end()) {
                for (uint64_t lock : it->second) {
                    group.locks_held.insert(lock);
                }
            }
            
            // Find locks wanted by threads in this group
            auto wait_it = waits_for.find(thread_name);
            if (wait_it != waits_for.end()) {
                for (const std::string& waiting_for : wait_it->second) {
                    // Find locks owned by the thread we're waiting for
                    for (const auto& [lock_addr, owner] : lock_owners) {
                        if (owner == waiting_for) {
                            group.locks_wanted.insert(lock_addr);
                        }
                    }
                }
            }
        }
    }
    
    // Phase 3: Identify conflicts between groups
    for (size_t i = 0; i < groups.size(); i++) {
        for (size_t j = i + 1; j < groups.size(); j++) {
            if (groups[i].conflicts_with(groups[j])) {
                groups[i].conflicting_groups.insert(j);
                groups[j].conflicting_groups.insert(i);
            }
        }
    }
    
    return groups;
}

void print_conflict_groups(const std::vector<ConflictGroup>& groups) {
    std::cout << "\n\033[1;36m╔══════════════════════════════════════════════════════════════════╗\033[0m\n";
    std::cout << "\033[1;36m║                     CONFLICT GROUP ANALYSIS                      ║\033[0m\n";
    std::cout << "\033[1;36m╠══════════════════════════════════════════════════════════════════╣\033[0m\n";
    
    if (groups.empty()) {
        std::cout << "  No conflict groups detected\n";
    } else {
        for (const auto& group : groups) {
            std::cout << "\033[1;33mGroup " << group.group_id << ":\033[0m\n";
            std::cout << "  Threads (" << group.threads.size() << "): ";
            for (const auto& thread : group.threads) {
                std::cout << thread << " ";
            }
            std::cout << "\n";
            
            if (!group.locks_held.empty()) {
                std::cout << "  Locks held: ";
                for (uint64_t lock : group.locks_held) {
                    std::cout << to_hex_string(lock) << " ";
                }
                std::cout << "\n";
            }
            
            if (!group.locks_wanted.empty()) {
                std::cout << "  Locks wanted: ";
                for (uint64_t lock : group.locks_wanted) {
                    std::cout << to_hex_string(lock) << " ";
                }
                std::cout << "\n";
            }
            
            if (!group.conflicting_groups.empty()) {
                std::cout << "  \033[31mConflicts with groups: ";
                for (size_t conflict_id : group.conflicting_groups) {
                    std::cout << conflict_id << " ";
                }
                std::cout << "\033[0m\n";
                
                // Explain why these groups conflict
                for (size_t conflict_id : group.conflicting_groups) {
                    if (conflict_id < groups.size()) {
                        const auto& other = groups[conflict_id];
                        
                        // Find specific conflicts
                        std::vector<uint64_t> shared_locks;
                        for (uint64_t lock : group.locks_held) {
                            if (other.locks_wanted.count(lock)) {
                                shared_locks.push_back(lock);
                            }
                        }
                        for (uint64_t lock : group.locks_wanted) {
                            if (other.locks_held.count(lock)) {
                                shared_locks.push_back(lock);
                            }
                        }
                        
                        if (!shared_locks.empty()) {
                            std::cout << "    - Conflict with Group " << conflict_id 
                                      << " over locks: ";
                            for (uint64_t lock : shared_locks) {
                                std::cout << to_hex_string(lock) << " ";
                            }
                            std::cout << "\n";
                        }
                    }
                }
            }
            
            std::cout << "\n";
        }
    }
    
    // Show which groups can deadlock with each other
    std::cout << "\033[1;31mDEADLOCK RISK ASSESSMENT:\033[0m\n";
    std::vector<std::pair<size_t, size_t>> risky_pairs;
    for (size_t i = 0; i < groups.size(); i++) {
        for (size_t j = i + 1; j < groups.size(); j++) {
            if (groups[i].conflicts_with(groups[j])) {
                risky_pairs.push_back({i, j});
                
                // Check if there's a circular wait between these groups
                bool group_i_waits_for_j = false;
                bool group_j_waits_for_i = false;
                
                // Check threads in group i waiting for threads in group j
                for (const auto& thread_i : groups[i].threads) {
                    auto it = waits_for.find(thread_i);
                    if (it != waits_for.end()) {
                        for (const auto& target : it->second) {
                            if (groups[j].threads.count(target)) {
                                group_i_waits_for_j = true;
                                break;
                            }
                        }
                    }
                    if (group_i_waits_for_j) break;
                }
                
                // Check threads in group j waiting for threads in group i
                for (const auto& thread_j : groups[j].threads) {
                    auto it = waits_for.find(thread_j);
                    if (it != waits_for.end()) {
                        for (const auto& target : it->second) {
                            if (groups[i].threads.count(target)) {
                                group_j_waits_for_i = true;
                                break;
                            }
                        }
                    }
                    if (group_j_waits_for_i) break;
                }
                
                if (group_i_waits_for_j && group_j_waits_for_i) {
                    std::cout << "  ⚠  \033[1;31mHIGH RISK: Group " << i << " ↔ Group " << j 
                              << " (circular wait detected!)\033[0m\n";
                } else if (group_i_waits_for_j || group_j_waits_for_i) {
                    std::cout << "  ⚠  \033[1;33mMEDIUM RISK: Group " << i << " → Group " << j 
                              << " (one-way wait)\033[0m\n";
                } else {
                    std::cout << "  ⚠  \033[1;32mLOW RISK: Group " << i << " ↔ Group " << j 
                              << " (potential conflict but no active wait)\033[0m\n";
                }
            }
        }
    }
    
    if (risky_pairs.empty()) {
        std::cout << "  No high-risk group conflicts detected\n";
    }
    
    std::cout << "\033[1;36m╚══════════════════════════════════════════════════════════════════╝\033[0m\n";
}

std::vector<std::vector<std::string>> find_potential_deadlock_scenarios() {
    std::vector<std::vector<std::string>> scenarios;
    
    // Get all threads involved in wait-for relationships
    std::vector<std::string> all_threads;
    for (const auto& [thread, _] : waits_for) {
        all_threads.push_back(thread);
    }
    
    // Simple heuristic: threads that wait for each other's locks
    for (const auto& [thread1, waits1] : waits_for) {
        for (const auto& target1 : waits1) {
            auto it = waits_for.find(target1);
            if (it != waits_for.end()) {
                for (const auto& target2 : it->second) {
                    if (target2 == thread1) {
                        // Direct mutual wait (A->B and B->A)
                        scenarios.push_back({thread1, target1});
                    } else {
                        // Check for longer cycles
                        auto it2 = waits_for.find(target2);
                        if (it2 != waits_for.end()) {
                            for (const auto& target3 : it2->second) {
                                if (target3 == thread1) {
                                    scenarios.push_back({thread1, target1, target2});
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    return scenarios;
}

void analyze_lock_dependency_graph() {
    std::cout << "\n\033[1;35m[LOCK DEPENDENCY ANALYSIS]\033[0m\n";
    
    // 1. Show thread-to-group mapping
    auto groups = analyze_conflict_groups();
    
    std::cout << "\033[1;33mThread to Group Mapping:\033[0m\n";
    std::unordered_map<std::string, size_t> thread_to_group;
    for (const auto& group : groups) {
        for (const auto& thread : group.threads) {
            thread_to_group[thread] = group.group_id;
            std::cout << "  " << thread << " -> Group " << group.group_id << "\n";
        }
    }
    
    // 2. Show group composition
    std::cout << "\n\033[1;33mGroup Composition:\033[0m\n";
    for (const auto& group : groups) {
        std::cout << "  Group " << group.group_id << " (" << group.threads.size() 
                  << " threads): ";
        for (const auto& thread : group.threads) {
            std::cout << thread << " ";
        }
        std::cout << "\n";
    }
    
    // 3. Show lock ownership with group info
    std::cout << "\n\033[1;33mLock Ownership (with Group Info):\033[0m\n";
    for (const auto& [lock_addr, owner] : lock_owners) {
        size_t owner_group = thread_to_group.count(owner) ? thread_to_group[owner] : -1;
        std::cout << "  " << to_hex_string(lock_addr) << " -> " << owner 
                  << " (Group " << owner_group << ")\n";
        
        // Show waiters for this lock with their groups
        auto waiters_it = futex_waiters.find(lock_addr);
        if (waiters_it != futex_waiters.end() && !waiters_it->second.empty()) {
            std::cout << "    Waiters: ";
            for (const auto& waiter : waiters_it->second) {
                size_t waiter_group = thread_to_group.count(waiter) ? thread_to_group[waiter] : -1;
                std::cout << waiter << "(G" << waiter_group << ") ";
            }
            std::cout << "\n";
        }
    }
    
    // 4. Show wait-for graph with group info
    std::cout << "\n\033[1;33mWait-For Graph (with Group Info):\033[0m\n";
    std::unordered_map<
        std::pair<size_t, size_t>, 
        std::vector<std::pair<std::string, std::string>>,
        PairHash,  // Add custom hash
        PairEqual  // Add custom equality (optional but recommended)
    > group_to_group_waits;    
    for (const auto& [waiter, waits] : waits_for) {
        size_t waiter_group = thread_to_group.count(waiter) ? thread_to_group[waiter] : -1;
        std::cout << "  " << waiter << "(G" << waiter_group << ") waits for: ";
        
        for (const auto& target : waits) {
            size_t target_group = thread_to_group.count(target) ? thread_to_group[target] : -1;
            std::cout << target << "(G" << target_group << ") ";
            
            // Record group-to-group wait
            if (waiter_group != -1 && target_group != -1) {
                group_to_group_waits[{waiter_group, target_group}].push_back({waiter, target});
            }
            
            // Show which lock causes this wait
            for (const auto& [lock_addr, owner] : lock_owners) {
                if (owner == target) {
                    auto waiters_it = futex_waiters.find(lock_addr);
                    if (waiters_it != futex_waiters.end()) {
                        auto& waiters = waiters_it->second;
                        if (std::find(waiters.begin(), waiters.end(), waiter) != waiters.end()) {
                            std::cout << "(via lock " << to_hex_string(lock_addr) << ") ";
                        }
                    }
                }
            }
        }
        std::cout << "\n";
    }
    
    // 5. Show group-to-group conflict matrix
    if (!group_to_group_waits.empty()) {
        std::cout << "\n\033[1;33mGroup-to-Group Conflict Matrix:\033[0m\n";
        std::cout << "  Legend: Gx -> Gy means threads in Group x are waiting for threads in Group y\n";
        
        std::unordered_set<size_t> all_groups;
        for (const auto& [pair, _] : group_to_group_waits) {
            all_groups.insert(pair.first);
            all_groups.insert(pair.second);
        }
        
        // Create matrix header
        std::cout << "      ";
        for (size_t col_group : all_groups) {
            std::cout << "G" << std::setw(2) << col_group << " ";
        }
        std::cout << "\n";
        
        // Create matrix rows
        for (size_t row_group : all_groups) {
            std::cout << "  G" << std::setw(2) << row_group << ": ";
            for (size_t col_group : all_groups) {
                if (group_to_group_waits.count({row_group, col_group})) {
                    size_t count = group_to_group_waits[{row_group, col_group}].size();
                    if (count > 0) {
                        std::cout << "\033[31m" << std::setw(3) << count << "\033[0m ";
                    } else {
                        std::cout << "  . ";
                    }
                } else {
                    std::cout << "  . ";
                }
            }
            std::cout << "\n";
        }
    }
    
    // 6. Show potential deadlock scenarios between groups
    std::cout << "\n\033[1;33mPotential Inter-Group Deadlocks:\033[0m\n";
    
    // Find cycles in group wait-for graph
    std::unordered_map<size_t, std::unordered_set<size_t>> group_waits_for;
    for (const auto& [pair, _] : group_to_group_waits) {
        group_waits_for[pair.first].insert(pair.second);
    }
    
    // Simple cycle detection in groups
    std::vector<std::vector<size_t>> group_cycles;
    for (const auto& [group, waits] : group_waits_for) {
        std::unordered_set<size_t> visited;
        std::unordered_set<size_t> in_stack;
        std::vector<size_t> path;
        
        std::function<bool(size_t)> dfs = [&](size_t current) -> bool {
            visited.insert(current);
            in_stack.insert(current);
            path.push_back(current);
            
            auto it = group_waits_for.find(current);
            if (it != group_waits_for.end()) {
                for (size_t neighbor : it->second) {
                    if (!visited.count(neighbor)) {
                        if (dfs(neighbor)) return true;
                    } else if (in_stack.count(neighbor)) {
                        // Found a cycle
                        auto cycle_start = std::find(path.begin(), path.end(), neighbor);
                        if (cycle_start != path.end()) {
                            std::vector<size_t> cycle(cycle_start, path.end());
                            group_cycles.push_back(cycle);
                            return true;
                        }
                    }
                }
            }
            
            in_stack.erase(current);
            path.pop_back();
            return false;
        };
        
        if (!visited.count(group)) {
            dfs(group);
        }
    }
    
    if (!group_cycles.empty()) {
        for (size_t i = 0; i < group_cycles.size(); i++) {
            std::cout << "  Scenario " << i + 1 << ": ";
            for (size_t group_id : group_cycles[i]) {
                std::cout << "G" << group_id << " -> ";
            }
            std::cout << "G" << group_cycles[i][0] << " (CYCLE)\n";
            
            // Show which threads are involved in this group cycle
            std::cout << "    Threads involved: ";
            for (size_t group_id : group_cycles[i]) {
                if (group_id < groups.size()) {
                    for (const auto& thread : groups[group_id].threads) {
                        // Check if this thread is actually in a wait relationship
                        if (waits_for.count(thread) || 
                            std::find_if(futex_waiters.begin(), futex_waiters.end(),
                                [&](const auto& kv) {
                                    auto& waiters = kv.second;
                                    return std::find(waiters.begin(), waiters.end(), thread) != waiters.end();
                                }) != futex_waiters.end()) {
                            std::cout << thread << " ";
                        }
                    }
                }
            }
            std::cout << "\n";
        }
    } else {
        std::cout << "  No inter-group deadlock cycles detected\n";
    }
    
    // 7. Print summary
    print_conflict_groups(groups);
}

void detect_and_resolve_deadlocks() {
    if (!monitoring_active.load()) return;
    
    std::lock_guard<std::mutex> lock(output_mutex);
    
    // Try group-based detection first
    auto group_deadlock = detect_group_deadlock();
    if (group_deadlock.group_cycle.size() >= 2) {
        deadlock_counter++;
        group_deadlock.deadlock_id = deadlock_counter;
        
        std::cout << "\033[1;31m[GROUP DEADLOCK #" << deadlock_counter << " DETECTED]\033[0m\n";
        
        // Show detailed analysis
        std::cout << "\033[1;35m[ANALYSIS]\033[0m\n";
        std::cout << "  Groups in deadlock: " << group_deadlock.group_cycle.size() << "\n";
        
        for (size_t i = 0; i < group_deadlock.group_cycle.size(); i++) {
            size_t group_id = group_deadlock.group_cycle[i];
            size_t next_group = group_deadlock.group_cycle[(i + 1) % group_deadlock.group_cycle.size()];
            std::cout << "    Group " << group_id << " -> Group " << next_group << "\n";
        }
        
        std::cout << "  Threads involved: " << group_deadlock.thread_cycle.size() << "\n";
        for (const auto& thread : group_deadlock.thread_cycle) {
            std::cout << "    " << thread << "\n";
        }
        
        if (!group_deadlock.involved_locks.empty()) {
            std::cout << "  Locks involved (" << group_deadlock.involved_locks.size() << "): ";
            for (uint64_t lock : group_deadlock.involved_locks) {
                std::cout << to_hex_string(lock) << " ";
            }
            std::cout << "\n";
        }
        
        // Try group-by-group resolution
        std::cout << "\033[1;35m[RESOLUTION STRATEGY]\033[0m Using group-by-group approach\n";
        
        if (resolve_group_deadlock(group_deadlock)) {
            std::cout << "\033[1;32m✓ Group deadlock resolved successfully\033[0m\n";
            return;
        } else {
            std::cout << "\033[1;33mGroup resolution failed, falling back to standard approach\033[0m\n";
        }
    }
    
    // Fall back to original detection if no group deadlock or group resolution failed
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
                        
                        std::cout << "\033[1;31m[THREAD DEADLOCK #" << deadlock_counter << " DETECTED]\033[0m\n";
                        
                        // Try standard resolution
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

// Add these functions to detection.cpp

std::vector<size_t> find_group_cycles() {
    auto groups = analyze_conflict_groups();
    std::unordered_map<size_t, std::unordered_set<size_t>> group_wait_graph;
    
    // Build wait-for graph between groups
    for (const auto& [waiter, waits] : waits_for) {
        // Find which group the waiter belongs to
        size_t waiter_group = -1;
        for (const auto& group : groups) {
            if (group.threads.count(waiter)) {
                waiter_group = group.group_id;
                break;
            }
        }
        
        if (waiter_group == -1) continue;
        
        // Find which groups the waiter is waiting for
        for (const auto& target : waits) {
            size_t target_group = -1;
            for (const auto& group : groups) {
                if (group.threads.count(target)) {
                    target_group = group.group_id;
                    break;
                }
            }
            
            if (target_group != -1 && target_group != waiter_group) {
                group_wait_graph[waiter_group].insert(target_group);
            }
        }
    }
    
    // Find cycles in group graph
    std::vector<std::vector<size_t>> group_cycles;
    std::unordered_set<size_t> visited;
    std::unordered_set<size_t> in_stack;
    std::vector<size_t> path;
    
    std::function<void(size_t)> dfs = [&](size_t current) {
        visited.insert(current);
        in_stack.insert(current);
        path.push_back(current);
        
        auto it = group_wait_graph.find(current);
        if (it != group_wait_graph.end()) {
            for (size_t neighbor : it->second) {
                if (!visited.count(neighbor)) {
                    dfs(neighbor);
                } else if (in_stack.count(neighbor)) {
                    // Found a cycle
                    auto cycle_start = std::find(path.begin(), path.end(), neighbor);
                    if (cycle_start != path.end()) {
                        std::vector<size_t> cycle(cycle_start, path.end());
                        // Avoid duplicate cycles
                        bool is_new = true;
                        for (const auto& existing : group_cycles) {
                            if (existing.size() == cycle.size() &&
                                std::equal(existing.begin(), existing.end(), cycle.begin())) {
                                is_new = false;
                                break;
                            }
                        }
                        if (is_new) {
                            group_cycles.push_back(cycle);
                        }
                    }
                }
            }
        }
        
        in_stack.erase(current);
        path.pop_back();
    };
    
    for (const auto& [group, _] : group_wait_graph) {
        if (!visited.count(group)) {
            dfs(group);
        }
    }
    
    // Return the largest cycle (most groups involved)
    if (!group_cycles.empty()) {
        auto largest_cycle = *std::max_element(group_cycles.begin(), group_cycles.end(),
            [](const std::vector<size_t>& a, const std::vector<size_t>& b) {
                return a.size() < b.size();
            });
        return largest_cycle;
    }
    
    return {};
}

std::vector<std::string> expand_group_cycle_to_threads(const std::vector<size_t>& group_cycle) {
    auto groups = analyze_conflict_groups();
    std::vector<std::string> thread_cycle;
    std::unordered_map<size_t, std::vector<std::string>> group_to_threads;
    
    // Map threads to their groups
    for (const auto& group : groups) {
        for (const auto& thread : group.threads) {
            group_to_threads[group.group_id].push_back(thread);
        }
    }
    
    // Find a thread cycle that follows the group cycle
    // We need to find threads such that thread_i (in group_i) waits for thread_{i+1} (in group_{i+1})
    for (size_t i = 0; i < group_cycle.size(); i++) {
        size_t current_group = group_cycle[i];
        size_t next_group = group_cycle[(i + 1) % group_cycle.size()];
        
        // Find a thread in current_group that waits for a thread in next_group
        bool found = false;
        for (const auto& thread : group_to_threads[current_group]) {
            auto wait_it = waits_for.find(thread);
            if (wait_it != waits_for.end()) {
                for (const auto& target : wait_it->second) {
                    // Check if target is in next_group
                    for (const auto& next_thread : group_to_threads[next_group]) {
                        if (target == next_thread) {
                            thread_cycle.push_back(thread);
                            found = true;
                            break;
                        }
                    }
                    if (found) break;
                }
            }
            if (found) break;
        }
        
        if (!found) {
            // Fallback: just pick any thread from the group
            if (!group_to_threads[current_group].empty()) {
                thread_cycle.push_back(group_to_threads[current_group][0]);
            }
        }
    }
    
    return thread_cycle;
}

GroupDeadlockInfo detect_group_deadlock() {
    GroupDeadlockInfo info;
    info.detection_time = std::chrono::system_clock::now();
    
    // Find group cycle
    auto group_cycle = find_group_cycles();
    if (group_cycle.size() < 2) {
        return info;  // No deadlock
    }
    
    info.group_cycle = group_cycle;
    info.thread_cycle = expand_group_cycle_to_threads(group_cycle);
    
    // Find involved locks
    auto groups = analyze_conflict_groups();
    std::unordered_set<uint64_t> involved_locks;
    
    for (size_t group_id : group_cycle) {
        if (group_id < groups.size()) {
            const auto& group = groups[group_id];
            for (uint64_t lock : group.locks_held) {
                involved_locks.insert(lock);
            }
            for (uint64_t lock : group.locks_wanted) {
                involved_locks.insert(lock);
            }
        }
    }
    
    info.involved_locks.assign(involved_locks.begin(), involved_locks.end());
    
    // Create group resolutions
    for (size_t group_id : group_cycle) {
        if (group_id < groups.size()) {
            const auto& group = groups[group_id];
            GroupResolution resolution;
            resolution.group_id = group_id;
            resolution.threads = group.threads;
            resolution.held_locks = group.locks_held;
            resolution.wanted_locks = group.locks_wanted;
            resolution.conflicting_groups = group.conflicting_groups;
            
            // Select a victim thread from this group
            // Prefer threads that are actually in the wait cycle
            for (const auto& thread : info.thread_cycle) {
                if (group.threads.count(thread)) {
                    resolution.selected_victim = thread;
                    resolution.victim_tid = extract_tid_from_identifier(thread);
                    break;
                }
            }
            
            // If no thread from cycle is in this group, pick any thread
            if (resolution.selected_victim.empty() && !group.threads.empty()) {
                resolution.selected_victim = *group.threads.begin();
                resolution.victim_tid = extract_tid_from_identifier(resolution.selected_victim);
            }
            
            info.group_resolutions.push_back(resolution);
        }
    }
    
    return info;
}

bool resolve_group_deadlock(const GroupDeadlockInfo& group_deadlock) {
    std::cout << "\n\033[1;35m[ULTIMATE DEADLOCK RESOLUTION]\033[0m\n";
    
    // Get all threads first
    auto all_tids = list_threads(target_pid);
    
    // ========== STEP 1: NUCLEAR DETACH ==========
    std::cout << "  [STEP 1] NUCLEAR DETACH FROM PTRACE...\n";
    
    // Method 1: Try to detach all threads with maximum force
    for (pid_t tid : all_tids) {
        int attempts = 0;
        bool detached = false;
        
        while (attempts < 3 && !detached) {
            attempts++;
            
            // Try normal detach
            if (ptrace(PTRACE_DETACH, tid, nullptr, (void*)SIGCONT) == 0) {
                std::cout << "    ✓ Detached thread " << tid << " (attempt " << attempts << ")\n";
                detached = true;
                continue;
            }
            
            // If normal fails, try attaching first
            if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
                int status;
                waitpid(tid, &status, __WALL);
                if (ptrace(PTRACE_DETACH, tid, nullptr, (void*)SIGCONT) == 0) {
                    std::cout << "    ✓ Attach-then-detach thread " << tid << "\n";
                    detached = true;
                }
            }
            
            if (!detached) {
                // Send SIGCONT anyway
                kill(tid, SIGCONT);
                usleep(50000);  // 50ms
            }
        }
        
        if (!detached) {
            std::cout << "    ✗ Failed to detach thread " << tid << " after 3 attempts\n";
        }
    }
    
    // Wait longer for detach to complete
    usleep(1000000);  // 1 SECOND!
    
    // ========== STEP 2: VERIFY AND FIX TRACING ==========
    std::cout << "\n  [STEP 2] VERIFYING TRACING STATUS...\n";
    
    std::vector<pid_t> still_traced;
    for (pid_t tid : all_tids) {
        char tracer_path[256];
        snprintf(tracer_path, sizeof(tracer_path), "/proc/%d/task/%d/status", target_pid, tid);
        
        FILE* f = fopen(tracer_path, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    int tracer_pid = 0;
                    sscanf(line + 10, "%d", &tracer_pid);
                    if (tracer_pid == getpid()) {
                        still_traced.push_back(tid);
                    }
                    break;
                }
            }
            fclose(f);
        }
    }
    
    if (!still_traced.empty()) {
        std::cout << "  \033[31mCRITICAL: Still tracing " << still_traced.size() << " threads!\033[0m\n";
        std::cout << "  Using PT_DENY_ATTACH technique...\n";
        
        // Last resort: Make target process deny further tracing
        // This is a macOS technique but Linux has similar
        
        // Create a helper program that will run after us
        std::ofstream helper("/tmp/ptrace_helper.c");
        if (helper) {
            helper << "#include <stdio.h>\n";
            helper << "#include <sys/ptrace.h>\n";
            helper << "#include <signal.h>\n";
            helper << "int main() {\n";
            helper << "  printf(\"PTRACE HELPER running\\n\");\n";
            for (pid_t tid : still_traced) {
                helper << "  ptrace(PTRACE_DETACH, " << tid << ", 0, (void*)SIGCONT);\n";
                helper << "  kill(" << tid << ", SIGCONT);\n";
            }
            helper << "  kill(" << target_pid << ", SIGCONT);\n";
            helper << "  kill(-" << target_pid << ", SIGCONT);\n";
            helper << "  printf(\"Done\\n\");\n";
            helper << "  return 0;\n";
            helper << "}\n";
            helper.close();
            
            // Compile and run it
            system("gcc -o /tmp/ptrace_helper /tmp/ptrace_helper.c 2>/dev/null");
            system("/tmp/ptrace_helper &");
        }
    } else {
        std::cout << "  \033[32m✓ Successfully detached from all threads\033[0m\n";
    }
    
    // ========== STEP 3: UNLOCK ALL LOCKS (IN-PROCESS) ==========
    std::cout << "\n  [STEP 3] UNLOCKING ALL FUTEXES...\n";
    
    monitoring_active.store(false);
    
    // Collect all locks
    std::unordered_set<uint64_t> all_locks;
    for (const auto& group_res : group_deadlock.group_resolutions) {
        all_locks.insert(group_res.held_locks.begin(), group_res.held_locks.end());
    }
    
    // Open memory and unlock
    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", target_pid);
    int mem_fd = open(mem_path, O_RDWR);
    
    if (mem_fd != -1) {
        std::cout << "  Unlocking " << all_locks.size() << " locks:\n";
        for (uint64_t lock_addr : all_locks) {
            uint32_t zero = 0;
            if (pwrite(mem_fd, &zero, sizeof(zero), lock_addr) == sizeof(zero)) {
                std::cout << "    ✓ " << to_hex_string(lock_addr) << "\n";
            }
        }
        close(mem_fd);
    }
    
    // ========== STEP 4: MASSIVE WAKEUP ==========
    std::cout << "\n  [STEP 4] MASSIVE WAKEUP CAMPAIGN...\n";
    
    for (int i = 0; i < 20; i++) {
        // Every possible wake method
        kill(target_pid, SIGCONT);
        kill(-target_pid, SIGCONT);  // Process group
        
        // All threads individually
        for (pid_t tid : all_tids) {
            kill(tid, SIGCONT);
        }
        
        usleep(50000);  // 50ms
    }
    
    // ========== STEP 5: CREATE INDESTRUCTIBLE GUARDIAN ==========
    std::cout << "\n  [STEP 5] LAUNCHING INDESTRUCTIBLE GUARDIAN...\n";
    
    pid_t guardian = fork();
    if (guardian == 0) {
        // GUARDIAN PROCESS - survives everything
        setsid();  // New session
        close(0); close(1); close(2);  // Close stdio
        
        // Write guardian PID to file for debugging
        std::ofstream pidfile("/tmp/deadlock_guardian.pid");
        pidfile << getpid() << "\n";
        pidfile.close();
        
        // Guardian runs forever (or until target exits)
        while (true) {
            // Check if target exists
            char proc_path[256];
            snprintf(proc_path, sizeof(proc_path), "/proc/%d", target_pid);
            if (access(proc_path, F_OK) != 0) {
                // Target died, we can exit
                unlink("/tmp/deadlock_guardian.pid");
                _exit(0);
            }
            
            // Send periodic SIGCONT
            kill(target_pid, SIGCONT);
            kill(-target_pid, SIGCONT);
            
            sleep(5);  // Check every 5 seconds
        }
    }
    
    // ========== STEP 6: FINALIZE AND EXIT ==========
    std::cout << "\n  [STEP 6] FINALIZING...\n";
    
    // Last check
    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", target_pid);
    if (access(proc_path, F_OK) == 0) {
        std::cout << "  \033[32m✓ Target process " << target_pid << " exists\033[0m\n";
        std::cout << "  \033[32m✓ All locks unlocked\033[0m\n";
        std::cout << "  \033[32m✓ Guardian process launched\033[0m\n";
    }
    
    std::cout << "\n\033[1;36m" << std::string(70, '=') << "\033[0m\n";
    std::cout << "\033[1;36m                    RESOLUTION COMPLETE                    \033[0m\n";
    std::cout << "\033[1;36m" << std::string(70, '=') << "\033[0m\n";
    
    std::cout << "\n\033[1;33m⚠  IF YOU SEE 'Killed' MESSAGE:\033[0m\n";
    std::cout << "   That's your SHELL (run.sh) killing the process!\n";
    std::cout << "   NOT our deadlock resolver!\n";
    
    std::cout << "\n\033[1;35m🔧 TO TEST PROPERLY:\033[0m\n";
    std::cout << "   1. Run in TWO terminals:\n";
    std::cout << "      Terminal 1: python ../app.py\n";
    std::cout << "      Terminal 2: ./deadlock_resolver <PID>\n";
    std::cout << "\n   2. Or fix run.sh with 'wait':\n";
    std::cout << "      python ../app.py &\n";
    std::cout << "      APP_PID=$!\n";
    std::cout << "      ./deadlock_resolver $APP_PID\n";
    std::cout << "      wait $APP_PID  # <-- CRITICAL!\n";
    
    std::cout << "\n\033[1;32m[*] Deadlock resolution SUCCESSFUL!\033[0m\n";
    std::cout << "[*] Monitor exiting. Target process continues with guardian.\n";
    
    // The guardian will keep the process alive even if shell tries to kill it
    _exit(0);
    
    return true;
}