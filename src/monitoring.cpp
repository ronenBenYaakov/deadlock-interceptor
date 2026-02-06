#include "monitoring.h"
#include "global_state.h"
#include "helpers.h"
#include <sys/ptrace.h>
#include <sys/user.h>
#include <iostream>
#include <sys/types.h>
#include <algorithm>
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>

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
    }
}

void on_lock(pid_t tid, uint64_t addr) {
    if (junk_addr(addr)) return;

    std::string thread_name = get_thread_identifier(tid);
    
    std::cout << "\033[32m[LOCK]\033[0m " << thread_name << " acquired lock at " 
              << to_hex_string(addr) << "\n";

    lock_owners[addr] = thread_name;
    thread_locks[thread_name].insert(addr);
    
    for (auto &kv : waits_for) {
        kv.second.erase(thread_name);
    }

    for (auto &kv : futex_waiters) {
        auto& waiters = kv.second;
        waiters.erase(std::remove(waiters.begin(), waiters.end(), thread_name), waiters.end());
    }
    
    update_lock_stats(addr, thread_name);
}

void on_wait(pid_t tid, uint64_t addr) {
    if (junk_addr(addr)) return;

    std::string thread_name = get_thread_identifier(tid);
    
    futex_waiters[addr].push_back(thread_name);
    wait_start_times[thread_name][addr] = Clock::now();
    
    std::cout << "\033[33m[WAIT]\033[0m " << thread_name << " waiting on futex " 
              << to_hex_string(addr) << "\n";

    if (lock_owners.count(addr)) {
        std::string owner = lock_owners[addr];
        if (owner != thread_name) {
            waits_for[thread_name].insert(owner);
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
        std::cout << "\033[34m[COMM]\033[0m " << thread_name << " sent message to " << waiter 
                  << " via futex " << to_hex_string(addr) << "\n";
    }

    futex_waiters.erase(addr);
    
    if (lock_stats.count(addr)) {
        lock_stats[addr].waiters_count = 0;
        lock_stats[addr].waiting_threads.clear();
    }
}

void handle_syscall(pid_t tid) {
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