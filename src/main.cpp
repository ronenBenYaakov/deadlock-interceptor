#include "global_state.h"
#include "helpers.h"
#include "monitoring.h"
#include "detection.h"
#include "strategy1.h"
#include <signal.h>
#include <iostream>
#include <sys/ptrace.h>
#include <thread>
#include <cstring>
#include <sys/wait.h>
#include <chrono>

pid_t target_pid = 0;
std::unordered_map<pid_t, ThreadInfo> thread_info_cache;
std::mutex thread_info_mutex;
std::atomic<bool> world_stopped{false};
std::atomic<bool> monitoring_active{true};
std::atomic<bool> is_resolving{false};  // Flag to indicate resolution in progress
std::mutex resolution_mutex;
std::vector<MemoryRegion> g_protected_regions;

std::unordered_map<uint64_t, std::vector<std::string>> futex_waiters;
std::unordered_map<std::string, std::unordered_map<uint64_t, Clock::time_point>> wait_start_times;
std::unordered_map<std::string, std::unordered_set<std::string>> waits_for;
std::unordered_map<std::string, std::unordered_set<uint64_t>> thread_locks;
std::unordered_map<uint64_t, std::string> lock_owners;
std::unordered_map<uint64_t, LockStats> lock_stats;

std::vector<DeadlockInfo> detected_deadlocks;
std::vector<ShadowProcess> shadow_processes;
std::vector<DeadlockResolution> resolution_history;

std::ofstream json_output;
std::ofstream deadlock_json_output;
std::ofstream resolution_log;
std::ofstream shadow_log;
size_t deadlock_counter = 0;
std::mutex output_mutex;

// Global flag for shutdown
std::atomic<bool> should_exit{false};

// Helper function to check if a thread is traced by us
static bool is_traced_by_us(pid_t tid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", tid);
    FILE* fp = fopen(path, "r");
    if (!fp) return false;
    
    char line[256];
    int tracer_pid = -1;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer_pid = atoi(line + 10);
            break;
        }
    }
    fclose(fp);
    
    return (tracer_pid == getpid());
}

void signal_handler(int sig) {
    std::cout << "\n[*] Received signal " << sig << ", cleaning up...\n";
    should_exit.store(true);
    monitoring_active.store(false);
    
    // Run final analysis before exit
    std::cout << "\n\033[1;35m[FINAL CONFLICT ANALYSIS]\033[0m\n";
    
    // Show wait-for graph
    std::cout << "\033[1;33mFinal Wait-For Graph:\033[0m\n";
    for (const auto& [waiter, waits] : waits_for) {
        std::cout << "  " << waiter << " waits for: ";
        for (const auto& target : waits) {
            std::cout << target << " ";
        }
        std::cout << "\n";
    }
    
    std::cout << "\n\033[1;36m╔══════════════════════════════════════════════════════════════════╗\033[0m\n";
    std::cout << "\033[1;36m║                         MONITORING SUMMARY                        ║\033[0m\n";
    std::cout << "\033[1;36m╠══════════════════════════════════════════════════════════════════╣\033[0m\n";
    std::cout << "\033[1;33m║ Total deadlocks detected:\033[0m " << detected_deadlocks.size() << "\n";
    
    size_t resolved_count = 0;
    for (const auto& deadlock : detected_deadlocks) {
        if (deadlock.resolved) resolved_count++;
    }
    
    std::cout << "\033[1;33m║ Deadlocks resolved:\033[0m " << resolved_count << "/" << detected_deadlocks.size() << "\n";
    std::cout << "\033[1;33m║ Total threads tracked:\033[0m " << thread_info_cache.size() << "\n";
    std::cout << "\033[1;33m║ Total locks tracked:\033[0m " << lock_stats.size() << "\n";
    std::cout << "\033[1;33m║ Shadow processes created:\033[0m " << shadow_processes.size() << "\n";
    std::cout << "\033[1;33m║ Active wait-for relationships:\033[0m " << waits_for.size() << "\n";
    std::cout << "\033[1;33m║ Threads holding locks:\033[0m " << thread_locks.size() << "\n";
    std::cout << "\033[1;36m╚══════════════════════════════════════════════════════════════════╝\033[0m\n";
    
    // Detach from all threads before exit
    auto tids = list_threads(target_pid);
    for (pid_t tid : tids) {
        if (thread_exists(tid)) {
            ptrace(PTRACE_DETACH, tid, nullptr, (void*)(intptr_t)SIGCONT);
        }
    }
    
    exit(0);
}

static void safe_handle_syscall(pid_t tid) {
    try {
        if (!thread_exists(tid)) {
            return;
        }
        
        // Check if still traced by us
        if (!is_traced_by_us(tid)) {
            // Try to re-attach if not traced
            if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
                int status;
                waitpid(tid, &status, 0);
                ptrace(PTRACE_SETOPTIONS, tid, nullptr,
                       PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
                ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
            }
            return;
        }
        
        handle_syscall(tid);
        detect_and_resolve_deadlocks();
        
    } catch (const std::exception& e) {
        std::cout << "  Exception in syscall handler for thread " << tid << ": " << e.what() << "\n";
    } catch (...) {
        std::cout << "  Unknown exception in syscall handler for thread " << tid << "\n";
    }
}

static void safe_resume_tracing(pid_t tid) {
    if (!thread_exists(tid)) {
        return;
    }
    
    if (!is_traced_by_us(tid)) {
        return;
    }
    
    // Resume with PTRACE_SYSCALL
    if (ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr) == -1) {
        // Try PTRACE_CONT as fallback
        if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
            // Thread is in bad state, try to detach and re-attach
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
            usleep(10000);
            if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
                int status;
                waitpid(tid, &status, 0);
                ptrace(PTRACE_SETOPTIONS, tid, nullptr,
                       PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
                ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
            }
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <pid> [strategy]\n";
        std::cerr << "strategies:\n";
        std::cerr << "  auto      - Automatic detection (default)\n";
        std::cerr << "  group     - Group-by-group resolution\n";
        std::cerr << "  single    - Single-thread resolution\n";
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);

    target_pid = atoi(argv[1]);
    std::string strategy = "auto";
    if (argc >= 3) {
        strategy = argv[2];
    }
    
    std::cout << "\033[1;36m[*] Deadlock Detector\033[0m\n";
    std::cout << "\033[1;36m[*] Attaching to process " << target_pid << "\033[0m\n";
    std::cout << "\033[1;36m[*] Strategy: " << strategy << "\033[0m\n";
    
    // Attach to all threads with retries
    auto tids = list_threads(target_pid);
    for (pid_t tid : tids) {
        int retry = 3;
        while (retry-- > 0) {
            if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
                int status;
                waitpid(tid, &status, __WALL);
                ptrace(PTRACE_SETOPTIONS, tid, nullptr,
                       PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
                ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
                std::cout << "  Attached to thread " << tid << "\n";
                break;
            }
            usleep(10000);
        }
    }

    std::cout << "\n\033[1;36m[*] Monitoring started. Detected deadlocks will be automatically resolved.\033[0m\n";
    std::cout << "\033[1;33m[*] Press Ctrl+C to stop and see summary\033[0m\n\n";
    
    // Main event loop
    while (!should_exit.load()) {
        // If in resolution, wait briefly and continue
        if (is_resolving.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        if (!monitoring_active.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        int status;
        pid_t tid = waitpid(-1, &status, __WALL | WNOHANG);
        
        if (tid <= 0) {
            // No events, small sleep to prevent CPU spinning
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        // Check if thread still exists
        if (!thread_exists(tid)) {
            continue;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            std::cout << "\033[90m[*] " << get_thread_identifier(tid) << " exited\033[0m\n";
            continue;
        }

        // Handle syscall event
        if (status >> 8 == (SIGTRAP | 0x80)) {
            if (monitoring_active.load() && !is_resolving.load()) {
                safe_handle_syscall(tid);
            }
        }

        // Resume tracing if monitoring is active
        if (monitoring_active.load() && !is_resolving.load()) {
            safe_resume_tracing(tid);
        }
    }
    
    // Clean shutdown
    std::cout << "\n[*] Shutting down...\n";
    auto all_tids = list_threads(target_pid);
    for (pid_t tid : all_tids) {
        if (thread_exists(tid)) {
            ptrace(PTRACE_DETACH, tid, nullptr, (void*)(intptr_t)SIGCONT);
        }
    }
    
    return 0;
}