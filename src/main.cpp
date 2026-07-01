#include "global_state.h"
#include "helpers.h"
#include "monitoring.h"
#include "detection.h"
#include "strategy1.h"

#include <signal.h>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <unordered_set>

/* ---------------- GLOBAL STATE ---------------- */

std::atomic<bool> should_exit{false};
std::atomic<bool> is_resolving{false};

/* One lock for ALL shared graph state (IMPORTANT FIX) */
std::mutex global_state_mutex;

/* ---------------- SAFE HELPERS ---------------- */

static bool pid_alive(pid_t pid) {
    return kill(pid, 0) == 0;
}

static bool tid_alive(pid_t tid) {
    return kill(tid, 0) == 0;
}

/* ---------------- SIGNAL HANDLER ---------------- */

void signal_handler(int sig) {
    std::cout << "\n[*] Shutdown signal received\n";
    should_exit.store(true);
    monitoring_active.store(false);

    std::lock_guard<std::mutex> lock(global_state_mutex);

    std::cout << "\n===== FINAL SUMMARY =====\n";
    std::cout << "Deadlocks detected: " << detected_deadlocks.size() << "\n";
    std::cout << "Active edges: " << waits_for.size() << "\n";

    exit(0);
}

/* ---------------- CORE SAFE SYSCALL HANDLER ---------------- */

static void handle_event(pid_t tid) {
    if (!tid_alive(tid)) return;

    std::lock_guard<std::mutex> lock(global_state_mutex);

    try {
        handle_syscall(tid);
        detect_and_resolve_deadlocks();
    } catch (...) {
        std::cerr << "[WARN] exception in handle_event for tid " << tid << "\n";
    }
}

/* ---------------- SAFE RESUME ---------------- */

static void resume_tid(pid_t tid) {
    if (!tid_alive(tid)) return;

    if (ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr) == -1) {
        // fallback only: CONT (no reattach here anymore)
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
    }
}

/* ---------------- ATTACH PHASE ---------------- */

static void attach_all_threads(pid_t pid) {
    auto tids = list_threads(pid);

    for (pid_t tid : tids) {
        if (!tid_alive(tid)) continue;

        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
            int status;
            waitpid(tid, &status, __WALL);

            ptrace(PTRACE_SETOPTIONS, tid, nullptr,
                   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);

            ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);

            std::cout << "[+] Attached: " << tid << "\n";
        }
    }
}

/* ---------------- MAIN LOOP ---------------- */

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <pid>\n";
        return 1;
    }

    target_pid = atoi(argv[1]);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);

    std::cout << "[*] Attaching to PID " << target_pid << "\n";

    attach_all_threads(target_pid);

    std::cout << "[*] Monitoring started\n";

    while (!should_exit.load()) {

        if (!monitoring_active.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        int status = 0;
        pid_t tid = waitpid(-1, &status, __WALL | WNOHANG);

        if (tid <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        if (!tid_alive(tid)) continue;

        /* Thread exit */
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            continue;
        }

        /* Syscall stop */
        if ((status >> 8) == (SIGTRAP | 0x80)) {

            if (!is_resolving.load()) {
                handle_event(tid);
            }
        }

        /* Resume safely */
        if (!is_resolving.load()) {
            resume_tid(tid);
        }
    }

    /* CLEAN EXIT */
    std::cout << "[*] Detaching...\n";

    auto tids = list_threads(target_pid);
    for (pid_t tid : tids) {
        if (tid_alive(tid)) {
            ptrace(PTRACE_DETACH, tid, nullptr, (void*)SIGCONT);
        }
    }

    return 0;
}