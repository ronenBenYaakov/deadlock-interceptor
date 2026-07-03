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

/* ---------------- GLOBAL STATE ---------------- */

std::atomic<bool> should_exit{false};
std::atomic<bool> is_resolving{false};

std::mutex global_state_mutex;

/* ---------------- SAFE HELPERS ---------------- */

static bool tid_alive(pid_t tid) {
    return kill(tid, 0) == 0;
}

/* ---------------- SIGNAL HANDLER (FIXED) ---------------- */

void signal_handler(int) {
    // ONLY set flag — NOTHING ELSE
    should_exit.store(true);
}

/* ---------------- EVENT HANDLER ---------------- */

static void handle_event(pid_t tid) {
    if (!tid_alive(tid)) return;

    std::lock_guard<std::mutex> lock(global_state_mutex);

    try {
        handle_syscall(tid);
        detect_and_resolve_deadlocks();
    } catch (...) {
        std::cerr << "[WARN] handle_event exception for tid " << tid << "\n";
    }
}

/* ---------------- RESUME ---------------- */

static void resume_tid(pid_t tid) {
    if (!tid_alive(tid)) return;

    if (ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr) == -1) {
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
    }
}

/* ---------------- ATTACH ---------------- */

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

/* ---------------- CLEAN SHUTDOWN ---------------- */

static void shutdown_clean(pid_t pid) {
    std::cout << "\n[*] Shutting down safely...\n";

    is_resolving.store(true);

    auto tids = list_threads(pid);

    for (pid_t tid : tids) {
        if (!tid_alive(tid)) continue;

        ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    for (pid_t tid : tids) {
        if (!tid_alive(tid)) continue;

        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    }

    std::cout << "[*] Clean detach complete (CRIU-safe)\n";
}

/* ---------------- MAIN LOOP ---------------- */

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <pid>\n";
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::cout << "[*] Attaching to PID " << target_pid << "\n";

    attach_all_threads(target_pid);

    std::cout << "[*] Monitoring started\n";

    while (!should_exit.load()) {

        int status = 0;
        pid_t tid = waitpid(-1, &status, __WALL | WNOHANG);

        if (tid <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        if (!tid_alive(tid)) continue;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            continue;
        }

        if ((status >> 8) == (SIGTRAP | 0x80)) {

            if (!is_resolving.load()) {
                handle_event(tid);
            }
        }

        if (!is_resolving.load()) {
            resume_tid(tid);
        }
    }

    shutdown_clean(target_pid);

    return 0;
}