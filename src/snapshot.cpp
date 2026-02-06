#include "snapshot.h"
#include "helpers.h"
#include <sys/ptrace.h>
#include <iostream>
#include <errno.h>

ThreadSnapshot snapshot_thread_state(pid_t tid) {
    ThreadSnapshot snap;
    snap.snapshot_time = std::chrono::system_clock::now();
    
    if (!thread_exists(tid)) {
        std::cout << "  [WARNING] Thread " << tid << " no longer exists!\n";
        return snap;
    }
    
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &snap.regs) == -1) {
        if (errno == ESRCH) {
            std::cout << "  [ERROR] Thread " << tid << " exited during snapshot\n";
        } else {
            perror("PTRACE_GETREGS failed");
        }
        return snap;
    }
    
    std::cout << "  Snapshot complete: RIP=0x" << std::hex << (unsigned long)snap.regs.rip << std::dec << "\n";
    return snap;
}

bool restore_thread_state(pid_t tid, const ThreadSnapshot& snap) {
    if (!thread_exists(tid)) {
        std::cout << "  Cannot restore: thread " << tid << " no longer exists\n";
        return false;
    }
    
    if (snap.regs.rip == 0) {
        std::cout << "  No valid snapshot to restore\n";
        return false;
    }
    
    std::cout << "\033[1;33m[RESTORE] Restoring thread " << tid << "...\033[0m\n";
    
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &snap.regs) == -1) {
        perror("  PTRACE_SETREGS failed");
        return false;
    }
    
    std::cout << "  ✓ Registers restored\n";
    return true;
}