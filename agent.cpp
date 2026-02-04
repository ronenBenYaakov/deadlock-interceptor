#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/user.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <chrono>
#include <fstream>
#include <algorithm>

using Clock = std::chrono::steady_clock;

/* -------------------- data structures -------------------- */

struct LockEvent {
    Clock::time_point last;
};

struct SnapshotInfo {
    uint64_t lock_addr; // lock protecting the object
    void* obj_ptr;      // pointer to the object
    size_t obj_size;    // size in bytes
};

static std::unordered_map<uint64_t, std::unordered_set<pid_t>> addr_users;
static std::unordered_map<pid_t, std::unordered_map<uint64_t, LockEvent>> recent;
static std::unordered_map<uint64_t, std::vector<pid_t>> futex_waiters;

// Wait-for graph: tid -> tids it waits for
static std::unordered_map<pid_t, std::unordered_set<pid_t>> waits_for;
// Map lock -> owner tid
static std::unordered_map<uint64_t, pid_t> lock_owners;

// Snapshot registry
static std::vector<SnapshotInfo> snapshot_objects;
// Memory snapshots
static std::unordered_map<void*, std::vector<uint8_t>> snapshots;

/* -------------------- helper functions -------------------- */

bool junk_addr(uint64_t addr) {
    if (addr == 0) return true;
    if (addr < 0x10000) return true;          // tagged / flags
    if (addr > 0x7fffffffffff) return true;   // kernel / invalid
    return false;
}

bool spin(pid_t tid, uint64_t addr) { return false; }
bool shared(pid_t tid, uint64_t addr) { addr_users[addr].insert(tid); return true; }

/* -------------------- deadlock detection -------------------- */

bool dfs_deadlock(pid_t tid,
                  std::unordered_set<pid_t> &visited,
                  std::unordered_set<pid_t> &stack,
                  std::vector<pid_t> &cycle) 
{
    visited.insert(tid);
    stack.insert(tid);

    for (pid_t neighbor : waits_for[tid]) {
        if (stack.count(neighbor)) {
            cycle.push_back(neighbor);
            return true; // cycle detected
        }
        if (!visited.count(neighbor)) {
            if (dfs_deadlock(neighbor, visited, stack, cycle)) {
                cycle.push_back(neighbor);
                return true;
            }
        }
    }

    stack.erase(tid);
    return false;
}

// Graphviz DOT
void dump_graph(const std::string &filename = "locks.dot") {
    std::ofstream out(filename);
    if (!out.is_open()) return;

    out << "digraph LockGraph {\n";
    out << "  rankdir=LR;\n";
    out << "  node [style=filled, color=lightblue];\n\n";

    std::unordered_set<pid_t> all_threads;
    for (auto &kv : waits_for) all_threads.insert(kv.first);
    for (auto &kv : lock_owners) all_threads.insert(kv.second);

    for (pid_t tid : all_threads)
        out << "  T" << tid << " [label=\"TID " << tid << "\", shape=ellipse];\n";

    for (auto &kv : lock_owners)
        out << "  L" << kv.first << " [label=\"0x" << std::hex << kv.first << std::dec << "\", shape=box];\n";

    out << "\n";

    for (auto &kv : lock_owners)
        out << "  T" << kv.second << " -> L" << kv.first << " [label=\"owns\", color=green];\n";

    for (auto &kv : waits_for)
        for (pid_t w : kv.second)
            out << "  T" << kv.first << " -> T" << w << " [label=\"waits\", color=red];\n";

    out << "}\n";
    printf("[GRAPH] Dumped lock graph to %s\n", filename.c_str());
}

void detect_deadlocks() {
    std::unordered_set<pid_t> visited;
    std::unordered_set<pid_t> stack;
    std::vector<pid_t> cycle;

    for (auto &kv : waits_for) {
        pid_t tid = kv.first;
        if (!visited.count(tid)) {
            cycle.clear();
            if (dfs_deadlock(tid, visited, stack, cycle)) {
                printf("[DEADLOCK] cycle detected: ");
                for (auto it = cycle.rbegin(); it != cycle.rend(); ++it)
                    printf("%d ", *it);
                printf("\n");
            }
        }
    }

    dump_graph();
}

/* -------------------- snapshot helpers -------------------- */

// Can snapshot if lock is owned and no waiters
bool can_snapshot(uint64_t lock_addr) {
    return lock_owners.count(lock_addr) && futex_waiters[lock_addr].empty();
}

// Take snapshot of all registered objects under quiescent locks
void snapshot_objects_now() {
    for (auto &info : snapshot_objects) {
        if (!can_snapshot(info.lock_addr)) continue;

        std::vector<uint8_t> bytes(info.obj_size);
        memcpy(bytes.data(), info.obj_ptr, info.obj_size);

        snapshots[info.obj_ptr] = std::move(bytes);

        printf("[SNAPSHOT] Object at %p under lock 0x%lx captured (%zu bytes)\n",
               info.obj_ptr, info.lock_addr, info.obj_size);
    }
}

// Create a new copy from snapshot (POD only)
void* create_copy(void* original) {
    if (!snapshots.count(original)) return nullptr;
    auto &data = snapshots[original];
    void* new_obj = malloc(data.size());
    memcpy(new_obj, data.data(), data.size());
    return new_obj;
}

/* -------------------- events -------------------- */

void on_lock(pid_t tid, uint64_t addr) {
    if (junk_addr(addr)) return;

    printf("[LOCK] TID %d acquired lock at addr 0x%lx\n", tid, addr);

    lock_owners[addr] = tid;
    for (auto &kv : waits_for) kv.second.erase(tid);

    snapshot_objects_now(); // take snapshot if possible
}

void on_wait(pid_t tid, uint64_t addr) {
    if (junk_addr(addr)) return;

    futex_waiters[addr].push_back(tid);
    printf("[WAIT] TID %d waiting on futex 0x%lx\n", tid, addr);

    if (lock_owners.count(addr)) {
        pid_t owner = lock_owners[addr];
        if (owner != tid) {
            waits_for[tid].insert(owner);
            detect_deadlocks();
        }
    }
}

void on_wake(pid_t tid, uint64_t addr) {
    if (!futex_waiters.count(addr)) return;

    for (pid_t waiter : futex_waiters[addr])
        printf("[COMM] TID %d sent message to TID %d via futex 0x%lx\n",
               tid, waiter, addr);

    futex_waiters.erase(addr);
}

/* -------------------- ptrace syscall decode -------------------- */

void handle_syscall(pid_t tid) {
    static std::unordered_map<pid_t, uint64_t> futex_uaddr;

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, tid, nullptr, &regs);

#if defined(__x86_64__)
    long syscall = regs.orig_rax;

    if (syscall == SYS_futex) {
        uint64_t uaddr = regs.rdi;
        int op = regs.rsi & FUTEX_CMD_MASK;

        if (op == FUTEX_WAIT) {
            on_wait(tid, uaddr);
            futex_uaddr[tid] = uaddr;
        }
        else if (op == FUTEX_WAKE) {
            on_wake(tid, uaddr);
            on_lock(tid, uaddr);
        }
    }
#endif
}

/* -------------------- attach helpers -------------------- */

std::vector<pid_t> list_threads(pid_t pid) {
    std::vector<pid_t> tids;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);

    DIR *dir = opendir(path);
    if (!dir) return tids;

    struct dirent *ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        tids.push_back(atoi(ent->d_name));
    }

    closedir(dir);
    return tids;
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    printf("[*] Attaching to process %d\n", pid);

    auto tids = list_threads(pid);

    for (pid_t tid : tids) {
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
            waitpid(tid, nullptr, 0);
            ptrace(PTRACE_SETOPTIONS, tid, nullptr,
                   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
            ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
            printf("  attached TID %d\n", tid);
        }
    }

    while (true) {
        int status;
        pid_t tid = waitpid(-1, &status, __WALL);
        if (tid <= 0) continue;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            printf("[*] Thread %d exited\n", tid);
            continue;
        }

        if (status >> 8 == (SIGTRAP | 0x80))
            handle_syscall(tid);

        ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
    }
}
