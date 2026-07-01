#include "helpers.h"
#include "global_state.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <sys/ptrace.h>
#include <algorithm>
#include <sstream>
#include <unistd.h>

std::string to_hex_string(uint64_t value) {
    std::stringstream ss;
    ss << "0x" << std::hex << value;
    return ss.str();
}

std::string get_thread_name(pid_t tid) {
    std::lock_guard<std::mutex> lock(thread_info_mutex);
    
    auto it = thread_info_cache.find(tid);
    if (it != thread_info_cache.end()) {
        return it->second.name;
    }

    std::string thread_name;
    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", tid);
    FILE* comm_file = fopen(proc_path, "r");
    if (comm_file) {
        char buffer[256] = {0};
        if (fgets(buffer, sizeof(buffer), comm_file)) {
            thread_name = buffer;
            thread_name.erase(std::remove_if(thread_name.begin(), thread_name.end(),
                                             [](unsigned char c){ return c == '\n' || c == '\r'; }),
                              thread_name.end());
        }
        fclose(comm_file);
    }

    if (thread_name.empty() && target_pid > 0) {
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/task/%d/comm", target_pid, tid);
        comm_file = fopen(proc_path, "r");
        if (comm_file) {
            char buffer[256] = {0};
            if (fgets(buffer, sizeof(buffer), comm_file)) {
                thread_name = buffer;
                thread_name.erase(std::remove_if(thread_name.begin(), thread_name.end(),
                                                 [](unsigned char c){ return c == '\n' || c == '\r'; }),
                                  thread_name.end());
            }
            fclose(comm_file);
        }
    }

    if (thread_name.empty()) {
        thread_name = "thread-" + std::to_string(tid);
    }

    thread_info_cache[tid] = ThreadInfo{tid, thread_name, target_pid};
    return thread_name;
}

std::string get_thread_identifier(pid_t tid) {
    std::string name = get_thread_name(tid);
    return name + "[" + std::to_string(tid) + "]";
}

bool junk_addr(uint64_t addr) {
    if (addr == 0) return true;
    if (addr < 0x10000) return true;
    if (addr > 0x7fffffffffff) return true;
    return false;
}

bool read_process_memory(pid_t pid, void* addr, void* buffer, size_t size) {
    size_t words = size / sizeof(long);
    size_t remainder = size % sizeof(long);
    
    long* dest = static_cast<long*>(buffer);
    long* src_addr = static_cast<long*>(addr);
    
    for (size_t i = 0; i < words; i++) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, src_addr + i, nullptr);
        if (errno != 0) {
            return false;
        }
        dest[i] = word;
    }
    
    if (remainder > 0) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, src_addr + words, nullptr);
        if (errno != 0) {
            return false;
        }
        memcpy(dest + words, &word, remainder);
    }
    
    return true;
}

// helpers.h
// helpers.cpp
int get_tracer_pid(pid_t tid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", tid);
    FILE* fp = fopen(path, "r");
    if (!fp) return -1;
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer = atoi(line + 10);
            fclose(fp);
            return tracer;
        }
    }
    
    fclose(fp);
    return -1;
}

bool thread_exists(pid_t tid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", tid);
    return (access(path, F_OK) == 0);
}

bool write_process_memory(pid_t pid, void* addr, const void* buffer, size_t size) {
    size_t words = size / sizeof(long);
    size_t remainder = size % sizeof(long);
    
    const long* src = static_cast<const long*>(buffer);
    long* dest_addr = static_cast<long*>(addr);
    
    for (size_t i = 0; i < words; i++) {
        if (ptrace(PTRACE_POKEDATA, pid, dest_addr + i, src[i]) == -1) {
            return false;
        }
    }
    
    if (remainder > 0) {
        errno = 0;
        long existing = ptrace(PTRACE_PEEKDATA, pid, dest_addr + words, nullptr);
        if (errno != 0) {
            return false;
        }
        
        memcpy(&existing, src + words, remainder);
        if (ptrace(PTRACE_POKEDATA, pid, dest_addr + words, existing) == -1) {
            return false;
        }
    }
    
    return true;
}

std::vector<MemoryRegion> read_process_maps(pid_t pid) {
    std::vector<MemoryRegion> regions;
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE* maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return regions;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), maps_file)) {
        MemoryRegion region;
        char perms[8];
        char name[256] = {0};
        
        if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %255[^\n]", 
                   &region.start, &region.end, perms, name) >= 3) {
            region.perms = perms;
            region.name = name;
            regions.push_back(region);
        }
    }
    
    fclose(maps_file);
    return regions;
}


// Check if thread is in STOP state
bool is_thread_stopped(pid_t tid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", tid);
    FILE* fp = fopen(path, "r");
    if (!fp) return false;
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "State:", 6) == 0) {
            bool stopped = (strchr(line, 'T') != nullptr);
            fclose(fp);
            return stopped;
        }
    }
    
    fclose(fp);
    return false;
}

std::vector<pid_t> list_threads(pid_t pid) {
    std::vector<pid_t> tids;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);

    DIR *dir = opendir(path);
    if (!dir) return tids;

    struct dirent *ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        pid_t tid = atoi(ent->d_name);
        tids.push_back(tid);
    }

    closedir(dir);
    return tids;
}

pid_t extract_tid_from_identifier(const std::string& identifier) {
    size_t bracket_pos = identifier.find('[');
    size_t end_bracket = identifier.find(']');
    if (bracket_pos != std::string::npos && end_bracket != std::string::npos) {
        std::string tid_str = identifier.substr(bracket_pos + 1, end_bracket - bracket_pos - 1);
        return std::stoi(tid_str);
    }
    return 0;
}