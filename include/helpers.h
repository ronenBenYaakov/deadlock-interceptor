#ifndef HELPERS_H
#define HELPERS_H

#include <string>
#include <vector>
#include <cstdint>
#include <sys/types.h>

struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    std::string perms;
    std::string name;
};

std::string to_hex_string(uint64_t value);
std::string get_thread_name(pid_t tid);
std::string get_thread_identifier(pid_t tid);
bool junk_addr(uint64_t addr);
bool read_process_memory(pid_t pid, void* addr, void* buffer, size_t size);
bool thread_exists(pid_t tid);
bool write_process_memory(pid_t pid, void* addr, const void* buffer, size_t size);
std::vector<MemoryRegion> read_process_maps(pid_t pid);
std::vector<pid_t> list_threads(pid_t pid);
pid_t extract_tid_from_identifier(const std::string& identifier);

#endif