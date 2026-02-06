#include "memory_duplication.h"
#include "global_state.h"
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <iostream>

bool should_duplicate_page(uintptr_t addr) {
    for (auto& region : g_protected_regions) {
        if (addr >= region.start && addr < region.end) {
            return true;
        }
    }
    return false;
}

void shadow_sigsegv_handler(int sig, siginfo_t* info, void* context) {
    void* fault_addr = info->si_addr;
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = ((uintptr_t)fault_addr / page_size) * page_size;
    
    std::cout << "[SHADOW SIGSEGV] Fault at " << fault_addr << ", handling page 0x" 
              << std::hex << page_start << std::dec << "\n";
    
    if (!should_duplicate_page(page_start)) {
        std::cerr << "[SHADOW] Unhandled fault at " << fault_addr << " - aborting\n";
        exit(1);
    }
    
    uint8_t page_copy[page_size];
    memcpy(page_copy, (void*)page_start, page_size);
    
    void* new_page = mmap((void*)page_start, page_size,
                         PROT_READ | PROT_WRITE,
                         MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                         -1, 0);
    
    if (new_page == MAP_FAILED) {
        perror("[SHADOW] mmap MAP_FIXED failed");
        exit(1);
    }
    
    memcpy(new_page, page_copy, page_size);
    
    std::cout << "[SHADOW] Page 0x" << std::hex << page_start << std::dec 
              << " replaced with private copy\n";
}