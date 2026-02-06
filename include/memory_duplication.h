#ifndef MEMORY_DUPLICATION_H
#define MEMORY_DUPLICATION_H

#include "deadlock_resolver.h"
#include <cstdint>
#include <vector>
#include <signal.h>

bool should_duplicate_page(uintptr_t addr);
void shadow_sigsegv_handler(int sig, siginfo_t* info, void* context);

#endif