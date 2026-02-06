#ifndef MONITORING_H
#define MONITORING_H

#include <sys/types.h>
#include <cstdint>
#include <string>

void update_lock_stats(uint64_t addr, const std::string& new_owner);
void on_lock(pid_t tid, uint64_t addr);
void on_wait(pid_t tid, uint64_t addr);
void on_wake(pid_t tid, uint64_t addr);
void handle_syscall(pid_t tid);

#endif