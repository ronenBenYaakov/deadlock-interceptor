#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include "deadlock_resolver.h"
#include <sys/types.h>

ThreadSnapshot snapshot_thread_state(pid_t tid);
bool restore_thread_state(pid_t tid, const ThreadSnapshot& snap);

#endif