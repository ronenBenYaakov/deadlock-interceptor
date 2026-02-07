# Deadlock Detector & Resolver 🔄⚡

A comprehensive C++ deadlock detection and resolution system that monitors processes, detects deadlocks in real-time, and automatically resolves them using advanced techniques including shadow process creation and group-based resolution strategies.

## 📋 Features

### 🔍 **Detection Capabilities**
- **Real-time monitoring** of futex operations (lock/wait/wake)
- **Wait-for graph analysis** for deadlock cycle detection
- **Conflict group analysis** - groups threads by shared lock dependencies
- **Multiple detection algorithms**: DFS cycle detection, group-based detection, heuristic scenario analysis
- **Lock statistics tracking**: acquisition counts, wait times, owner history

### 🛠️ **Resolution Strategies**
1. **Strategy 1**: Thread reconstitution in shadow process
   - Creates a shadow process to safely unlock resources
   - Preserves original process state
   - Uses SIGSEGV handlers for memory protection

2. **Group-Based Resolution**
   - Analyzes conflicts between thread groups
   - Resolves inter-group deadlocks systematically
   - Minimizes impact on unrelated threads

3. **Emergency Break**
   - Forceful thread termination as last resort
   - Automatic cleanup of lock ownership data

4. **Nuclear Resolution** (Ultimate)
   - Complete process detachment from ptrace
   - Mass futex unlocking via direct memory access
   - Indestructible guardian process for recovery

### 📊 **Analysis & Visualization**
- **Conflict group matrices** showing inter-group dependencies
- **Wait-for graphs** with thread/group annotations
- **Lock ownership trees** with waiter information
- **Deadlock risk assessment** (high/medium/low)
- **Final summary reports** with resolution statistics

## 🏗️ Architecture

### Core Components
```
deadlock_resolver/
├── detection.cpp          # Deadlock detection algorithms
├── monitoring.cpp         # System call interception
├── strategy1.cpp         # Shadow process resolution
├── global_state.cpp      # Shared data structures
├── helpers.cpp           # Utility functions
├── snapshot.cpp          # Thread state capture/restore
├── memory_duplication.cpp # Protected memory handling
└── main.cpp             # Entry point & signal handling
```

### Key Data Structures
- `DeadlockInfo`: Complete deadlock information
- `ConflictGroup`: Groups of threads sharing locks
- `ThreadSnapshot`: Saved thread register state
- `ShadowProcess`: Shadow process management
- `LockStats`: Lock usage statistics

## 🚀 Quick Start

### Building
```bash
g++ -std=c++17 -o deadlock_resolver *.cpp -pthread
```

### Basic Usage
```bash
# Monitor a process with automatic resolution
./deadlock_resolver <PID>

# Use specific strategy
./deadlock_resolver <PID> group      # Group-based resolution
./deadlock_resolver <PID> single     # Single-thread resolution
```

### Testing with Python App
```bash
# Terminal 1: Start the application
python ../app.py &
APP_PID=$!

# Terminal 2: Run deadlock resolver
./deadlock_resolver $APP_PID

# Critical: Wait for the app to complete
wait $APP_PID
```

## 🔧 Resolution Strategies

### Strategy 1: Shadow Process Creation
1. **Stop the World**: Pause all process threads
2. **Choose Victim**: Select optimal thread to sacrifice
3. **Create Shadow**: Fork a shadow process
4. **Initialize Private Memory**: Set up protected regions
5. **Force Unlock**: Release locks in shadow space
6. **Resume**: Continue original process
7. **Monitor**: Track shadow process completion

### Group-Based Resolution
- Groups threads by shared lock dependencies
- Identifies conflicts between groups
- Resolves deadlocks at group level
- Minimizes collateral damage

### Nuclear Resolution (When All Else Fails)
- **Step 1**: Nuclear detach from ptrace
- **Step 2**: Verify and fix tracing status
- **Step 3**: Unlock all futexes via direct memory access
- **Step 4**: Massive SIGCONT wakeup campaign
- **Step 5**: Create indestructible guardian process
- **Step 6**: Final cleanup and reporting

## 📈 Monitoring Output

The system provides color-coded real-time output:

- 🟢 **Green**: Lock acquisitions
- 🟡 **Yellow**: Wait operations
- 🔵 **Blue**: Inter-thread communication
- 🔴 **Red**: Deadlock detection
- 🟣 **Purple**: Resolution steps
- ⚪ **Gray**: Thread exits

## 🛡️ Safety Features

### Memory Protection
- SIGSEGV handlers for protected memory regions
- Private memory copies for locked resources
- Safe page fault handling in shadow processes

### Thread Safety
- Mutex-protected shared data structures
- Atomic flags for monitoring state
- Safe thread suspension/resumption

### Clean Recovery
- Automatic cleanup of orphaned resources
- Guardian processes for post-resolution monitoring
- Comprehensive signal handling (SIGINT, SIGTERM)

## 📊 Analysis Features

### Conflict Group Analysis
```
╔══════════════════════════════════════════════════════════════════╗
║                     CONFLICT GROUP ANALYSIS                      ║
╠══════════════════════════════════════════════════════════════════╣
Group 0:
  Threads (3): worker-1[1234] worker-2[1235] worker-3[1236]
  Locks held: 0x7fffe00008c0 0x7fffe0000900
  Locks wanted: 0x7fffe0000940
  Conflicts with groups: 1
    - Conflict with Group 1 over locks: 0x7fffe0000940
```

### Wait-For Graph
```
worker-1[1234](G0) waits for: worker-2[1235](G1) (via lock 0x7fffe00008c0)
worker-2[1235](G1) waits for: worker-1[1234](G0) (via lock 0x7fffe0000900)
```

### Group Conflict Matrix
```
      G 0 G 1 G 2
  G 0:  .   1   .
  G 1:  1   .   .
  G 2:  .   .   .
```

## 🐛 Debugging

### Common Issues

1. **"Killed" Message Appears**
   - This is your shell killing the process, not the resolver
   - Fix run.sh with proper `wait` command

2. **Permission Denied**
   - Run as root or with appropriate capabilities
   - Check `/proc/sys/kernel/yama/ptrace_scope`

3. **Threads Not Detaching**
   - Use the nuclear resolution strategy
   - Check for anti-debugging techniques in target

### Debug Output
Enable additional debugging by modifying `debug_wait_for_graph()` calls in the code.

## 📝 Configuration

### Command Line Arguments
```bash
./deadlock_resolver <PID> [strategy]
```

Strategies:
- `auto`: Automatic detection (default)
- `group`: Group-by-group resolution
- `single`: Single-thread resolution

### Environment Variables
- `DEADLOCK_DEBUG=1`: Enable verbose debugging
- `SHADOW_MEM_SIZE=65536`: Set shadow memory size

## 🧪 Testing

### Test Applications
The system is designed to work with:
- Multi-threaded C/C++ applications using pthreads
- Python applications with threading
- Any application using futexes for synchronization

### Integration Testing
```python
# Example test_deadlock.py
import threading
import time

lock1 = threading.Lock()
lock2 = threading.Lock()

def worker1():
    with lock1:
        time.sleep(0.1)
        with lock2:
            print("Worker1 done")

def worker2():
    with lock2:
        time.sleep(0.1)
        with lock1:
            print("Worker2 done")

# This will deadlock, and the resolver should detect and fix it
```

## 📚 API Reference

### Key Functions

#### Detection
- `detect_and_resolve_deadlocks()`: Main detection loop
- `dfs_deadlock()`: Depth-first search for cycles
- `analyze_conflict_groups()`: Group thread conflicts
- `detect_group_deadlock()`: Group-based detection

#### Resolution
- `resolve_deadlock_strategy1()`: Shadow process resolution
- `resolve_group_deadlock()`: Group-based resolution
- `emergency_deadlock_break()`: Forceful termination
- `stop_the_world()`: Pause all threads safely

#### Monitoring
- `handle_syscall()`: Intercept futex operations
- `on_lock()`/`on_wait()`/`on_wake()`: Track synchronization
- `update_lock_stats()`: Update lock usage statistics

## 🎯 Performance

- **Low overhead**: Minimal ptrace interception
- **Fast detection**: Real-time cycle detection
- **Efficient resolution**: Targeted thread handling
- **Minimal memory**: Shared state between components

## 🔮 Future Enhancements

1. **Machine Learning Integration**
   - Predict deadlock-prone patterns
   - Adaptive resolution strategy selection

2. **Distributed Deadlock Detection**
   - Multi-process deadlock detection
   - Network resource deadlocks

3. **GUI Dashboard**
   - Real-time visualization of wait-for graphs
   - Interactive resolution control

4. **Kernel Module Version**
   - In-kernel deadlock detection
   - Zero-overhead monitoring

## 📄 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## ⚠️ Disclaimer

This tool performs low-level process manipulation and should be used with caution:
- Only on processes you own or have permission to debug
- Not on production systems without thorough testing
- Always have backups of critical data

## 📊 Statistics Tracked

- Total deadlocks detected/resolved
- Threads tracked and their states
- Lock acquisition counts and wait times
- Resolution success rates
- Shadow process creation statistics

---

**Happy deadlock hunting!** 🕵️‍♂️✨
