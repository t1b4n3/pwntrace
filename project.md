# pwntracer dev plan


## High level architecture & components

1. The tracer : The main process that spawns/attaches to the target and controls execution.
2. The syscall intercepotr: Catches syscalls at entry and exit. (Using `ptrace`)
3. The policy engine: Decides what to do with an intercepted syscall. (allow, deny, modify and redirect)
4. Proxy backend: Handles forwarding a syscall to be executed in a different context.
5. Logging and reply system: records all activity for analysis 

```
+-------------------+      	+-----------------------+
|   Target Process  |  <---->	|    pwntracer (Tracer) |
|   (Tracee)        |  ptrace	|                       |
+-------------------+      	+-----------------------+
                                    |
                                    v
                    +-----------------------+
                    |   Policy Engine       |
                    |  - Rule Matching      |
                    |  - Decision Logic     |
                    +-----------------------+
                      /        |       	    \
                     /         |       	     \
        +------------+   +------------+	      +---------------+
        | Logging    |   | Syscall    |	      | Proxy Backend |
        | & Replay   |   | Modifier   |	      | (Remote/Env)  |
        +------------+   +------------+	      +---------------+
```


## Development Plan

### Phase 1: Basic Tracing

**GOAL**: Build a simple tracer that can start/attach a process and log every syscall it makes.

- **Deliverable**: Binary runs `./pwntracer /bin/cat /etc/passwd` and prints a list of all syscalls (by name and number) with thier arguments and returns values.

#### Tasks

1. Process Control: Implement code to spawn a child process under `ptrace` or attach to an existing PID.
2. Syscall Caputre: Catch syscals at entry `PTRACE_SYSCALL` and exit.
3. Argument Reading. Read syscall number and arguments from the registers. 
	- `RAX, RDI, RSI, RDX, ...` on `x86_64`
4. Return Value Reading: Read return value.
	- `RAX`
5. syscall mapping: Create a lookup table to map syscall numbers to thier names
	- use `/usr/include/asm/unistd_64.h`

### Phase 2: Policy Engine

**GOAL**: Move from passive logging to active control.

**Deliverable**: A tool that can deny/allow/modify syscalls.

#### Tasks

1. Policy Configuration: Design a configuration format (JSON)
2. Rule Matching: Implement logic to match an intercepted syscall against the loaded policies based on syscall number/name and arguments.
3. Action Execution: 
	- Allow: Let the syscall execute normally.
	- Deny: Skip the actual kernel execution and set the return register to an error code.
	- Modify: Modify syscall arguments and return values
4. Argument Inspection: Read arguments from tracee's memory.
5. Interface

### Phase 3: Time Travel Syscall debugging (Timeless)

**GOAL**: Add timeless syscall debugging

**Deliverable**: A tool that can modify syscall arguments/return values and produce a replaybale trace of execution.

A tool that can 

#### Tasks

1. Recording System. 
	- Buffer of recent syscalls
	- selective memory snapshots
	- 
2. 
3. Fast-Forward: When 
4. Interface

### Phase 4: Branch Exploration: 

**GOAL**: A syscall tries different execution paths

#### Tasks

1. Fork-on demand system
2. Branch Management 
3. interface

### Phase 5: Differential Analysis

**GOAL** Compare execution from two different points.

#### Tasks

1. State Comparision Engine
2. Execution Diffing
3. Interface


### Phase 6: Syscall proxing

**GOAL**: Implement proxy to execute syscalls in different environment.

**Deliverable**: A tool that can forward a syscall from the target to a handler process that returns custom data.

#### Tasks

1. Proxy backend: A process that can execute syscalls on behalf of the target.
2. Commnucation Channel: IPC mechanism between the tracer and the proxy backend.
3. Stub execution: when a syscall is to be proxied, the tracer stops the target, sends the syscall details to the proxy, waits for response, and then injects the return value/data back into the target process.
