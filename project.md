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

**Deliverable**: A tool that can deny/allow/redirect/modify syscalls.

#### Tasks

1. Policy Configuration: Design a configuration format (JSON)
2. Rule Matching: Implement logic to match an intercepted syscall against the loaded policies based on syscall number/name and arguments.
3. Action Execution: 
	- Allow: Let the syscall execute normally.
	- Deny: Skip the actual kernel execution and set the return register to an error code.
	- Rediret: 
	- Modify: 
4. Argument Inspection: Read arguments from tracee's memory.

### Phase 3: Advanced Manipulation and replay

**GOAL**: Add modifications and recording capabilities.

**Deliverable**: A tool that can modify syscall arguments/return values and produce a replaybale trace of execution.

#### Tasks

1. Syscall Modification: 
	- Modify Arguments: Use `ptrace` to write new values into the tracee's registers or memory before the syscall is executed.
	- Modify return values: Change the value in `RAX` after the syscall returns
2. Enhanced Policy Actions: Add `modify` and `simulate_success` actions to the policy engine.
3. Structured Logging: Each log should contain a full record of the syscall event.
4. Trace Replay: Develope tool that can read the log file and `replay` the sequence of syscalls, useful for analysis and regression testing.

### Phase 4: Syscall proxing

**GOAL**: Implement proxy to execute syscalls in different environment.

**Deliverable**: A tool that can forward a syscall from the target to a handler process that returns custom data.

#### Tasks

1. Proxy backend: A process that can execute syscalls on behalf of the target.
2. Commnucation Channel: IPC mechanism between the tracer and the proxy backend.
3. Stub execution: when a syscall is to be proxied, the tracer stops the target, sends the syscall details to the proxy, waits for response, and then injects the return value/data back into the target process.
