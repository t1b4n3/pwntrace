# Syscall Proxing Framework — Design Document + Coding Tickets

**Name:** Sysproxy (working name)
**Goal:** Intercept selected syscalls in user-space, log/forward them to a proxy, and apply policy-based permit/deny/modify decisions. Target audience: reverse engineers, exploit developers, security researchers.
**Primary language:** C++ (C ABI wrappers for LD_PRELOAD shim).
**Prototype plan:** 3-hour LD_PRELOAD shim (C++ core) + Python proxy for validation; then full C++ implementation.

---

# 1. Elevator pitch

Sysproxy is a user-space **syscall proxying framework** that hooks libc/syscall invocations (via LD_PRELOAD and seccomp/ptrace fallbacks), records them, and optionally forwards them to an external proxy which can emulate, modify, or deny the action. Use cases include deterministic dynamic analysis, sandboxing hostile binaries, stubbing problematic syscalls during exploit development, and tracing post-exploit behavior.

---

# 2. High-level architecture

```
             +----------------------+
             |      Controller      |  (launches target, chooses mode)
             +----------------------+
                        |
                        v
            target binary (LD_PRELOAD=libsysproxy.so)
                        |
                +---------------+
                |   Shim (.so)  |  -- exported C ABI wrappers
                |  (C++ core)   |
                +---------------+
                  |   |     |   \
     local call--/    |     |    \---> policy engine -> logger
         (dlsym)       |     |         |
                      IPC    |         v
                      |      v   +--------------+
               unix_sock/shared_mem  proxy (local/remote)
                                +--------------+
```

Modes:

* **LD_PRELOAD shim** (fast-path; libc wrapper interception)
* **Seccomp user notification** (catch raw syscalls; medium perf)
* **ptrace** fallback (full coverage; high overhead)
* Optional: **kernel/eBPF** module later (advanced)

---

# 3. Core components

1. **shim/** — Shared object injected via `LD_PRELOAD`.

   * Exports C ABI wrappers (`open`, `close`, `read`, `write`, `connect`, `send`, `recv`, etc.).
   * For each hook: builds `SyscallEvent`, calls `SyscallProxy::handle_event()`, then calls real function (or synthesizes response).

2. **core/** — C++ library used by shim and other binaries.

   * `SyscallProxy` singleton: orchestrates logging, policy, IPC.
   * `FdMap` (fd → metadata): `std::unordered_map<int, FileMeta>` + mutex.
   * `PolicyEngine`: evaluate rules, return `Action` (ALLOW, DENY, MODIFY, PROXY, SYNTHESIZE).
   * `Logger`: structured JSON logging to file/stdout.

3. **ipc/** — IPC abstraction for shim ↔ proxy.

   * Unix domain sockets (control & SCM_RIGHTS), optional shared mem for big buffers.
   * Serialization protocol (small JSON messages or protobuf for efficiency).

4. **proxy/** — receives event requests, executes/wraps syscalls, applies remote policy, returns results.

   * Can be local (same host) or remote (VM/container) for environment emulation.

5. **controller/** — CLI to launch process under shim, set policy file, choose mode (LD_PRELOAD/seccomp/ptrace), manage sessions.

6. **replay/** — save traces, replay them later deterministically.

7. **tests/examples/** — small test binaries (file_io, net_client, raw_syscall) used in CI and local testing.

---

# 4. Data model & messages

**SyscallEvent**

* pid, tid, timestamp
* syscall name/number
* args (typed): fd, path, buffer_len, sockaddr, flags, mode
* on-entry / on-exit flag
* return value / errno (on-exit)
* optional buffer payload (or shared-mem handle)

**PolicyRule**

* selector: syscall(s), process/path regex, arg predicates
* action: ALLOW | DENY(errno) | REDIRECT(path) | MODIFY(arg_index,new_value) | PROXY | SYNTHESIZE
* priority, TTL, audit flag

**IPC message**

* JSON: `{ "id": <uuid>, "event": <SyscallEvent>, "reply_to": ... }`
* Replies: `{ "id": <uuid>, "action": { "type":"redirect", "path":"/tmp/x" } }`

---

# 5. Non-functional requirements

* **Fail-open**: shim must not hang the target if proxy unreachable — default to calling real syscall.
* **Low overhead**: LD_PRELOAD path should be low-latency; heavy work should be offloaded to proxy asynchronously where possible.
* **Safety**: Do not allow interception code to introduce security vulnerabilities; isolate proxy (container) and encrypt remote channels.
* **Determinism**: Trace format must be replayable.

---

# 6. Security & ethical constraints

* Only run on machines and binaries you control.
* Proxy performing syscalls must be sandboxed (container/chroot/seccomp).
* Logs may contain secrets: store securely; redact in production.

---

# 7. Acceptance criteria (for MVP)

* LD_PRELOAD shim loads and intercepts `open`, `read`, `write`, `close` for dynamic ELF binaries.
* `FdMap` stores fd → path and logs on `open` and `close`.
* Shim sends JSON events to a local UNIX socket proxy; proxy logs and replies with `{"action":"allow"}`.
* Shim supports simple policy: deny access to a configured path and return `-EPERM`.
* Replay tool can take saved trace and replay syscalls by invoking test program in deterministic mode.

---

# 8. Tickets / Issues (GitHub-style)

Below tickets are ordered and grouped by priority. Each ticket includes: **Title**, **Description**, **Acceptance**, **Estimate**, **Dependencies**, **Labels**.

---

### Phase 0 — Repo & infra (T0)

**T0.1 — Repo skeleton & CMake**

* **Desc:** Create repo layout, top-level CMake, basic CI skeleton.
* **Acceptance:** `cmake` config builds an empty target; CI running lints.
* **Estimate:** 1d
* **Labels:** infra, setup

**T0.2 — Example test binaries**

* **Desc:** Add `file_io`, `secret_reader`, `net_client`, `raw_syscall` simple C programs.
* **Acceptance:** examples compile with `make examples`.
* **Estimate:** 0.5d

---

### Phase 1 — Core utilities & data structures (T1)

**T1.1 — FdMap class**

* **Desc:** Implement `class FdMap` using `std::unordered_map<int, FileMeta>`, thread-safe with `std::shared_mutex`. API: `insert(fd, path)`, `lookup(fd) -> optional`, `erase(fd)`.
* **Acceptance:** unit tests for insert/lookup/erase under concurrent access.
* **Estimate:** 1d
* **Labels:** core, data-structures

**T1.2 — Logger utility**

* **Desc:** `Logger` that writes JSONL to file with a rotation option. Thread-safe.
* **Acceptance:** can log `SyscallEvent` objects; tests assert valid JSON lines.
* **Estimate:** 0.5d

**T1.3 — SyscallEvent model & serialization**

* **Desc:** Define `SyscallEvent` struct and JSON (de)serialization using `nlohmann/json`.
* **Acceptance:** round-trip serialization unit tests.
* **Estimate:** 0.5d

---

### Phase 2 — Shim skeleton & wrappers (T2)

**T2.1 — LD_PRELOAD shim skeleton (C ABI exports)**

* **Desc:** Add `shim_exports.c` with `extern "C"` wrappers that forward to C++ core functions. Provide simple `open` wrapper to demonstrate hooking. Link as `libsysproxy.so`.
* **Acceptance:** `LD_PRELOAD=./libsysproxy.so ./examples/file_io` prints shim debug message and `cat` behaves normally.
* **Estimate:** 1d
* **Labels:** shim, prototype

**T2.2 — Shim core: SyscallProxy singleton**

* **Desc:** Implement `SyscallProxy` class with `handle_event(SyscallEvent)` stub that logs events via `Logger`. Integrate `FdMap`.
* **Acceptance:** `open` wrapper calls into `SyscallProxy::on_open`, which logs and inserts fd->path.
* **Estimate:** 1d

**T2.3 — dlsym caching & safe wrappers**

* **Desc:** Implement mechanism to obtain real libc functions via `dlsym(RTLD_NEXT, ...)` with caching and `pthread_once` init. Ensure exceptions don't escape to C ABI.
* **Acceptance:** wrappers call real functions correctly after logging.
* **Estimate:** 1d

---

### Phase 3 — IPC & local proxy (T3)

**T3.1 — Unix socket IPC library**

* **Desc:** Implement `UnixIpc` helper to connect to `/tmp/sysproxy.sock`, send JSON messages, and receive replies. Nonblocking connect with short timeout.
* **Acceptance:** unit tests simulate server and client transfer.
* **Estimate:** 1d

**T3.2 — Python quick-proxy (prototype)**

* **Desc:** Small Python proxy that listens, prints incoming messages, and replies `{"action":"allow"}`. Used to validate shim behavior.
* **Acceptance:** shim sends event, Python proxy prints it.
* **Estimate:** 0.5d
* **Labels:** prototype

**T3.3 — Shim -> proxy sync call path**

* **Desc:** Shim queries proxy before calling certain syscalls (e.g., `open`), and acts on reply (allow/deny/redirect). Implement timeout/fail-open behavior.
* **Acceptance:** when proxy replies `deny`, shim returns `-EPERM` (without calling real open).
* **Estimate:** 1d

---

### Phase 4 — Policy engine (T4)

**T4.1 — Policy rule model & evaluator**

* **Desc:** Implement `PolicyRule` structures, rule parser (JSON), and evaluator that runs in `PolicyEngine`. Support simple predicates: path equals, path matches regex, syscall name.
* **Acceptance:** unit tests for rule matching (true/false) for different events.
* **Estimate:** 1.5d

**T4.2 — Apply policies in shim**

* **Desc:** Integrate `PolicyEngine` into `SyscallProxy::handle_event` and execute action returned by engine (deny/redirect/allow).
* **Acceptance:** configured rule to deny `/etc/passwd` results in `open` returning `-EPERM`.
* **Estimate:** 1d

**T4.3 — Config loader + hot reload**

* **Desc:** Load policy from JSON/YAML file; support SIGHUP to reload.
* **Acceptance:** updating file and sending SIGHUP updates rules in memory.
* **Estimate:** 1d

---

### Phase 5 — Extras & robustness (T5)

**T5.1 — Read/Write payload capture**

* **Desc:** Capture `read` buffers (store to log files or shared memory handles) and `write` previews (hex/preview). Respect size limits.
* **Acceptance:** `cat` example logs read payload to `logs/pid_read_*.bin`.
* **Estimate:** 1d

**T5.2 — Multi-thread safety & tests**

* **Desc:** Add integration tests with multi-threaded target programs to ensure no deadlocks and correct mapping behavior.
* **Acceptance:** integration test passes under CI.
* **Estimate:** 1d

**T5.3 — Seccomp user-notif mode (prototype)**

* **Desc:** Implement minimal seccomp user-notif handler to intercept raw syscalls and forward to same `PolicyEngine`. (Use libseccomp).
* **Acceptance:** statically-linked test that does a direct `syscall()` gets intercepted.
* **Estimate:** 2d

**T5.4 — Replay & deterministic trace format**

* **Desc:** Implement trace exporter and replayer which reads events and replays them in order.
* **Acceptance:** replay reproduces program behavior under controlled harness.
* **Estimate:** 1.5d

---

### Phase 6 — Polish & deployment (T6)

**T6.1 — CLI controller**

* **Desc:** `sysproxyctl` to launch/attach to processes, choose mode, set policy file, manage logs.
* **Acceptance:** basic CLI flags to start a target with LD_PRELOAD and policy path.
* **Estimate:** 1d

**T6.2 — Packaging & docs**

* **Desc:** README, architecture doc, example policies, and usage walkthrough. Add Docker compose for proxy.
* **Acceptance:** README includes quickstart and example.
* **Estimate:** 1d

**T6.3 — Benchmarks & perf reports**

* **Desc:** Microbenchmarks for read/write latency overhead under shim vs baseline.
* **Acceptance:** included bench scripts and sample results.
* **Estimate:** 1d

---

# 9. Sprint / timeline suggestion

* **Week 0 (prototype day):** T0.1, T0.2, T2.1, T3.2 (finish quick prototype with Python proxy). (~3–4 days if part-time)
* **Week 1:** T1.1, T1.2, T1.3, T2.2, T2.3 (core map, logger, shim skeleton). (3–5 days)
* **Week 2:** T3.1, T3.3, T4.1, T4.2 (IPC, sync path, policy). (4–6 days)
* **Week 3:** T5.1, T5.2, T5.3 (payload capture, multithreading, seccomp). (4–6 days)
* **Week 4:** T5.4, T6.1, T6.2, T6.3 (replay, CLI, docs, benchmarks). (4–6 days)

Adjust based on daily availability. Many tickets are independent and can be parallelized.

---

# 10. Testing plan (CI & local)

* Unit tests: `FdMap`, `PolicyEngine`, `Logger`, `IPC` serialization.
* Integration tests:

  * Example binaries run under shim with Python proxy.
  * Multi-threaded programs to catch races.
* Manual tests:

  * `LD_PRELOAD` test: `cat /etc/hosts`, `secret_reader`, `net_client`.
  * Deny rule test: `/etc/passwd` open returns EPERM.
* Security tests:

  * Ensure shim fails open on IPC failure.
  * Ensure no unbounded memory growth when logging big buffers.

---

# 11. Deliverables (MVP)

* `libsysproxy.so` capable of intercepting `open/read/write/close`.
* Basic `FdMap` and JSON logging into `logs/`.
* Local Python proxy to accept events (for prototype).
* Simple policy engine that can deny/redirect file opens.
* README with quickstart.

---