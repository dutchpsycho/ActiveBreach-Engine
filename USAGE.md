# USAGE.md

## Repository Layout (Key Files)
- `README.md`, `TECH.md`, `USAGE.md`
- `E900U.yar` (root YARA rule)
- `Diagram/` (PNG architecture diagrams)
- `SDK/`
  - `C/` (C implementation + `C.sln` + `C Tests`)
  - `C++/` (C++ implementation + `C++.sln` + `C++ Tests`)
  - `Rust/` (Rust crate + benchmark harness in `tests/`)

## Requirements
- Windows 10/11 x64
- MSVC toolchain (Visual Studio 2022 recommended) for C/C++
- Rust stable toolchain for Rust/KFD

All implementations target Windows x64 only.

## Build / Run

### C++
- Open `SDK/C++/C++.sln` in Visual Studio.
- Build either `C++` (core) or `C++ Tests`.
- Core files: `SDK/C++/Include/ActiveBreach.hpp` and `SDK/C++/Include/ActiveBreach.cpp`.

See `Example/minimal/include/ActiveBreach.cpp` for a working integration that wraps the SDK headers and demonstrates the `AntiBreach` integrity checks/diagnostics described below.

#### AntiBreach diagnostics (C++)
- `AntiBreach` (namespace inside `Example/minimal/include/ActiveBreach.cpp`) runs per-call integrity checks. `InitBounds` extracts the module `.text` range, `ChkTEB` validates the thread/environment block, `TraceSuspiciousCallers`/`StackWalk` look for return addresses outside the trusted range, and `Evaluate` increments the violation counter whenever a mismatch occurs.
- `_AbViolationCount()` (declared in `SDK/C++/Include/ActiveBreach.hpp`) exposes `g_violation_counter` so you can query how many anti-tamper events fired while the dispatcher keeps running.
- The dispatcher thread (see the tokenized work callback in `ActiveBreach.cpp`) already calls `AntiBreach::Evaluate()` before invoking each stub, so counting is automatic; use `_AbViolationCount()` to feed telemetry or break into debugger when it rises above zero.
- Defining `AB_DEBUG` before including `ActiveBreach.hpp` switches on `ActiveBreachDebugger`. The instrumentation in `Example/minimal/include/ActiveBreach.cpp` logs syscall metadata via `Start()` and `Return()`, including argument names from `syscall_db`, pointer memory classifications, register mappings, stack canaries, and NTSTATUS-to-string printing (`ntstatus_to_str`). The dispatcher wires the tracer around every syscall (see the `TPWork` callback) so you can inspect each call/return for debugging, albeit with high logging overhead.

### C
- Open `SDK/C/C.sln` in Visual Studio.
- Build either `C` (core) or `C Tests`.
- Core files: `SDK/C/Include/ActiveBreach.h` and `SDK/C/Include/ActiveBreach.c`.

### Rust (ActiveBreach crate)
```bash
cd SDK\Rust
cargo build
cargo build --release
```
Output: `SDK\Rust\target\{debug,release}\libactivebreach.rlib`.

#### Rust Feature Flags
Feature flags live in `SDK/Rust/Cargo.toml`:

- `secure` (default): Uses `PAGE_NOACCESS` at rest and protection flips during stub lifecycle.
- `stealth`: Marker feature for "no `secure`". Use `--no-default-features` to disable `secure`.
- `long_sleep`: Enables dispatcher idle teardown + blocking wait. Exposes `ab_set_long_sleep_idle_ms(ms)`.
- `ntdll_backend`: Prefer jumping into intact loaded-NTDLL syscall prologues; falls back to direct stubs if hooked/invalid.

Examples:
```bash
# default (secure)
cargo build

# no protection flips (stealth-ish)
cargo build --no-default-features --features stealth

# long idle teardown
cargo build --features long_sleep

# prefer loaded NTDLL prologues
cargo build --features ntdll_backend
```

### Rust Harness (benchmark/tests)
```bash
cd SDK\Rust
cargo test --test activebreach_harness

# stealth mode
cargo test --no-default-features --features stealth --test activebreach_harness

# prefer loaded-NTDLL prologues
cargo test --features ntdll_backend --test activebreach_harness
```

### Konflict Variant (KFD-EDR-Version)
Builds the Konflict variant inside `KFD-EDR-Version/` (Rust workspace). 

## Integration / Usage

### C++
1. Add `SDK/C++/Include/ActiveBreach.hpp` and `SDK/C++/Include/ActiveBreach.cpp` to your project.
2. Call `ActiveBreach_launch()` once at process start/TLS Callback/XLA.
3. Use `ab_call` (typed) or `ab_call_fn_cpp` (explicit arg count).

Example (mirrors `Example/minimal/main.cpp`):
```cpp
#include "ActiveBreach.hpp"

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    ULONG, PVOID, ULONG, PULONG
);

int main() {
    ActiveBreach_launch();
    NTSTATUS st = ab_call(
        NtQuerySystemInformation_t,
        "NtQuerySystemInformation",
        5, buffer, bufferSize, &returnLength
    );
}
```

### C
1. Add `SDK/C/Include/ActiveBreach.h` and `SDK/C/Include/ActiveBreach.c` to your project.
2. Call `ActiveBreach_launch()` once at process start/TLS Callback/XLA.
3. Use `ab_call` (macro) or `ab_call_func` for a dynamic arg count.

Example:
```c
#include "ActiveBreach.h"

int main() {
    ActiveBreach_launch();
    NTSTATUS status;
    ab_call(NTSTATUS, "NtQueryInformationProcess", status,
        (HANDLE)-1, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
}
```

### Rust
Add as a path dependency:
```toml
[dependencies]
activebreach = { path = "../SDK/Rust" }
```

Example:
```rust
use activebreach::{activebreach_launch, ab_call};

unsafe {
    activebreach_launch().expect("failed to init");
    let cpu = ab_call("NtGetCurrentProcessorNumber", &[]);
}
```

If built with `--features long_sleep`, you can configure the idle timeout:
```rust
#[cfg(feature = "long_sleep")]
activebreach::ab_set_long_sleep_idle_ms(60_000);
```

## Notes / Limits
- Syscall names must match exported `Nt*` names (max 63 bytes).
- Up to 16 arguments per call; the dispatcher enforces that limit and returns an error code if exceeded.
- `ActiveBreach_launch()` / `activebreach_launch()` must complete before any syscall; failing to initialize returns stub `0`/`NoOpStub`.
- In C/C++, missing stubs or lookup failures print errors to stderr and return `NoOpStub`; verify `_AbGetStub` results when diagnosing failures.

## Operational Changes (Recent)
- The Rust global opframe is no longer exposed as a `pub static mut`; it is kept internal and accessed via a small wrapper to reduce misuse.
- The caller-side wait in `AbFire` uses a hybrid backoff (pause/yield/spin) and a short timed `WaitOnAddress` to avoid burning CPU during long waits.
- The Rust thread spawner no longer closes the returned thread handle during `activebreach_launch()` to avoid introducing a close-call dependency in that module.
