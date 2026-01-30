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

### Rust Harness (benchmark/tests)
```bash
cd SDK\Rust\tests
cargo run --release
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

## Notes / Limits
- Syscall names must match exported `Nt*` names (max 63 bytes).
- Up to 16 arguments per call; the dispatcher enforces that limit and returns an error code if exceeded.
- `ActiveBreach_launch()` / `activebreach_launch()` must complete before any syscall; failing to initialize returns stub `0`/`NoOpStub`.
- In C/C++, missing stubs or lookup failures print errors to stderr and return `NoOpStub`; verify `_AbGetStub` results when diagnosing failures.
