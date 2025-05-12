![TITAN](https://avatars.githubusercontent.com/u/199383721?s=200&v=4)

## Project Overview  

**ActiveBreach Engine** is an open-source offensive security research project developed under the **TITAN Softwork Solutions** collective, designed for undetectable syscall execution under AC/AV/EDR protected environments.  

Inspired by [MDSEC](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/), **SysWhispers**, and **Hell’s Gate**. This framework expands on their foundational concepts by going beyond hardcoded syscall lists — implementing a full execution pipeline with dynamic stub generation, proper memory management, runtime encryption, and modern code.

---

### Why?

Most public syscall tooling falls into one of two buckets:

1. **Global Unhooking:**  
   Nuking all usermode protections via page remapping or ntdll restoration. Effective short-term — but loud, risky, and easily behaviorally profiled by modern EDRs/AC's.

2. **Static Stub Patching:**  
   Embedding syscall stubs inline. Fast, but fragile. Prone to detection through simple memory scanning or sig-based heuristics.

---

**ActiveBreach Engine** was built on a third principle:

> *“Sidestep.”*

Rather than restoring overwritten memory, touching hooks or exploiting the kernel, ActiveBreach extracts SSN's from a clean memory copy of `ntdll.dll`, builds ephemeral execution stubs in dynamically allocated memory, and proxies all execution through an isolated, internal unlinked dispatcher thread. All syscall interactions are memory-local, thread-isolated, and AV-opaque. Rust crate also encrypts stubs at rest.

---

### ActiveBreach Language Implementations

#### C Edition — *"Baremetal"*

* Designed for minimalism, portability, and raw Windows compatibility
* Syscall stubs are constructed in-place without any encryption
* Dispatcher runs on a single internal thread via `CreateThread`
* No STL or CRT dependencies — pure WinAPI
* Ideal for small implants, loaders, or low-footprint tools

---

#### C++ Edition — *"Enhanced"*

* Implements a dynamic syscall stub manager with hash-based lookup
* Encrypted syscall stubs are stored in the binary and decrypted on runtime
* Uses STL containers or `std::pmr` for optimal mem allocation under C++20
* Syscall dispatcher is threadpool-backed via `TP_CALLBACK_INSTANCE`, not a fixed thread
* Exception-safe, fully encapsulated in `_ActiveBreach_Internal`
* Compatible with C++14 and C++20
* Great for full-featured EDR bypass modules or internal framework integration
* Fastest execution model

---

#### Rust Edition — *"Advanced"*

* Constructs syscall stubs dynamically at runtime, uses a ring-based stub management system
* Single threaded, fast due to spinlock system
* Least context switches between userland & kernel
* Syscall stubs are encrypted in-memory with a signatureless LEA implementation
* Designed for seamless integration into Rust-native malware frameworks or red team tools
* Securest & stealthies
* Largest footprint

---


| Feature                 | C                | C++                        | Rust                        |
| ----------------------- | ---------------- | -------------------------- | --------------------------- |
| Thread Model            | Single Thread    | Threadpool Dispatcher      | Single Thread (Fast)        |
| Stub Encryption on Disk | None             | Yes (decrypted at runtime) | Semi (LLVM)                 |
| Runtime Stub Encryption | None             | No                         | Yes                         |
| String Encoding         | No               | Yes                        | Yes                         |
| STL/CRT Dependency      | No               | Yes (`std`/`pmr`)          | Yes                         |
| Invocation              | `ab_call_func()` | `ab_call_fn()`             | `ab_call()` (FFI or native) |
| Deployment              | Header + Source  | Header + Source            | Crate                       |
| Language Target         | C                | C++14 / C++20              | Rust 1.75+                  |

---

## Bypasses

#### 🚫 User-Mode (Driverless EDR/AV)

| **Bypass Target**              | **How It's Avoided**                                                                 |
|--------------------------------|----------------------------------------------------------------------------------------|
| `ntdll.dll` inline hooks       | Loads raw `ntdll.dll` from disk manually, bypassing loader and avoiding all inline patches |
| API call heuristics            | No `Nt*`, `Zw*`, or Win32 APIs used — all syscalls are dispatched via hashed stub indirection |
| Import resolver traps          | Nothing is dynamically resolved via `GetProcAddress` or `LoadLibrary`; all stubs are mapped from a clean image |
| `GetProcAddress` tracing       | Never used — stub lookup and mapping is performed via internal hashed syscall table |
| User-mode hook detection       | No Win32-layer APIs are touched; all calls avoid user-mode trampolines and inline detours |
| `CreateRemoteThread` heuristics| Thread creation is done via `NtCreateThreadEx` syscall stubs, avoiding heuristic detection |
| `NtSetInformationThread` usage| Direct syscall stub used to hide threads from debuggers; no API-layer visibility |
| ETW-based telemetry            | No interaction with ETW-traced APIs (e.g. `OpenProcess`, `WriteProcessMemory`, `VirtualAllocEx`, etc.) |
| AMSI (Windows Defender)        | No use of scripting or interpreter APIs; avoids all paths that would invoke `AmsiScanBuffer` |
| Import Address Table (IAT) hooks | Does not use any imported syscall-related functions — import table stays clean/normal |
| SEH/Vectored Exception tracing | No calls to `AddVectoredExceptionHandler` or related routines — avoids exception chaining traps |
| Heap/stack signature detection | Syscall stubs and argument passing occur on a dedicated, obfuscated thread with custom memory layout |
| `VirtualProtect` / `VPEx` guards | RWX stub memory is committed as RW, written, then changed to RX — minimal exposure to memory scanners |

---

#### ⛔ Kernel-Mode (Driver-Based)

| **Detection Vector**           | **Mitigation / Sidestep**                                                           |
|-------------------------------|--------------------------------------------------------------------------------------|
| `PsSetLoadImageNotifyRoutine` | Avoided by manually reading `ntdll.dll` from disk — no image load events fired |
| `MmLoadSystemImage` traps     | No system image mapping or section object creation is involved |
| Kernel stack traceback on caller TID         | Syscalls are dispatched from a dedicated thread — origin call stack is never modified |
| SMEP/SMAP/KVA traps            | No kernel-mode shellcode, no ring-0 transitions attempted |
| APC injection / thread hooks on caller TID  | Dispatcher thread is unlinked, obfuscated, and not enumerated via common thread inspection routines |
| File system filter drivers    | Uses direct NT file access to read `ntdll.dll`; avoids FS minifilter interception |
| Kernel ETW provider traps     | Never touches `EtwWrite` or other kernel tracing entrypoints — all telemetry is sidestepped |
| Hypervisor-based monitors     | Does not engage syscall shims or VM exit triggers — low-level behavior mimics activity |
| Process creation callbacks     | No new process is created — all execution stays in the current address space |
| PatchGuard integrity checks   | No kernel objects or memory regions are modified — avoids all PG violations |
| DSE/CI callback hooks         | No driver loading or signature verification involved — operates entirely in user-mode |
| CFG/XFG trapping              | No indirect control flow into unknown or untrusted pages; dispatcher thread controls all execution |
| Syscall return/ret checks     | Syscall stubs preserve expected CPU state and return cleanly; no ROP-style anomalies |

---

### 🧬 Detection Surface

| **Surface**              | **State**                        |
|--------------------------|----------------------------------|
| Hooked Kernel Functions  | **Not Bypassed** — kernel-mode EDR hooks (e.g. SSDT, inline traps) will still trigger |
| PE Imports               | **Clean** — no syscall-related functions resolved or used via IAT |
| Static Strings           | **Hashed/Encrypted** — no plaintext syscall names or known IOC markers |
| API Usage                | **None (Direct Syscall Stubs)** — completely bypasses Win32 and ntdll API layers |
| Memory Artefacts         | **Ephemeral / Zeroed** — stub memory is wiped after use, and mapping is transient |
| Disk Presence            | **None** — no dropped files, modules, or persistent presence on disk |
| Thread Context           | **Isolated** — dispatcher runs in its own stealth thread, separate from caller context |

---

### Example: Hooked API Flow vs ActiveBreach

```
User Process
    │
    ├──▶ CreateFile (Wrapper, kernel32.dll)
    │         │
    │         ▼
    │    NtCreateFile (ntdll.dll)   <─── [Hooked by AntiVirus/AntiCheat]
    │         │ 
    │         ▼
    │   [Hook Handler]  <─── (Monitoring, logging, blocking, etc...)
    │         │
    │         ▼
    │  Kernel (Syscall)  <─── (Actual system call after handling)
    │ 
    ▼ 
  Return 
```

---

### **ActiveBreach API call**
```
User Process
    │
    ├──▶ ab_call("NtCreateFile")  <─── (Not using "CreateFile" as ActiveBreach only supports Nt functions)
    │         │
    │         │
    │         │
    │         │
    │         │
    │         ▼
    │  Kernel (Syscall)  <─── (Direct system call without passing through `ntdll.dll`)
    │ 
    ▼ 
  Return
```

---

## Usage
See [USAGE.md](USAGE.md) for full setup & examples in **C, C++ & Rust**.

---

## License

**Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**  

[Full License](https://creativecommons.org/licenses/by-nc/4.0/)

---

## Disclaimer
This tool is for educational and research use only. Use at your own risk. You are solely responsible for how you use this code.
