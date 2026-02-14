# TECH.md

## Core Techniques Used

1. **Clean ntdll mapping + dynamic SSN extraction**  
2. **Encrypted ring-buffer of syscall stubs** (AES-128-CTR, per-process key)  
3. **Per-call decryption / SSN patching / re-encryption**  
4. **Stack spoofing (Sidewinder)** – fake realistic call stacks  
5. **Usermode-only dispatcher thread** (no kernel objects for sync)  
6. **Hidden dispatcher thread creation** (direct NtCreateThreadEx)  
7. **No WinAPI usage in hot paths** (avoids hooks)  
8. **Runtime-only memory** – nothing persistent for static analysis

These are layered so that even if one layer is defeated, others still protect.

## Why These Techniques Are Effective (and How Windows Actually Works)

### 1. How Windows Syscalls Really Work (Beginner Explanation)

- Every Windows process has `ntdll.dll` loaded.  
- Inside ntdll are functions like `NtCreateFile`, `NtOpenProcess`, etc.  
- These functions are tiny stubs:  

  ```asm
  mov r10, rcx      ; move first arg to r10 (calling convention)
  mov eax, 0xXX     ; SSN = System Service Number (unique per syscall, changes per Windows build)
  syscall           ; enter kernel
  ret
  ```

- The kernel looks at EAX (SSN) to decide which internal function to run.  
- EDR tools hook these ntdll stubs or monitor the syscall instruction to see what the process is doing.

**Direct syscalls** = manually build the same stub with the correct SSN -> bypasses ntdll hooks.  
But EDR evolved: they now check:

- Is the call coming from ntdll code section?  
- Does the call stack look like normal API calls (kernel32 -> ntdll)?  
- Is there a fresh RWX page with a syscall stub?  
- Is the stub encrypted or behaving strangely?

ActiveBreach defeats all of these.

### 2. Clean ntdll Mapping + Dynamic SSN Extraction

Why?  
SSNs change between Windows versions/builds. Hardcoding them breaks on updates.

How it works:

- On launch, ActiveBreach opens and memory-maps a fresh copy of `ntdll.dll` from `C:\Windows\System32\ntdll.dll`.  
- It parses the export table, finds every `Nt*`/`Zw*` function.  
- For each, it reads the first few bytes to extract the `mov eax, SSN` value.  
- Stores SSN in a hashmap (`FxHashMap<String, u32>`).

Effect:

- No reliance on the already-loaded (possibly hooked) ntdll.  
- Works on any Windows build without updating the binary.

### 3. Encrypted Ring-Buffer of Stubs (AES-CTR)

Why encrypt?

- Fresh RWX pages with syscall stubs are a huge red flag.  
- Static analysis (YARA) looks for the exact byte pattern of syscall stubs.

How it works:

- Preallocates a small ring of stubs (size is randomized at init, each stub is 32 bytes, 16-byte aligned).  
- Each stub starts as the template:

  ```asm
  mov r10, rcx
  mov eax, 0x00000000   ; placeholder SSN
  syscall
  ret
  ```

- Immediately encrypts the entire stub in-place using AES-128-CTR (encryption/decryption are identical XOR operations).  
- A per-process key is derived best-effort from CPUID + RDTSC (x86/x64).  
- With the default `secure` feature, stubs are protected `PAGE_NOACCESS` when encrypted at rest.

When a syscall is needed:

- Acquire a slot from the ring -> (optional) change protection -> decrypt -> patch -> mark executable -> use.

After use:

- Zero memory -> rewrite template -> re-encrypt -> back to `PAGE_NOACCESS` (when `secure` is enabled).

Effect:

- At rest: memory contains only encrypted blobs -> evades memory scans.  
- Only briefly decrypted/executable during actual syscall.  
- Ring reuse -> no constant allocation of new RWX pages.

### 4. Stack Spoofing (Sidewinder)

Why?
Modern EDR checks the call stack during syscall. A direct stub has a stack that looks wrong (no kernel32/kernelbase frames).

How Sidewinder works:

- Pre-resolves real addresses of common benign functions (e.g., `VirtualAlloc`, `OpenProcess`, `CreateFileW`, etc.) from legitimate DLLs.  
- Groups them into profiles (Memory, Process, Thread, Mapping).  
- Per thread, allocates a private fake stack page.  
- When building a syscall, it constructs a fake stack with realistic return addresses matching the syscall type.

Effect:

- Kernel/EDR sees a call stack that looks like legitimate API usage -> blends in perfectly.

### 5. Usermode-Only Dispatcher Thread

Why?
Directly issuing syscalls from the caller thread can leak context or be traced.

How it works:

- On launch, uses a fresh direct syscall to call `NtCreateThreadEx` and spawn a hidden dispatcher thread.  
- Caller queues requests into a shared `ABOpFrame` (pure usermode structure).  
- Dispatcher thread pulls request -> acquires stub -> patches SSN -> sets up spoofed stack -> executes syscall -> returns result.  
- Synchronization uses `WaitOnAddress` / `WakeByAddressSingle` plus short timed waits for backoff (no kernel event handles).

Effect:

- Caller thread never directly executes the syscall instruction.  
- No kernel synchronization objects -> harder to trace.

### Optional Backend: Loaded-NTDLL Prologue Jump (`ntdll_backend`)

When built with `--features ntdll_backend`, the dispatcher can prefer a different execution strategy:

- Resolve and cache an intact loaded-`ntdll.dll` syscall prologue pointer inside `ntdll` `.text`.
- Patch the stub as a tiny `mov r11, imm64; jmp r11` trampoline to that prologue.
- If the loaded stub/prologue looks hooked or fails validation, fall back to the direct-syscall stub template (never jump to arbitrary export entry bytes).

This backend disables stack spoofing (no synthetic return chain is constructed), because execution returns naturally from the `ntdll` prologue.

### 6. Overall Stealth Properties

- No WinAPI calls in evasion-critical paths (everything uses direct syscalls or manual memory work).  
- No persistent RWX regions.  
- No cleartext syscall stubs in memory.  
- Realistic call stacks.  
- Dynamic SSN resolution.  
- Minimal, encrypted, rotating footprint.

## Why Is This Considered Advanced?

Most public direct-syscall projects do one or two of these things.  
ActiveBreach combines **all major modern evasion vectors** into a single coherent framework:

| Detection Method              | Typical Direct Syscall | ActiveBreach Defense                              |
|-------------------------------|------------------------|---------------------------------------------------|
| ntdll hooks                   | Bypassed               | Bypassed (clean map + own stubs)                  |
| Fresh RWX pages               | Detected               | Encrypted ring, brief decryption                  |
| Static stub signatures        | Detected               | Encrypted at rest                                 |
| Suspicious call stack         | Detected               | Sidewinder spoofing                               |
| Direct syscall from caller    | Detected (context)     | Separate dispatcher thread                        |
| Hardcoded SSNs                | Breaks on update       | Runtime extraction                                |
| Timing / long execution       | Possible detection     | Fast AES-CTR + minimal work                       |

This layered approach makes it significantly harder for current-generation EDR to reliably flag the activity without high false positives.
