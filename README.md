![TITAN](https://avatars.githubusercontent.com/u/199383721?s=200&v=4)

## Project Overview  

Welcome to **ActiveBreach Engine**. This is an open-source offensive security research project developed under **TITAN Softwork Solutions**. Designed for bypassing hooks & remaining undetected in protected environments.

Inspired by [MDSEC](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/), **SysWhispers**, and **Hell’s Gate**. This framework expands on their foundational concepts by going beyond hardcoded syscall lists — We implemented a full execution pipeline with dynamic stub generation, proper memory management, runtime encryption, and modern code.

---

### Why?

Most public syscall tooling falls into one of two categories:

1. **Global Unhooking:**  
   Nuking all usermode protections via page remapping or ntdll restoration. Effective short-term — but loud, risky, and easily behaviorally profiled by modern EDRs/AC's.

2. **Static Stub Patching:**  
   Embedding syscall stubs inline. Fast, but fragile. Prone to detection through simple memory scanning or sig-based heuristics.

**ActiveBreach Engine** was built on a third category:

Rather than restoring overwritten memory, touching hooks or elevating to the kernel, ActiveBreach sets up it's own encrypted Syscall Execution framework in an unlinked thread. Using this framework is identical to how you'd use any normal Nt* function from ``ntdll.dll``, but with ActiveBreach's wrapper.

---

### How does ActiveBreach work?

Instead of routing throug ``ntdll.dll``, which is almost 100% of the time hooked, ActiveBreach sets up its own layer, replicating the Nt layer to execute syscalls directly to the Kernel, without touching any other API's on the way. This means any Nt* call you execute via ActiveBreach will bypass any usermode (Including remote process's, or global) hooks. If you'd like a more in-depth explanation on actual hooking, see > [TECH.md](TECH.md)

---

### ActiveBreach Language Implementations

#### C Edition

- Smallest, most basic version. Can be included in any C/C++ project on MSVC, simply add the .c/h files & compile.
- Does not include encryption or encoding of strings, runtime stub building, operates on the same core ideas but not fully fledged.
- Fastest of the 3, but the real speed difference is minimal when you're considering these are syscalls.

---

#### C++ Edition

- Larger implementation, RAII, leveraged C++ language features
- Cane be included on any C++ project on MSVC, simply add the .cpp/hpp & compile.
- Supports C++ 14&20, MSVC
- Encodes & Decrypts strings and builds stubs from encrypted bytes
- Larger, more secure

#### Rust Edition

- Much, much larger implementation
- Used as a crate, can easily be refactored into a DLL (coming soon)
- For use in larger projects, much more stable, stealthy & optimized
- Stubs are encrypted via unsignatured LEA crypto implementation
- Imporved memory management, stub management, ring allocation system & usermode spinlocks, much less context switching
- Runs in unlinked isolated thread
- Able to be embedded & ran in TLS callback before process init (See example in ``testrunner``)

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
