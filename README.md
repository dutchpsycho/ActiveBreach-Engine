![TITAN](https://avatars.githubusercontent.com/u/199383721?s=200&v=4)

## Project Overview  

**Syscall Proxy** is an open-source research project developed by **TITAN Softwork Solutions** with inspiration from [MDSEC](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/), SysWhisperer & Hellsgate.  

This implements a stub-based internal syscall dispatcher which bypasses all usermode hooks and sidesteps lower level kernel API's (EDR/AC/AV evasion tech)

This project is powered by **ActiveBreach**, our dedicated syscall execution framework

### Why?

I've seen so many implementations and frameworks where the consensus is "Lets unhook everything globally in usermode andd risk getting detected by thousands of measures!". These projects aren't inherently bad, I just think there's a less aggressive and smarter way of doing it. Enter Syscall-Proxy

---

## Bypasses

### 🚫 Driverless
| **Bypass**                            | **Description**                                                                 |
|--------------------------------------|---------------------------------------------------------------------------------|
| Global `ntdll.dll` hooks             | Reads directly from disk, skips APIs like `LoadLibrary`                         |
| Remote process `ntdll.dll` hooks     | Uses internal stubs, doesn't touch remote `ntdll.dll`                           |
| YARA/CADA evasion                    | Syscall names are hashed, `ntdll` is zeroed and dropped post-extraction        |
| Memory dumps                         | Stubs are encrypted in-memory when not executing (Rust version only)           |

### ⛔ Kernel Driver
| **Sidestep**                         | **Description**                                                                 |
|-------------------------------------|----------------------------------------------------------------------------------|
| PsSetLoadImageNotifyRoutine         | Manually loads `ntdll.dll`, skipping image load callbacks                       |
| MmLoadSystemImage                   | Avoids flagged system image mapping entirely                                   |
| Stack Frame Tracing                 | Compiled with MSVC stack metadata disabled to confuse dumpers                   |

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
