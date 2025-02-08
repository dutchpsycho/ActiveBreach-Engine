![MDSEC](https://www.mdsec.co.uk/wp-content/themes/mdsec/img/mdsec-logo.svg)

## Project Overview
ACTIVEBREACH-UM-HookBypass is an an implementation of a stub based syscall invocation system from a blogpost by [MDSEC](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)

<br>

This demonstrates a methodology for bypassing user-mode hooks by leveraging direct system call invocation without routing through user-mode API or using LoadLibrary, this also gets around breakpoints set on ``ntdll.dll``. The project showcases syscall stub generation by extracting system service numbers (SSNs) from `ntdll.dll` and invoking them directly.

For an explanation on how hooks work, and why I've created this, read > [TECH.md](TECH.md).

<br>

# Features 💎

## **Driverless**  

| **Bypass**                                      | **Description**                                                                        |
|-------------------------------------------------|----------------------------------------------------------------------------------------|
| **Global hooks on `ntdll.dll`**                 | Loads a clean copy of `ntdll.dll` from disk, avoiding in-memory modifications.         |
| **Remote process `ntdll.dll` hooks**            | Uses internal ActiveBreach dispatcher instead of calling hooked `ntdll.dll` directly.  |
| **Partial YARA/CADA evasion**                   | Minimizes `ntdll.dll` presence in memory by zeroing out portions.                      |

---

## **Kernel Driver**  

| **Sidestep**                      | **Description**                                                             |
|------------------------------------|-----------------------------------------------------------------------------|
| **PsSetLoadImageNotifyRoutine**    | Loads `ntdll.dll` manually, avoiding kernel notifications (`PsApi`).        |
| **MmLoadSystemImage**              | Maps `ntdll.dll` manually, preventing system image load tracking.           |


### **Normal hooked API call**
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
    │         │
    │         ▼
    │  Kernel (Syscall)  <─── (Direct system call without passing through `ntdll.dll`)
    │ 
    ▼ 
  Return
```
<br>

# **Using ActiveBreach (C & C++)**

---

## ActiveBreach Usage

### 1. Include the Appropriate Header
- **C++ Projects:**  
  Include `ActiveBreach.hpp` and link with `ActiveBreach.cpp`:
  ```cpp
  #include <ActiveBreach.hpp>
  ```
- **C/C++ Universal Projects:**  
  Include `ActiveBreach.h` and link with `ActiveBreach.c`:
  ```c
  #include "ActiveBreach.h"
  ```

### 2. Initialize ActiveBreach
Call the initialization function **before** any syscalls:
- **C++ Example (optional "LMK" prints a status message):**
  ```cpp
  ActiveBreach_launch("LMK");
  ```
- **C/C++ Example:**
  ```c
  ActiveBreach_launch();
  ```
This function maps `ntdll.dll`, extracts syscall numbers, builds syscall stubs, and sets up the system.

### 3. Making a System Call
Use the `ab_call` macro to invoke syscalls dynamically. You must supply:
- The NT function type
- The syscall name
- The required arguments

**Example for NtQuerySystemInformation:**
```cpp
NTSTATUS status;
status = ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", infoClass, buffer, bufferSize, &returnLength);
```
*(For C, the syntax is similar but might pass the status as an additional parameter.)*

### 4. Cleanup
No manual cleanup is needed—resources are automatically released at program exit.

---

## How does this work under the hood?

1. **ntdll.dll** is found in *System32*, then mapped into our processes private memory.
2. **ntdll's** exports are found, **SSN**'s are extracted and referenced against exceptions directory (way of checking for global hooks)
3. this is given to the stub manager, which then generates a stub for each syscall (around ~500 syscalls, total ~8kb mem)
4. when fetchstub is called, stub manager will get the relevant stub, then cast to the function ptr type.
5. this then loads the **syscall** args + **SSN**, then fires the syscall with **syscall** instruction & returns the status code (As any normal API would)

Actual instructions; (args are pre-loaded bc of x64 fastcalls)
Moves *rcx* into *r10*, loads **SSN** into *eax*, executes *syscall* then *ret*.

## Requirements:
- Windows, 11, x64 (Pending Win10 Compatibility)
- Visual Studio, C++ 17

### Compiling
1. Open `HookBypass.sln` in Visual Studio.
2. Build the solution (Release)

## Disclaimer
I am not responsible for anything done with this code. It is provided under public domain and is free-use, what users do with this falls under their personal obligations. I do not condone unethical use of this project, you are liable for your own actions.
