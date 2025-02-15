![TITAN SOFTWORKS](https://cdn.discordapp.com/icons/1240608336005828668/c1bf74f2566a9ab188447ef8ce679b4d.webp?size=2048&format=webp)

## Project Overview  

**Syscall Proxy** is an open-source research project developed by **TITAN Softwork Solutions** and inspired by [MDSEC](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/).  

It implements a **stub-based syscall proxying system**, allowing **direct invocation of system calls** while bypassing traditional user-mode hooks, anti-cheat, and antivirus monitoring.  

This project is powered by **ActiveBreach**, a dedicated syscall execution framework that:  
- Dynamically extracts **system service numbers (SSNs)** from `ntdll.dll`  
- Constructs **syscall stubs** for direct execution  
- Uses a **dispatcher model** to invoke syscalls without routing through user-mode APIs  

For a deeper technical breakdown, see > [TECH.md](TECH.md).  

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

## **How Does This Work Under the Hood?**

### **1. Syscall Proxying & Stub Generation**
1. **Mapping a Clean Copy of `ntdll.dll`**  
   - `ntdll.dll` is located in *System32* and mapped into the process's private memory.  
   - This prevents interaction with the system's in-memory version, which may be hooked by security tools.

2. **Extracting System Service Numbers (SSNs)**  
   - The exports of `ntdll.dll` are parsed to extract **SSNs** (System Service Numbers).  
   - The exception directory is checked to detect potential **global hooks** applied by security tools.

3. **Stub Generation & Execution**  
   - The **stub manager** generates **lightweight syscall stubs** (around ~500 stubs, totaling ~8KB in memory).  
   - Each stub is mapped into executable memory and associated with its corresponding **SSN**.

4. **Fetching & Executing Syscalls**  
   - When a syscall is requested, the **stub manager retrieves the corresponding stub**.  
   - The stub is cast to a function pointer and executed, ensuring **direct syscall execution**.  
   - This **bypasses user-mode API hooks**, preventing detection by traditional monitoring tools.

5. **Execution Flow in Assembly (x64 Fastcall Convention)**  
   - Moves **`rcx` into `r10`** (x64 fastcall convention).  
   - Loads **SSN** into `eax`.  
   - Executes **`syscall`** and returns the status code (`ret`).  

---

### **2. Worker Thread Model (Multi-Threaded Execution)**
- **A dedicated worker thread** now manages syscall execution.  
- Uses a **dispatcher event model** to handle system calls without blocking the main thread.  
- Enables **synchronous** (blocking) and **asynchronous** (non-blocking) execution, improving performance.  
- Allows **multiple syscalls to be handled concurrently**, increasing efficiency.

---

### **3. Asynchronous Procedure Call (APC) Syscall System**
- **Leverages APCs (Asynchronous Procedure Calls) for indirect execution.**  
- Uses **APC injection** to schedule syscalls at specific execution points.  
- Enables execution in a **different thread context**, reducing the risk of detection.  
- Supports **queued syscalls** via `NtQueueApcThread`, allowing syscall execution inside alertable threads.  
- Works in tandem with the **stub-based system**, dynamically resolving and executing syscalls.  

<br>

## Requirements:
- Windows, 11, x64 (Pending Win10 Compatibility)
- Visual Studio, C++ 17

### Compiling
1. Open `HookBypass.sln` in Visual Studio.
2. Build the solution (Release)

<br>

### **License & Ownership**  
**ActiveBreach** is a research project developed by **TITAN Softwork Solutions** and is licensed under:  

### **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**  
You are free to:  
✔ **Share** — Copy and redistribute this software in any format.  
✔ **Adapt** — Modify and build upon it.  

**However:**  
❌ **No Commercial Use** — This software cannot be used in for-profit applications.  
✔ **Attribution Required** — You must credit **TITAN Softwork Solutions** as the original creator.  
✏ **Modifications Must Be Documented** — If you make changes, you must state what was modified.  

Full License: [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/)

<br>

## Disclaimer
I am not responsible for anything done with this code. It is provided under public domain and is free-use, what users do with this falls under their personal obligations. I do not condone unethical use of this project, you are liable for your own actions.
