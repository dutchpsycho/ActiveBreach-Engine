![TITAN](https://avatars.githubusercontent.com/u/199383721?s=200&v=4)

## Project Overview  

**Syscall Proxy** is an open-source research project developed by **TITAN Softwork Solutions** with inspiration from [MDSEC](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/), SysWhisperer & Hellsgate.  

This implements a stub-based internal syscall dispatcher which bypasses all usermode hooks and sidesteps lower level kernel API's (EDR/AC/AV evasion tech)

This project is powered by **ActiveBreach**, a dedicated syscall execution we built framework that:
- Dynamically extracts **system service numbers (SSNs)** from `ntdll.dll`
- Constructs **syscall stubs** for direct execution
- Uses a **dispatcher model** to invoke syscalls without routing through user-mode APIs
- Leverages a **callback** to prevent debugging.

I put a lot more effort into the rust version of this project. It supports memory encryption through an internal algo, leverages it's own TLS callback and uses an MT model. If you haven't used rust before, I'd reccomend trying.

For a technical breakdown on how hooks work, see > [TECH.md](TECH.md).

### Why did I make this?

I've seen so many implementations and frameworks where the consensus is "Lets unhook everything globally in usermode andd risk getting detected by thousands of measures!". These projects aren't inherently bad, I just think there's a less aggressive and smarter way of doing it. Enter Syscall-Proxy

<br>

# Bypasses

## **Driverless**  

| **Bypass**                                      | **Description**                                                                        |
|-------------------------------------------------|----------------------------------------------------------------------------------------|
| **Global hooks on `ntdll.dll`**                 | Reads `ntdll.dll` directly into buffer, bypassing any API's monitoring lib loading.    |
| **Remote process `ntdll.dll` hooks**            | Uses internal ActiveBreach dispatcher instead of calling hooked `ntdll.dll` directly.  |
| **Partial YARA/CADA evasion**                   | Minimizes `ntdll.dll` presence in memory by zeroing out portions.                      |

The rust version fully bypasses YARA/CADA evasion unless scanned during syscall execution due to page encryption.

---

## **Kernel Driver**  

| **Sidestep**                       | **Description**                                                             |
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

<br>

## Requirements:
- Win11/10, x64
- MSVC, C++ 17/20

### Compiling
1. Open `ActiveBreach.sln` in Visual Studio.
2. Build the solution

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
We am not responsible for anything done with this code. It is provided under public domain and is free-use, what users do with this falls under their personal obligations. I do not condone unethical use of this project, you are liable for your own actions.
