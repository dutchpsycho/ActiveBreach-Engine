![MDSEC](https://www.mdsec.co.uk/wp-content/themes/mdsec/img/mdsec-logo.svg)

## Project Overview
ACTIVEBREACH-UM-HookBypass is an an implementation of a stub based syscall invocation system from a blogpost by [MDSEC](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)

<br>

This demonstrates a methodology for bypassing user-mode hooks by leveraging direct system call invocation without routing through user-mode API or using LoadLibrary, this also gets around breakpoints set on ``ntdll.dll``. The project showcases syscall stub generation by extracting system service numbers (SSNs) from `ntdll.dll` and invoking them directly.

## What is a hook? why do they need to be bypassed?
On Windows, we have something called the **Windows API** *(WinApi/Windows.h)* and the **Native API** *(NtApi/ntdll.dll)*, **Windows API** is a wrapper around the **Native API**, these provide functions not normally accessible (as most transfer to the Kernel). For example, if we call **CreateFile**, It'll follow this routine;

``CreateFile (Kernel32.dll) > NtCreateFile (ntdll.dll) -> Kernel -> Return STATUSCODE``

Now, a hook can be set on any of the calls in the sequence, a usermode hook in this example could be set on either **CreateFile** or **NtCreateFile** *(More likely on NtCreateFile as this is the underlying Kernel translation)*, a usermode hook cannot be set on the Kernel calls.

The most common hooks will be set at the start of the function eg; a couple bytes replaced at the start of the ``ntdll.dll`` function re-routing the call to that EDR/AntiCheat's own handler 

Now, the flaw with this is that these hooks are only called if you make calls through that processes API and it passes through their DLL's, instead of overcomplicating and risking unhooking, we can instead make calls directly to the Kernel through **SSN's**.

To do this, we need something called an **SSN** *(Syscall Number)*, we can find these in DLL's like ``ntdll.dll``, each syscall has its own number, if you have the number you can call it directly through a stub, without passing through any user-mode APIs (This will NOT bypass Kernel hooks, but these are much rarer)

So, using this concept our call looks like this;

``NtCreateFile (Own process Stub) -> Kernel -> Return STATUSCODE``

This effectively bypasses any hooks set within the userspace, though this will do nothing against Kernel hooks.

## How do I use this? (C & C++)

## **C/C++ Usage w/ include**
### **1. Include the Header & Source file**
Ensure you include the `ActiveBreach.hpp` file in your project:
```cpp
#include <ActiveBreach.hpp>
```
Make sure Activebreach.hpp is linked.

### **2. Initialize ActiveBreach**
Before making any syscalls, initialize the system using:
```cpp
ActiveBreach_launch("LMK"); // Optional "LMK" argument will print "ACTIVEBREACH OPERATIONAL"
```
This function:
- Maps `ntdll.dll`
- Extracts syscall numbers (SSNs)
- Builds syscall stubs
- Sets up the ActiveBreach system

### **3. Making a System Call**
Use the `ab_call` macro to make syscalls dynamically. The caller **must** provide:
- The NT function type
- The syscall name
- The required arguments

#### **Example: NtQuerySystemInformation** (Through C include files)
```cpp
status = ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", infoClass, buffer, bufferSize, &returnLength);
```

Make sure you call ``ActiveBreach_launch``, as this initializes the ActiveBreach system.

### **4. Cleanup**
Cleanup is handled **automatically** at program exit. You do not need to manually free resources.

---

- The process you are performing "Educational Activities" on has usermode hooks set on functions, you don't wanna trip those. Implement this in your DLL to bypass them all, no unhooking/overwrites required.
- You don't want your process to be debugged, this'll bypass any breakpoints *(BPs)* on your process.
- A horrible AntiVirus has set global usermode hooks, you wanna get around that.

## How does this work under the hood?

1. **ntdll.dll** is found in *System32*, then mapped into our processes private memory.
2. **ntdll's** exports are found, **SSN**'s are extracted and referenced against exceptions directory (way of checking for global hooks)
3. this is given to the stub manager, which then generates a stub for each syscall (around ~500 syscalls, total ~8kb mem)
4. when fetchstub is called, stub manager will get the relevant stub, then cast to the function ptr type.
5. this then loads the **syscall** args + **SSN**, then fires the syscall with **syscall** instruction & returns the status code (As any normal API would)

Actual instructions; (args are pre-loaded bc of x64 fastcalls)
Moves *rcx* into *r10*, loads **SSN** into *eax*, executes *syscall* then *ret*.
=======
>>>>>>> Stashed changes

## Requirements:
- Windows, 11, x64 (Pending Win10 Compatibility)
- Visual Studio, C++ 17

### Compiling
1. Open `HookBypass.sln` in Visual Studio.
2. Build the solution (Release)

## Disclaimer
I am not responsible for anything done with this code. It is provided under public domain and is free-use, what users do with this falls under their personal obligations. I do not condone unethical use of this project, you are liable for your own actions.
