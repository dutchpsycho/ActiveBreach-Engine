![MDSEC](https://www.mdsec.co.uk/wp-content/themes/mdsec/img/mdsec-logo.svg)

## Project Overview
ACTIVEBREACH-UM-HookBypass is an an implementation of a stub based syscall invocation system from a blogpost by [MDSEC](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)

<br>

This demonstrates a methodology for bypassing user-mode hooks by leveraging direct system call invocation without routing through user-mode API or using LoadLibrary, this also gets around breakpoints set on ``ntdll.dll``. The project showcases syscall stub generation by extracting system service numbers (SSNs) from `ntdll.dll` and invoking them directly.

## What is a hook? why do they need to be bypassed?
On Windows, we have something called the **Windows API** *(Windows.h)* and the **Native API** *(ntdll.dll)*, **Windows API** is a wrapper around the **Native API**, these provide functions not normally accessible (as most transfer to the Kernel). For example, if we call **CreateFile**, It'll follow this routine;

<sub>The proper naming convention is the NtApi and WinApi</sub>

``CreateFile (Kernel32.dll) > NtCreateFile (ntdll.dll) -> Kernel -> Return STATUSCODE``

Now, a hook can be set on any of the calls in the sequence, a usermode hook in this example could be set on either **CreateFile** or **NtCreateFile** *(More likely on NtCreateFile as this is the underlying Kernel translation)*, a usermode hook cannot be set on the Kernel calls.

The most common hooks will be set at the start of the function eg; a couple bytes replaced at the start of the ``ntdll.dll`` function re-routing the call to that EDR/AntiCheat's own handler 

Now, the flaw with this is that these hooks are only called if you make calls through that processes API and it passes through their DLL's, instead of overcomplicating and risking unhooking, we can instead make calls directly to the Kernel through **SSN's**.

To do this, we need something called an **SSN** *(Syscall Number)*, we can find these in DLL's like ``ntdll.dll``, each syscall has its own number, if you have the number you can call it directly through a stub, without passing through any user-mode APIs (This will NOT bypass Kernel hooks, but these are much rarer)

So, using this concept our call looks like this;

``NtCreateFile (Own process Stub) -> Kernel -> Return STATUSCODE``

This effectively bypasses any hooks set within the userspace, though this will do nothing against Kernel hooks.

## What is this useful for?

- The process you are performing "Educational Activities" on has UM hooks set on their ntdll funcs, you don't wanna trip those. Implement this in your DLL to bypass them all, no unhooking/overwrites required.
- You don't want your process to be debugged, this'll bypass BP's on ``ntdll.dll`` functions.
- A horrible EDR or Anticheat has set global hooks in the User-Space on your system, you want to (Educationally) get around this. 

## Requirements:
- Windows, x64
- Visual Studio or Cmake to compile

## Features;
- Extracts **system service numbers (SSNs)** directly from `ntdll.dll` export's table (EAT)
- Generates **syscall stubs** to invoke syscalls directly, avoiding user-mode hooks, this is done by creating the same stub that would be seen in `ntdll.dll`, but for our own process.

## Fundementals

### **System Service Number (SSN) Extraction**
The project identifies system service numbers from the `ntdll.dll` export table:
1. Maps `ntdll.dll` into memory using `CreateFileMapping` and `MapViewOfFile`, if this was done through LoadLibrary it is likely to be flagged by EDR/AC.
2. PE Validation
3. Parses the export directory to locate functions prefixed with `Nt`.
4. Extracts SSNs by analyzing the function prologue;
   - `mov r10, rcx`
   - `mov eax, <SSN>`
   - `syscall`
5. Stores SSNs in a mapping of syscall names to their corresponding number.

### **Direct Syscall Invocation**
By bypassing user-mode APIs (e.g., `NtQuerySystemInformation`), the project avoids user-mode hooks placed by EDR/AC/Debuggers
- Allocates executable memory to store syscall stubs.
- Constructs stubs dynamically with the extracted SSN.
- Executes syscalls directly to the Kernel.

### **User-Mode Hooks and Instrumentation Callbacks**
- **User-Mode Hooks**: Often implemented by intercepting calls to functions in `ntdll.dll`, such as `NtQuerySystemInformation`, and redirecting them to malicious or monitoring code. These hooks can be bypassed by avoiding the hooked API entirely and directly invoking the syscall.
- **Instrumentation Callbacks**: Sometimes anti-tamper systems use callbacks in the TEB to intercept & validate thread ops. While this is outside the primary scope of the project, the `ICManager` utility provides a routine to identify and disable some general callbacks.

## Build Instructions

C++ 17.

### Using Visual Studio
1. Open `HookBypass.sln` in Visual Studio.
2. Build the solution (Release)

### Using CMake
Run Compile.bat

## Disclaimer
I am not responsible for anything done with this code. It is provided under public domain and is free-use, what users do with this falls under their personal obligations. I do not condone unethical use of this project, you are liable for your actions.
