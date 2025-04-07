![TITAN](https://avatars.githubusercontent.com/u/199383721?s=200&v=4)

## Project Overview  

**Syscall Proxy** is an open-source research project developed by **TITAN Softwork Solutions** with inspiration from [MDSEC](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/), SysWhisperer & Hellsgate.  

This implements a stub-based internal syscall dispatcher which bypasses all usermode hooks and sidesteps lower level kernel API's (EDR/AC/AV evasion tech)

This project is powered by **ActiveBreach**, our dedicated syscall execution framework

I put a lot more effort into the rust version of this project. It supports memory encryption through an internal algo, leverages it's own TLS callback and uses an MT model. If you haven't used rust before, I'd reccomend trying.

For a technical breakdown on how hooks work, see > [TECH.md](TECH.md).

### Why?

I've seen so many implementations and frameworks where the consensus is "Lets unhook everything globally in usermode andd risk getting detected by thousands of measures!". These projects aren't inherently bad, I just think there's a less aggressive and smarter way of doing it. Enter Syscall-Proxy

<br>

# Bypasses

## **Driverless**  

| **Bypass**                                      | **Description**                                                                        |
|-------------------------------------------------|----------------------------------------------------------------------------------------|
| **Global hooks on `ntdll.dll`**                 | Reads `ntdll.dll` directly into buffer, bypassing any API's monitoring lib loading.    |
| **Remote process `ntdll.dll` hooks**            | Uses internal ActiveBreach dispatcher instead of calling hooked `ntdll.dll` directly.  |
| **YARA/CADA evasion**                           | No syscall names are exposed in plaintext, everything is hashed, ntdll's memory signature is destroyed & dropped the second it leaves mem   |
| **Memory Dumping (Rust Version)**               | When stubs are not in use, they're stored in encrypted memory via a custom encryption algorithm |

---

## **Kernel Driver**  

| **Sidestep**                       | **Description**                                                             |
|------------------------------------|-----------------------------------------------------------------------------|
| **PsSetLoadImageNotifyRoutine**    | Loads `ntdll.dll` manually, avoiding kernel notifications (`PsApi`).        |
| **MmLoadSystemImage**              | Maps `ntdll.dll` manually, preventing system image load tracking.           |
| **Stack Frame Dumps**              | Stack frames will be missing in some function calls due to the disabling of MSVC compiling features |


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

---

### 3. Making a System Call

#### **Using the `ab_call` Macro (C & C++)**

The `ab_call` macro dynamically invokes syscalls. You must supply:
- The NT function type (e.g., `NTSTATUS`, `ULONG`, etc.)
- The syscall name as a string
- The required arguments

**C Example:**
```c
NTSTATUS status;
ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", infoClass, buffer, bufferSize, &returnLength);
```

**C++ Example:**
```cpp
NTSTATUS status;
status = ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", infoClass, buffer, bufferSize, &returnLength);
```

**Explanation:**
- The `ab_call` macro resolves the syscall by using the function type (`NtQuerySystemInformation_t` in this case) and invokes it with the provided arguments.
- In **C**, the result is stored in the `result` variable. The syntax for passing arguments is similar, but the status is handled slightly differently.
- In **C++**, the macro works in the same way, but the flexibility of modern C++ features (such as templates and type inference) may provide easier and more elegant usage.

---

#### **Using the `ab_call_fn` Function (C & C++)**

`ab_call_fn` is a more flexible function designed for runtime dynamic syscall invocations. It allows passing any number of arguments dynamically.

**C Function Declaration:**
```c
extern "C" ULONG_PTR ab_call_fn(const char* name, size_t arg_count, ...);
```

**C Example:**
```c
ULONG_PTR ret = ab_call_fn("NtQuerySystemInformation", 5, infoClass, buffer, bufferSize, &returnLength);
```

**C++ Example:**
```cpp
ULONG_PTR ret = ab_call_fn("NtQuerySystemInformation", 5, infoClass, buffer, bufferSize, &returnLength);
```

**Explanation:**
- `ab_call_fn` takes the syscall name, the number of arguments (`arg_count`), and the actual arguments to pass to the syscall.
- It retrieves the corresponding syscall stub and invokes the system call directly, bypassing `ntdll.dll` and the usual API wrappers.
- This approach is more flexible compared to the `ab_call` macro as it can handle a variable number of arguments and is especially useful when arguments may change dynamically.

---

#### **C++ `ab_call_fn` Template Wrapper**

For C++ users, there's an additional helper template `ab_call_fn_cpp` that allows you to call `ab_call_fn` with any return type and arguments.

**C++ Example:**
```cpp
template<typename Ret = ULONG_PTR, typename... Args>
Ret ab_call_fn_cpp(const char* name, Args... args) {
    void* stub = _ab_get_stub(name);
    if (!stub) {
        fprintf(stderr, "ab_call_fn_cpp: stub for \"%s\" not found\n", name);
        return (Ret)0;
    }
    return (Ret)ab_call_fn(name, sizeof...(args), (ULONG_PTR)args...);
}
```

**Usage Example:**
```cpp
NTSTATUS status = ab_call_fn_cpp<NTSTATUS>("NtQuerySystemInformation", infoClass, buffer, bufferSize, &returnLength);
```

**Explanation:**
- `ab_call_fn_cpp` allows you to invoke `ab_call_fn` with a specified return type (`Ret`) and any number of arguments (`Args...`).
- It returns the result directly in the specified type (`NTSTATUS` in the example).

---

### Quick version:
- **`ab_call` macro** is the primary method for calling syscalls and works with both C and C++.
- **`ab_call_fn`** provides more flexibility for dynamically invoking syscalls with any number of arguments.
- In **C++**, `ab_call_fn_cpp` can be used to streamline calling syscalls with typed return values.


---

### 4. Cleanup
No manual cleanup is needed—resources are automatically released at program exit.

<br>

# Using ActiveBreach (Rust)

### 1. Add to Cargo Project
Add **ActiveBreach** as a dependency in your `Cargo.toml`:

```toml
[dependencies]
activebreach = { path = "path/to/activebreach" }
```

Then include the crate in your main file:

```rust
use activebreach::{activebreach_launch, ab_call};
```

---

### 2. Initialize ActiveBreach
Before making any syscalls, call the initialization function:

```rust
activebreach_launch();
```

This:
- Maps a local `ntdll.dll`
- Extracts syscall numbers
- Builds syscall stubs
- Launches a dispatcher thread

---

### 3. Making a System Call
Use `ab_call()` to dynamically proxy a syscall. Supply:
- The syscall name (`&str`)
- A slice of up to 16 `usize` arguments

```rust
let ret = ab_call("NtProtectVirtualMemory", &[proc_handle, base_addr, region_size, protect]);
```

This sends the call to the dispatcher, which'll execute the system call & return the status code

---

### 4. Cleanup
No explicit cleanup is required. All memory is zeroed and freed, and resources are released on process termination.

<br>

## Requirements:
- Win11/10, x64
- MSVC, C++ 14 OR 20

### Compiling
1. Open `ActiveBreach.sln` in Visual Studio.
2. Build the solution

<br>

### **License & Ownership**  
**ActiveBreach** is a research project developed by **TITAN Softwork Solutions** and is licensed under: 

### **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**  

Full License: [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/)

<br>

## Disclaimer
I am not responsible for anything done with this code. It is provided under public domain and is free-use, what users do with this falls under their personal obligations. I do not condone unethical use of this project, you are liable for your own actions.
