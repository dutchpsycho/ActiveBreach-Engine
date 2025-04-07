# Using ActiveBreach (C, C++, Rust)

## 1. Include the Headers

### C++
```cpp
#include <ActiveBreach.hpp>
```

### C
```c
#include "ActiveBreach.h"
```

---

## 2. Launching ActiveBreach

### C++
```cpp
ActiveBreach_launch("LMK");
```

### C
```c
ActiveBreach_launch();
```

---

## 3. Making Syscalls

### ab_call Macro (C/C++)

#### C++
```cpp
NTSTATUS status = ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", infoClass, buffer, bufferSize, &returnLength);
```

#### C
```c
NTSTATUS status;
ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", infoClass, buffer, bufferSize, &returnLength);
```

---

### ab_call_fn (Dynamic)

#### C / C++
```c
ULONG_PTR ret = ab_call_fn("NtQuerySystemInformation", 5, infoClass, buffer, bufferSize, &returnLength);
```

#### C++ Template Helper:
```cpp
NTSTATUS status = ab_call_fn_cpp<NTSTATUS>("NtQuerySystemInformation", infoClass, buffer, bufferSize, &returnLength);
```

---

## Using ActiveBreach (Rust)

### 1. Add Dependency

```toml
[dependencies]
activebreach = { path = "path/to/activebreach" }
```

### 2. Launch & Use

```rust
activebreach_launch();
let ret = ab_call("NtProtectVirtualMemory", &[handle, base, size, new_protect]);
```

---

## Requirements
- Windows 10/11, x64
- MSVC, C++14 or C++20

---

## Compiling (C/C++)
```bash
Open `ActiveBreach.sln` in Visual Studio and build.
```