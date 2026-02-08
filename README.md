# ACTIVEBREACH-ENGINE (ABE)

[![Discord](https://img.shields.io/discord/1240608336005828668?label=TITAN%20Softworks&logo=discord&color=5865F2&style=flat)](https://discord.gg/yUWyvT9JyP)
![C](https://img.shields.io/badge/C-00599C?logo=c&logoColor=white&style=flat)
![C++](https://img.shields.io/badge/C%2B%2B-00599C?logo=c%2B%2B&logoColor=white&style=flat)
![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white&style=flat)

**ActiveBreach-Engine (ABE)** is a Windows execution capability platform designed to support authorized adversary emulation, detection validation, and low-level security research in modern EDR-protected environments.

**ABE** provides a controlled, fully dynamic mechanism for executing Windows system calls without reliance on user-mode API invocation or resident `ntdll.dll` code paths, enabling security teams to evaluate detection coverage, telemetry fidelity, and behavioral assumptions made by modern EDR, XDR, and security monitoring solutions.

This project is architected as a successor-class capability to historical syscall research tooling (e.g., SysWhispers and Hell’s Gate), addressing the limitations, static assumptions, and detectability issues inherent in earlier designs.

## SCOPE

Modern defensive products increasingly rely on user-mode instrumentation due to Microsoft locking down the kernel. This instrumentation comes in many forms, such as *API hooking* and *behavioral inference*, to detect malicious activity. While effective, these approaches introduce blind spots at the user-to-kernel boundary.

**ABE** targets what defensive products cannot control: the system itself. A common approach is for products to set *API hooks* on `Nt*` functions, which are exported by `ntdll.dll` and contain the `syscall` instruction. The `syscall` instruction is important for two reasons:

1. It is not instrumentable by user-mode products  
2. It performs a context switch  

When the CPU executes the `syscall` instruction, it transitions execution into a privileged kernel-mode context. This context switch itself is not directly observable by user-mode defensive products. API hooking, by contrast, relies on redirecting execution prior to the syscall, which executes the defensive product’s instrumentation routine. From an adversary emulation perspective, executing that instrumentation is undesirable.

![Hooking Diagram](./Diagram/AB.png)

This is where **ABE** comes in. **ABE** builds an in-process ring of stubs for each `syscall` instruction provided by `ntdll.dll`, encrypts them, and sets up a specialized dispatcher to decrypt and execute these syscalls. All execution is managed by ABE’s context-controlled dispatcher thread. This results in a controlled execution environment where system calls can be dispatched without user-mode monitoring or external product interference.

For a full technical outline, see [Technical Overview](./TECH.md)

## DEVELOPMENT

For ease of integration, **ABE** is provided in three trims: C, C++, and Rust. Rust is the most technically advanced implementation, while C++ offers an integrated debugger.

### Why three versions?

Primarily due to integration complexity. Linking cryptographic libraries and using Windows internal structures in C++ introduces development friction and unnecessary complexity. The goal of **ABE** is ease of integration, which means no external dependencies. As a result, the C and C++ versions are provided as single-include header files (`.h`).

The Rust version includes exclusive features such as stub encryption, a custom stub ring allocator, and TLS callbacks.

## USAGE

See [Usage Overview](./USAGE.md)

## Disclaimer

This tool is provided for **educational and authorized security research only**.  
Unauthorized use may violate applicable laws. The authors and contributors assume no liability.

## License

Copyright © 2026 TITAN Softwork Solutions

Licensed under the Apache License, Version 2.0 (the "License") **with the Commons Clause License Condition v1.0**.

- You may not use this software for commercial purposes ("Sell the Software" as defined in the Commons Clause).
- Full text is provided in `LICENSE`.

Apache 2.0: <http://www.apache.org/licenses/LICENSE-2.0>  
Commons Clause details: <https://commonsclause.com/>
