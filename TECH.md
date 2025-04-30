### What is a Hook, and Why Bypass It?

On Windows, user applications interact with the OS through two main API layers:

- **WinAPI** (e.g. `CreateFile` from `kernel32.dll`)
- **NtAPI** (e.g. `NtCreateFile` from `ntdll.dll`)

The WinAPI is just a wrapper. It calls into the NtAPI, which issues a syscall to the kernel. For example:

```text
CreateFile (kernel32.dll)
 → NtCreateFile (ntdll.dll)
   → syscall → Kernel
   → NTSTATUS returned
```

---

### How Syscalls Work

Modern Windows builds (21H2+ → 22H2 and onwards into 2025) introduced changes in the syscall prologue. These changes were designed to support mitigation mechanisms like:

- **HVCI (Hypervisor-protected Code Integrity)**
- **CFG/XFG (Control-flow Enforcement)**
- **Dynamic syscall fallback toggling**

This added a runtime check before the syscall instruction, to conditionally bypass fast syscalls if disabled.

Clean `NtOpenProcess` syscall stub:

```asm
NtOpenProcess:
    mov     r10, rcx                     ; standard syscall prelude
    mov     eax, 0x26                    ; syscall number (NtOpenProcess) AKA Syscall Service Number 
    test    byte ptr ds:[7FFE0308], 1    ; check syscall fallback bit (KUSER_SHARED_DATA)
    jnz     fallback                     ; if set, take alternative path
    syscall
    ret
```

The key addition is the test against `KUSER_SHARED_DATA + 0x308`, which Microsoft uses to control syscall mode dynamically at runtime. This check is *not* present in older syscall stubs (pre-20H2).

---

### What Does a Hook Look Like?

EDRs and Anti-Cheats commonly hook `ntdll.dll` exports by modifying the start of a syscall stub. But instead of overwriting the entire function, most modern implementations inject a **trampoline** via `call` that routes execution into their monitoring logic before falling through to the original stub.

This lets them inspect syscall arguments or context **before** the syscall executes, without relocating or duplicating the full function.

Example: Hooked `NtOpenProcess` (trampoline-style):

```asm
NtOpenProcess:
    call    0xWinDefender                ; call into EDR's syscall monitor
    mov     r10, rcx                     ; legit prologue starts here
    mov     eax, 0x26
    test    byte ptr ds:[7FFE0308], 1
    jnz     fallback
    syscall
    ret
```

The injected `call` pushes a return address and jumps to the EDR’s logic. After logging, it returns execution back to the original stub, allowing the syscall to continue as normal.

This style is less destructive and more stealthy than fully overwriting with a `jmp`, and it survives better across Windows updates.

---

### How Hooks Work

When your process calls something like `NtOpenProcess`:

1. It loads the function from `ntdll.dll`
2. If hooked, the function starts with a `call` to the EDR
3. The EDR inspects or logs the syscall, then returns to the stub
4. The syscall instruction is then issued normally

This entire process happens **before** the syscall instruction is reached, so even if your syscall goes through, your behavior was already seen.

---

### Bypassing Hooks via Direct Syscalls

You can avoid these hooks by skipping `ntdll.dll` completely:

1. Locate the **syscall number (SSN)** for the function you want
2. Generate your own syscall stub in memory
3. Issue the syscall directly from your code

By doing this, you never enter the hooked usermode export, so redirections don’t trigger.

Example flow:

```text
YourStub → syscall → Kernel
```

This bypasses any EDR/AntiCheat logic that relies on hooking DLL exports.

---

### Stub Structure Example

The modern syscall stub used in `ntdll.dll` includes fallback logic:

```asm
mov     r10, rcx
mov     eax, <syscall_id>
test    byte ptr ds:[0x7FFE0308], 1
jnz     fallback
syscall
ret
```

We don't need the KUSER bit-check, we can use a minimal prologue that skips it (What ActiveBreach uses)

```asm
mov     r10, rcx
mov     eax, <syscall_id>
syscall
ret
```

---

### Limitations

- This will **not bypass kernel-mode hooks** (like SSDT patching or callbacks), but those are rare in modern commercial EDRs due to PatchGuard.
- Syscall bypasses only defeat usermode hooks. Kernel callbacks, SSDT modifications, or hypervisor-layer inspection still see your behavior.
