/*
 * ==================================================================================
 *  Repository:   Syscall Proxy
 *  Project:      ActiveBreach
 *  File:         ActiveBreach.cpp
 *  Author:       DutchPsycho
 *  Organization: TITAN Softwork Solutions
 *  Inspired by:  MDSEC Research
 *
 *  Description:
 *      ActiveBreach is a syscall abstraction layer that dynamically proxies syscalls
 *      by extracting system service numbers (SSNs) from ntdll.dll and constructing hashed
 *      syscall stubs for indirect execution.
 *
 *  License:      Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)
 *  Copyright:    (C) 2025 TITAN Softwork Solutions. All rights reserved.
 *
 *  Licensing Terms:
 *  ----------------------------------------------------------------------------------
 *   - You are free to use, modify, and share this software.
 *   - Commercial use is strictly prohibited.
 *   - Proper credit must be given to TITAN Softwork Solutions.
 *   - Modifications must be clearly documented.
 *   - This software is provided "as-is" without warranties of any kind.
 *
 *  Full License: https://creativecommons.org/licenses/by-nc/4.0/
 * ==================================================================================
 */

#include "ActiveBreach.hpp"

#include <windows.h>
#include <stdexcept>
#include <string>
#include <cstring>
#include <unordered_map>
#include <atomic>
#include <cstdio>
#include <iostream>

#if __cplusplus >= 202002L
#include <memory_resource>
#endif

#include <immintrin.h>
#include <intrin.h>

using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST
    );

/**
 * @brief Performs runtime integrity checks to detect potential tampering, debugging, or external influence.
 *
 * This function performs multiple low-level validations:
 * - Initializes .text section bounds (if not already initialized).
 * - Checks if the current thread's TEB matches the expected process/thread ID.
 * - Walks the stack to identify suspicious return addresses (RIPs) that are outside the module's .text section.
 * - Detects common debugging indicators (PEB->BeingDebugged, NtGlobalFlag).
 *
 * If a violation is found (invalid TEB or suspicious RIP), it increments a global violation counter.
 * This function is intended to be called frequently (e.g., on syscall execution) to provide continuous anti-tamper assurance.
 *
 * @note Does not terminate the process or take evasive action — it only logs and counts violations.
 *       Use GetViolationCount() to retrieve current violation state.
 */
namespace AntiBreach {

    static std::atomic<uintptr_t> g_text_start{ 0 };
    static std::atomic<uintptr_t> g_text_end{ 0 };
    static std::atomic<bool>      g_text_initialized{ false };
    static std::atomic<uint32_t>  g_violation_counter{ 0 };

    [[nodiscard]] __forceinline PPEB GetPEB() noexcept {return reinterpret_cast<PPEB>(__readgsqword(0x60));}
    [[nodiscard]] __forceinline PTEB GetTEB() noexcept {return reinterpret_cast<PTEB>(__readgsqword(0x30));}

    [[nodiscard]] inline bool ChkTEB() noexcept
    {
        const auto teb = GetTEB();
        bool ok =
            (DWORD)(ULONG_PTR)teb->ClientId.UniqueProcess == __readgsdword(0x40) &&
            (DWORD)(ULONG_PTR)teb->ClientId.UniqueThread == __readgsdword(0x48);

#ifdef AB_DEBUG
        if (!ok) std::puts("[AntiBreach] TEB mismatch");
#endif

        return ok;
    }

    inline void InitBounds() noexcept
    {
        if (g_text_initialized.load(std::memory_order_acquire)) return;

        uintptr_t base = 0;
        __try {
            base = reinterpret_cast<uintptr_t>(GetPEB()->ImageBaseAddress);
        }

        __except (EXCEPTION_EXECUTE_HANDLER) {
#ifdef AB_DEBUG
            std::puts("[AntiBreach] PEB read failed");
#endif
            return;
        }

        if (base < 0x10000 || base > 0x7FFFFFFFFFFF) return;

        auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base); if (IsBadReadPtr(dos, sizeof * dos) || dos->e_magic != IMAGE_DOS_SIGNATURE) return; 
        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(base + dos->e_lfanew); if (IsBadReadPtr(nt, sizeof * nt) || nt->Signature != IMAGE_NT_SIGNATURE) return;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        WORD  count = nt->FileHeader.NumberOfSections;

        for (WORD i = 0; i < count; ++i) {
            if (*reinterpret_cast<DWORD const*>(sec[i].Name) == 'txet') {
                g_text_start.store(base + sec[i].VirtualAddress, std::memory_order_relaxed);
                g_text_end.store(g_text_start.load() + sec[i].Misc.VirtualSize, std::memory_order_release);

#ifdef AB_DEBUG
                std::printf("[AntiBreach] .text [%p–%p]\n",
                    (void*)g_text_start.load(), (void*)g_text_end.load());
#endif

                break;
            }
        }

        g_text_initialized.store(true, std::memory_order_release);
    }

    inline bool IsDebuggerPresentFast() noexcept {
        return GetPEB()->BeingDebugged || (GetPEB()->NtGlobalFlag & 0x70);
    }

    struct CallerTraceInfo {
        void* suspicious_rips[4]{};
        int   count{};
    };

    [[nodiscard]] inline CallerTraceInfo TraceSuspiciousCallers() noexcept {
        CallerTraceInfo info{};
        auto* rsp = reinterpret_cast<uintptr_t const*>(_AddressOfReturnAddress());

        constexpr uintptr_t lo = 0x10000;
        constexpr uintptr_t hi = 0x7FFFFFFFFFFF;

        auto txt_lo = g_text_start.load(std::memory_order_acquire);
        auto txt_hi = g_text_end.load(std::memory_order_acquire);

        for (int i = 0; i < 64 && info.count < 4; ++i) {
            uintptr_t rip = rsp[i];
            if (rip < lo || rip > hi) continue;
            if (rip >= txt_lo && rip <= txt_hi) continue;

            info.suspicious_rips[info.count++] = (void*)rip;
        }

        return info;
    }

    [[nodiscard]] inline void* StackWalk() noexcept
    {
        auto const* rsp = reinterpret_cast<uintptr_t const*>(_AddressOfReturnAddress());

        constexpr uintptr_t lo = 0x10000;
        constexpr uintptr_t hi = 0x7FFFFFFFFFFF;

        auto const txt_lo = g_text_start.load(std::memory_order_acquire);
        auto const txt_hi = g_text_end.load(std::memory_order_acquire);

        for (int i = 0; i < 64; ++i) {
            uintptr_t rip = rsp[i];
            if (rip < lo || rip > hi)      continue;
            if (rip >= txt_lo && rip <= txt_hi) continue;

#ifdef AB_DEBUG
            std::printf("[AntiBreach] External RIP: %p\n", (void*)rip);
#endif

            return (void*)rip;
        }

#ifdef AB_DEBUG
        std::puts("[AntiBreach] No external RIP");
#endif

        return nullptr;
    }

    inline void Evaluate() noexcept {

        bool debugged = IsDebuggerPresentFast();
        auto trace = TraceSuspiciousCallers();

#ifdef AB_DEBUG
        std::puts("\n[[ AntiBreach ]]");
#endif
        InitBounds();

        bool teb_ok = ChkTEB();
        void* rip = StackWalk();
        if (!teb_ok || !rip) {
            ++g_violation_counter;

#ifdef AB_DEBUG
            std::printf(
                "  Status: \x1B[31mVIOLATION\x1B[0m\n"
                "  TEB: %s\n"
                "  RIP: %s\n"
                "  Count: %u\n\n",
                teb_ok ? "OK" : "FAIL",
                rip ? "OK" : "NONE",
                g_violation_counter.load());
#endif
            return;
        }

#ifdef AB_DEBUG
        std::printf(
            "  Status: \x1B[32mPASS\x1B[0m\n"
            "  RIP: %p\n"
            "  Count: %u\n\n",
            rip,
            g_violation_counter.load());
#endif
    }

    [[nodiscard]] inline uint32_t GetViolationCount() noexcept
    {
        return g_violation_counter.load();
    }
}

/**
 * @brief Provides runtime preprocessor def tracing and inspection for syscalls invoked through ActiveBreach.
 *
 * This debugging subsystem allows detailed introspection of syscall arguments and return states
 * during development or security testing. When `AB_DEBUG` is a preprocessor def, it activates logging &
 * diagnostics for each syscall dispatched by the ActiveBreach system.
 *
 * Features include:
 * - Argument classification by type (integer, pointer, handle, flags).
 * - Symbolic mapping of known values (e.g., access rights, protection flags).
 * - Pointer validation using `VirtualQuery`, including region protection checks.
 * - Stack trace inspection and argument-to-register mapping (RCX, RDX, R8, R9).
 * - Canary detection for stack corruption or overwritten arguments.
 * - NTSTATUS-to-string resolution for interpreting return codes.
 *
 * Internally maintains a static database (`syscall_db`) defining known syscall signatures and
 * corresponding metadata. Uses `Start()` to log syscall entry and `Return()` to log final status.
 *
 * @note If AB_DEBUG is not in preprocessor definitions, this code is excluded from compilation.
 * @note Tracing introduces overhead and console logging — use only in safe/test environments.
 */
#ifdef AB_DEBUG
#include <map>
#include <vector>

namespace ActiveBreachDebugger {

    enum class ArgType { Integer, Pointer, Handle, Flags };

    struct ArgMeta {
        const char* name;
        ArgType type;
    };

    struct SyscallMeta {
        const char* name;
        std::vector<ArgMeta> args;
        std::map<ULONG_PTR, const char*> knownValues;
    };

    const std::map<std::string, SyscallMeta> syscall_db = {

        { "NtCreateSection", {
            "NtCreateSection",
            {
                { "SectionHandle", ArgType::Handle },
                { "DesiredAccess",  ArgType::Flags  },
                { "ObjectAttributes", ArgType::Pointer },
                { "MaximumSize",    ArgType::Pointer },
                { "PageProtect",    ArgType::Integer },
                { "AllocAttr",      ArgType::Flags  },
                { "FileHandle",     ArgType::Handle },
                { "Extra",          ArgType::Integer }
            },
            {
                { PAGE_READONLY,        "PAGE_READONLY" },
                { PAGE_READWRITE,       "PAGE_READWRITE" },
                { PAGE_EXECUTE_READ,    "PAGE_EXECUTE_READ" },
                { PAGE_EXECUTE_READWRITE, "PAGE_EXECUTE_READWRITE" },
                { SEC_COMMIT,           "SEC_COMMIT" },
                { SEC_RESERVE,          "SEC_RESERVE" }
            }
        }},
        { "NtQuerySystemInformation", {
            "NtQuerySystemInformation",
            {
                { "SystemInformationClass", ArgType::Integer },
                { "SystemInformation",      ArgType::Pointer },
                { "SystemInformationLength",ArgType::Integer },
                { "ReturnLength",           ArgType::Pointer }
            },
            {
                { 5,  "SystemProcessInformation" },
                { 11, "SystemHandleInformation" },
                { 16, "SystemModuleInformation" },
                { 0x23, "SystemExtendedHandleInformation" },
                { 0x2B, "SystemCodeIntegrityInformation" }
            }
        }},

        { "NtOpenProcess", {
            "NtOpenProcess",
            {
                { "ProcessHandle",    ArgType::Handle  },
                { "DesiredAccess",    ArgType::Flags   },
                { "ObjectAttributes", ArgType::Pointer },
                { "ClientId",         ArgType::Pointer }
            },
            {
                { PROCESS_ALL_ACCESS,      "PROCESS_ALL_ACCESS" },
                { PROCESS_VM_READ,         "PROCESS_VM_READ" },
                { PROCESS_VM_WRITE,        "PROCESS_VM_WRITE" },
                { PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION" }
            }
        }},
        { "NtAllocateVirtualMemory", {
            "NtAllocateVirtualMemory",
            {
                { "ProcessHandle", ArgType::Handle  },
                { "BaseAddress",   ArgType::Pointer },
                { "ZeroBits",      ArgType::Integer },
                { "RegionSize",    ArgType::Pointer },
                { "AllocationType",ArgType::Flags   },
                { "Protect",       ArgType::Flags   }
            },
            {
                { MEM_COMMIT,       "MEM_COMMIT" },
                { MEM_RESERVE,      "MEM_RESERVE" },
                { PAGE_READWRITE,   "PAGE_READWRITE" },
                { PAGE_EXECUTE_READWRITE, "PAGE_EXECUTE_READWRITE" }
            }
        }},
        { "NtFreeVirtualMemory", {
            "NtFreeVirtualMemory",
            {
                { "ProcessHandle", ArgType::Handle  },
                { "BaseAddress",   ArgType::Pointer },
                { "RegionSize",    ArgType::Pointer },
                { "FreeType",      ArgType::Flags   }
            },
            {
                { MEM_RELEASE,   "MEM_RELEASE" },
                { MEM_DECOMMIT,  "MEM_DECOMMIT" }
            }
        }},
        { "NtProtectVirtualMemory", {
            "NtProtectVirtualMemory",
            {
                { "ProcessHandle", ArgType::Handle  },
                { "BaseAddress",   ArgType::Pointer },
                { "RegionSize",    ArgType::Pointer },
                { "NewProtect",    ArgType::Flags   },
                { "OldProtect",    ArgType::Pointer }
            },
            {
                { PAGE_READONLY,       "PAGE_READONLY" },
                { PAGE_READWRITE,      "PAGE_READWRITE" },
                { PAGE_EXECUTE_READ,   "PAGE_EXECUTE_READ" },
                { PAGE_EXECUTE_READWRITE, "PAGE_EXECUTE_READWRITE" }
            }
        }},
        { "NtReadVirtualMemory", {
            "NtReadVirtualMemory",
            {
                { "ProcessHandle", ArgType::Handle  },
                { "BaseAddress",   ArgType::Pointer },
                { "Buffer",        ArgType::Pointer },
                { "BufferSize",    ArgType::Integer },
                { "ReturnSize",    ArgType::Pointer }
            },
            {}
        }},
        { "NtWriteVirtualMemory", {
            "NtWriteVirtualMemory",
            {
                { "ProcessHandle", ArgType::Handle  },
                { "BaseAddress",   ArgType::Pointer },
                { "Buffer",        ArgType::Pointer },
                { "BufferSize",    ArgType::Integer },
                { "ReturnSize",    ArgType::Pointer }
            },
            {}
        }},
        { "NtCreateThreadEx", {
            "NtCreateThreadEx",
            {
                { "ThreadHandle",        ArgType::Handle  },
                { "DesiredAccess",       ArgType::Flags   },
                { "ObjectAttributes",    ArgType::Pointer },
                { "ProcessHandle",       ArgType::Handle  },
                { "StartRoutine",        ArgType::Pointer },
                { "Argument",            ArgType::Pointer },
                { "CreateFlags",         ArgType::Flags   },
                { "ZeroBits",            ArgType::Pointer },
                { "StackSize",           ArgType::Pointer },
                { "MaximumStackSize",    ArgType::Pointer },
                { "AttributeList",       ArgType::Pointer }
            },
            {
                { THREAD_ALL_ACCESS,      "THREAD_ALL_ACCESS" },
            }
        }},
        { "NtWaitForSingleObject", {
            "NtWaitForSingleObject",
            {
                { "Handle",    ArgType::Handle },
                { "Alertable", ArgType::Integer },
                { "Timeout",   ArgType::Pointer }
            },
            {
                { 0,           "WaitZero" },
                { 0xFFFFFFFF,  "INFINITE" }
            }
        }},
        { "NtClose", {
            "NtClose",
            {
                { "Handle", ArgType::Handle }
            },
            {}
        }},
        { "NtDuplicateObject", {
            "NtDuplicateObject",
            {
                { "SourceProcessHandle", ArgType::Handle },
                { "SourceHandle",        ArgType::Handle },
                { "TargetProcessHandle", ArgType::Handle },
                { "TargetHandle",        ArgType::Pointer },
                { "DesiredAccess",       ArgType::Flags  },
                { "HandleAttributes",    ArgType::Flags  },
                { "Options",             ArgType::Flags  }
            },
            {
                { DUPLICATE_SAME_ACCESS, "DUPLICATE_SAME_ACCESS" }
            }
        }},
        { "NtResumeThread", {
            "NtResumeThread",
            {
                { "ThreadHandle",       ArgType::Handle },
                { "PreviousCount",      ArgType::Pointer }
            },
            {}
        }},
        { "NtSuspendThread", {
            "NtSuspendThread",
            {
                { "ThreadHandle",       ArgType::Handle },
                { "PreviousCount",      ArgType::Pointer }
            },
            {}
        }}
    };

    static const char* classify_memory(ULONG_PTR ptr) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(ptr), &mbi, sizeof(mbi)))
            return "bad";

        if (mbi.State != MEM_COMMIT)
            return "not committed";

        DWORD prot = mbi.Protect;

        switch (prot) {
        case PAGE_NOACCESS:            return "NOACCESS";
        case PAGE_READONLY:            return "R";
        case PAGE_READWRITE:           return "RW";
        case PAGE_WRITECOPY:           return "WC";
        case PAGE_EXECUTE:             return "X";
        case PAGE_EXECUTE_READ:        return "RX";
        case PAGE_EXECUTE_READWRITE:   return "RWX";
        case PAGE_EXECUTE_WRITECOPY:   return "WCX";
        case PAGE_GUARD:               return "GUARD";
        case PAGE_NOCACHE:             return "NOCACHE";
        case PAGE_WRITECOMBINE:        return "WRITECOMBINE";
        }

        if (prot & PAGE_GUARD) return "GUARD";
        if (prot & PAGE_NOACCESS) return "NOACCESS";
        if (prot & PAGE_EXECUTE_READWRITE) return "RWX";
        if (prot & PAGE_EXECUTE_READ) return "RX";
        if (prot & PAGE_EXECUTE) return "X";
        if (prot & PAGE_READWRITE) return "RW";
        if (prot & PAGE_READONLY) return "R";

        return "other";
    }

    static const char* ntstatus_to_str(NTSTATUS code) {
        switch (code) {
        case 0x00000000: return "STATUS_SUCCESS";
        case 0x00000103: return "STATUS_PENDING";
        case 0x00000104: return "STATUS_REPARSE";
        case 0x80000001: return "STATUS_GUARD_PAGE_VIOLATION";
        case 0x80000002: return "STATUS_DATATYPE_MISALIGNMENT";
        case 0x80000003: return "STATUS_BREAKPOINT";
        case 0x80000004: return "STATUS_SINGLE_STEP";
        case 0x8000000A: return "STATUS_BUFFER_OVERFLOW";
        case 0x80000005: return "STATUS_ACCESS_VIOLATION";
        case 0xC0000001: return "STATUS_UNSUCCESSFUL";
        case 0xC0000002: return "STATUS_NOT_IMPLEMENTED";
        case 0xC0000005: return "STATUS_ACCESS_VIOLATION";
        case 0xC0000008: return "STATUS_INVALID_HANDLE";
        case 0xC000000D: return "STATUS_INVALID_PARAMETER";
        case 0xC0000017: return "STATUS_NO_MEMORY";
        case 0xC0000018: return "STATUS_CONFLICTING_ADDRESSES";
        case 0xC000001D: return "STATUS_ILLEGAL_INSTRUCTION";
        case 0xC0000022: return "STATUS_ACCESS_DENIED";
        case 0xC0000023: return "STATUS_BUFFER_TOO_SMALL";
        case 0xC0000025: return "STATUS_NONCONTINUABLE_EXCEPTION";
        case 0xC0000026: return "STATUS_INVALID_DISPOSITION";
        case 0xC0000027: return "STATUS_UNWIND";
        case 0xC0000028: return "STATUS_BAD_STACK";
        case 0xC0000029: return "STATUS_INVALID_UNWIND_TARGET";
        case 0xC000002A: return "STATUS_NOT_LOCKED";
        case 0xC000002B: return "STATUS_PARITY_ERROR";
        case 0xC0000030: return "STATUS_PORT_DISCONNECTED";
        case 0xC0000034: return "STATUS_OBJECT_NAME_NOT_FOUND";
        case 0xC0000035: return "STATUS_OBJECT_NAME_COLLISION";
        case 0xC000003A: return "STATUS_OBJECT_PATH_NOT_FOUND";
        case 0xC000003B: return "STATUS_DATABUS_ERROR";
        case 0xC0000043: return "STATUS_SHARING_VIOLATION";
        case 0xC0000044: return "STATUS_QUOTA_EXCEEDED";
        case 0xC0000054: return "STATUS_FILE_LOCK_CONFLICT";
        case 0xC000007B: return "STATUS_INVALID_IMAGE_FORMAT";
        case 0xC00000BB: return "STATUS_NOT_SUPPORTED";
        case 0xC0000135: return "STATUS_DLL_NOT_FOUND";
        case 0xC0000139: return "STATUS_ENTRYPOINT_NOT_FOUND";
        case 0xC0000142: return "STATUS_DLL_INIT_FAILED";
        case 0xC0000185: return "STATUS_IO_DEVICE_ERROR";
        case 0xC0000205: return "STATUS_INSTRUCTION_MISALIGNMENT";
        case 0xC000021A: return "STATUS_SYSTEM_PROCESS_TERMINATED";
        case 0xC0000225: return "STATUS_NOT_FOUND";
        case 0xC0000263: return "STATUS_DRIVER_FAILED_LOAD";
        case 0xC0000264: return "STATUS_OBJECT_PATH_SYNTAX_BAD";
        case 0xC000027B: return "STATUS_CONNECTION_REFUSED";
        case 0xC000027D: return "STATUS_CONNECTION_ABORTED";
        case 0xC0000280: return "STATUS_TIMEOUT";
        case 0xC0000061: return "STATUS_INVALID_PAGE_PROTECTION";
        case 0xC00000A0: return "STATUS_SECTION_NOT_EXTENDED";
        case 0xC00000A1: return "STATUS_NOT_MAPPED_VIEW";
        case 0xC00000A2: return "STATUS_UNABLE_TO_FREE_VM";
        case 0xC00000A3: return "STATUS_UNABLE_TO_DELETE_SECTION";

        default:
            return nullptr;
        }
    }

    inline void Start(const char* syscallName, size_t arg_count, const ULONG_PTR* args) {
        static std::map<std::string, int> call_count;
        call_count[syscallName]++;

        printf("\n[[ ActiveBreach Syscall Tracer ]]\n");
        printf("  Name        : %s\n", syscallName);
        printf("  Call Count  : %d\n", call_count[syscallName]);
        printf("  Arg Count   : %zu\n", arg_count);

        const SyscallMeta* meta = nullptr;
        auto it = syscall_db.find(syscallName);
        if (it != syscall_db.end())
            meta = &it->second;

        if (!args) {
            printf("  [!] Args pointer is NULL — invalid syscall context.\n");
            return;
        }

        for (size_t i = 0; i < arg_count && i < 16; ++i) {
            ULONG_PTR val = args[i];
            const char* arg_name = (meta && i < meta->args.size()) ? meta->args[i].name : "";
            ArgType type = (meta && i < meta->args.size()) ? meta->args[i].type : ArgType::Integer;

            printf("    [%2zu] %-16s 0x%016llX", i, arg_name, (unsigned long long)val);

            bool printed = false;

            // Symbolic value (if matched)
            if (meta && meta->knownValues.count(val)) {
                printf("  (int: %llu = %s)", (unsigned long long)val, meta->knownValues.at(val));
                printed = true;
            }

            // Null or sentinel
            if (val == 0 || val == (ULONG_PTR)-1) {
                printf("  (null/invalid)");
                printed = true;
            }
            else if (val == 0xCCCCCCCCCCCCCCCCULL || val == 0xDDDDDDDDDDDDDDDDULL) {
                printf("  (MSVC uninitialized/freed)");
                printed = true;
            }
            else if ((val & 0xFFFFFFFF00000000ULL) == 0) {
                if (!printed) printf("  (int: %llu)", (unsigned long long)val);
                printed = true;
            }
            else if (val <= 0xFFFF) {
                printf("  (possible HANDLE)");
                printed = true;
            }

            // Pointer classification
            if (type == ArgType::Pointer || val > 0x10000) {
                MEMORY_BASIC_INFORMATION mbi = {};
                if (VirtualQuery((LPCVOID)val, &mbi, sizeof(mbi))) {
                    const char* prot = classify_memory(val);
                    printf("  (ptr: %s)", prot);
                    if ((mbi.Protect & PAGE_EXECUTE) && (mbi.Protect & PAGE_READWRITE))
                        printf("  [!] W+X region");
                    if (mbi.RegionSize > 0x1000000)
                        printf("  [!] Suspicious size > 16MB");
                }
                else {
                    printf("  (ptr: bad)");
                }
            }

            if (i >= 4 && (val & 0xF) != 0)
                printf("  [!] Stack arg unaligned");

            printf("\n");
        }

        if (arg_count > 0) {
            const char* regs[] = { "RCX", "RDX", "R8", "R9" };
            printf("\n  Register Mapping:\n");
            for (size_t i = 0; i < arg_count && i < 4; ++i)
                printf("    -> %-3s = 0x%016llX\n", regs[i], (unsigned long long)args[i]);

            if (arg_count > 4) {
                printf("    -> Remaining args passed via shadow stack\n");
                printf("  Shadow Stack Args:\n");

                void* shadow_base = _AddressOfReturnAddress();
                for (size_t i = 4; i < arg_count && i < 16; ++i) {
                    ULONG_PTR* shadow = ((ULONG_PTR*)shadow_base) + (i - 4);
                    printf("    [%2zu] @%p => 0x%016llX\n", i, shadow, *shadow);
                }
            }
        }

        static const ULONG_PTR canary = 0xFEE1DEADFEE1DEADULL;
        for (size_t i = 0; i < arg_count; ++i) {
            if (args[i] == canary) {
                printf("  [!] Canary value detected in syscall args! Possible stack overwrite.\n");
                __debugbreak();
            }
        }

        printf("  Stack Ptr   : %p\n", _AddressOfReturnAddress());
        printf("  Return Addr : %p\n", _ReturnAddress());
    }

    inline void Return(const char* syscallName, NTSTATUS status) {
        const char* label = ntstatus_to_str(status);
        printf("[[ActiveBreach Debugger]] Return NTSTATUS: 0x%08X", status);
        if (label) printf(" [%s]", label);
        printf("\n\n");
    }
}
#endif

namespace ActiveBreach {

    /**
     * @namespace Types
     * @brief Defines core types and structures used by ActiveBreach syscall dispatcher.
     *
     * - `_ABStubFn` is the standard calling convention for 16-arg syscall stub functions.
     * - `_SyscallState` can be expanded to track syscall timing or telemetry.
     */
    namespace Types {
        typedef ULONG_PTR(NTAPI* _ABStubFn)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

        struct _SyscallState {
            uint64_t start_time;
        };
    }

    /**
     * @namespace Crypto
     * @brief Contains low-level crypto utilities used in stub decryption and hashing.
     *
     * - `_decrypt_stub`: Decrypts a 16-byte syscall stub using AES-style XOR, with AVX2 acceleration if available.
     * - `has_avx2`: Detects CPU support for AVX2.
     * - `hash`: Computes a fast, entropy-mixed hash over function names to avoid string-based lookups.
     * - `decstr`: Reverses and decodes obfuscated strings using a multi-key bitshift and XOR transformation.
     */
    namespace Crypto {
        __forceinline bool has_avx2() {
            static const bool result = []() -> bool {
                int info[4];
                __cpuid(info, 0);
                if (info[0] >= 7) {
                    __cpuidex(info, 7, 0);
                    return (info[1] & (1 << 5)) != 0;
                }
                return false;
                }();
            return result;
        }

        __forceinline void _decrypt_stub(uint8_t* out, const uint8_t* enc, const uint8_t* key) {
            if (has_avx2()) {
                __m128i v_enc = _mm_loadu_si128((__m128i*)enc);
                __m128i v_key = _mm_loadu_si128((__m128i*)key);
                __m128i v_out = _mm_xor_si128(v_enc, v_key);
                _mm_storeu_si128((__m128i*)out, v_out);
            }

            else {
                for (int i = 0; i < 16; ++i)
                    out[i] = enc[i] ^ key[i];
            }
        }

        __declspec(noinline) uint64_t hash(const char* str) {
            const size_t len = strlen(str);
            uint64_t     seed = 0xDEADC0DECAFEBEEF;
            if (has_avx2() && len >= 32) {
                __m256i acc = _mm256_set1_epi64x(seed);
                for (size_t i = 0; i + 32 <= len; i += 32) {
                    __m256i chunk = _mm256_loadu_si256((__m256i*)(str + i));
                    acc = _mm256_xor_si256(acc, chunk);
                    acc = _mm256_add_epi64(acc, _mm256_shuffle_epi8(chunk, _mm256_set1_epi8(0x1B)));
                    acc = _mm256_or_si256(acc, _mm256_slli_epi64(acc, 5));
                    acc = _mm256_sub_epi64(acc, _mm256_srli_epi64(acc, 3));
                }
                uint64_t h[4];
                _mm256_storeu_si256((__m256i*)h, acc);
                return h[0] ^ h[1] ^ h[2] ^ h[3] ^ seed;
            }
            else {
                __m128i acc = _mm_set1_epi64x(seed);
                for (size_t i = 0; i + 16 <= len; i += 16) {
                    __m128i chunk = _mm_loadu_si128((__m128i*)(str + i));
                    acc = _mm_xor_si128(acc, chunk);
                    acc = _mm_or_si128(acc, _mm_slli_epi64(acc, 3));
                    acc = _mm_add_epi64(acc, _mm_srli_epi64(acc, 2));
                    acc = _mm_shuffle_epi8(acc, _mm_set_epi8(
                        1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14
                    ));
                }
                uint64_t h[2];
                _mm_storeu_si128((__m128i*)h, acc);
                return h[0] ^ h[1] ^ seed;
            }
        }

        __declspec(noinline) void decstr(std::string& str) {
            uint8_t k1 = static_cast<uint8_t>(str.length() ^ 0xA5);
            uint8_t k2 = 0x5F;
            std::reverse(str.begin(), str.end());
            for (size_t i = 0; i < str.length(); ++i) {
                uint8_t ch = static_cast<uint8_t>(str[i]);
                ch ^= ((i * 17) & 0xFF);
                ch = (ch >> 3) | (ch << 5);
                ch = static_cast<uint8_t>((ch - (k2 ^ (i << 1))) ^ (k1 + i));
                str[i] = static_cast<char>(ch);
            }
        }
    }

    /**
     * @namespace Loader
	 * @brief Responsible for locating and mapping an obfuscated copy of `ntdll.dll` from disk avoiding LoadLibrary.
     *
     * - `Zero`: Frees and zeroes the temporary buffer once parsing is complete.
     * - `Buffer`: Locates an alternate system path from environment variables (obfuscated), builds a full path,
     *   and memory-maps the PE image of `ntdll.dll` into user memory for parsing.
     *
     * This loader avoids standard API calls and registry access, using obfuscated strings to resolve paths
     * like `System32`, `SysWOW64`, or `%SystemRoot%` via decrypted environment variables.
     */
    namespace Loader {
        void Zero(void* buffer, size_t size) {
            SecureZeroMemory(buffer, size);
            VirtualFree(buffer, 0, MEM_RELEASE);
        }

        void* Buffer(size_t* out_size) {
            if (!out_size) return nullptr;
            *out_size = 0;

            std::string enc_dll = "\xB1\xF6\x2F\xF2\xDD\xD3\x0B\xA0\x09";
            std::string enc_env = "\x51\xB1\x26\xB7\x24\x2D\xCB\xCA\x20\xDA";
            std::string enc_sys = "\xC9\xF8\xF4\x1D\xDB\x9B\xB0\xEA";

            Crypto::decstr(enc_dll);
            Crypto::decstr(enc_env);
            Crypto::decstr(enc_sys);

            wchar_t sysdir[MAX_PATH], path[MAX_PATH], wide_env[MAX_PATH];
            wchar_t wide_dll[MAX_PATH], wide_sys[MAX_PATH];
            size_t conv = 0;
            mbstowcs_s(&conv, wide_env, enc_env.c_str(), MAX_PATH);
            if (!GetEnvironmentVariableW(wide_env, sysdir, MAX_PATH)) return nullptr;
            mbstowcs_s(&conv, wide_dll, enc_dll.c_str(), MAX_PATH);
            mbstowcs_s(&conv, wide_sys, enc_sys.c_str(), MAX_PATH);
            if (swprintf(path, MAX_PATH, L"%s\\%s\\%s", sysdir, wide_sys, wide_dll) < 0)
                return nullptr;

            HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) return nullptr;
            DWORD size = GetFileSize(file, nullptr);
            if (size == INVALID_FILE_SIZE || size < sizeof(IMAGE_DOS_HEADER)) {
                CloseHandle(file);
                return nullptr;
            }
            uint8_t* raw = (uint8_t*)VirtualAlloc(nullptr, size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!raw) {
                CloseHandle(file);
                return nullptr;
            }
            DWORD read = 0;
            if (!ReadFile(file, raw, size, &read, nullptr) || read != size) {
                VirtualFree(raw, 0, MEM_RELEASE);
                CloseHandle(file);
                return nullptr;
            }
            CloseHandle(file);

            auto* dos = (IMAGE_DOS_HEADER*)raw;
            auto* nt = (IMAGE_NT_HEADERS*)(raw + dos->e_lfanew);
            SIZE_T full_size = nt->OptionalHeader.SizeOfImage;
            uint8_t* mapped = (uint8_t*)VirtualAlloc(nullptr, full_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!mapped) {
                VirtualFree(raw, 0, MEM_RELEASE);
                return nullptr;
            }

            memcpy(mapped, raw, nt->OptionalHeader.SizeOfHeaders);
            const auto* sec = IMAGE_FIRST_SECTION(nt);
            for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                if (!sec[i].SizeOfRawData) continue;
                if (sec[i].PointerToRawData + sec[i].SizeOfRawData > size ||
                    sec[i].VirtualAddress + sec[i].SizeOfRawData > full_size)
                    continue;
                memcpy(mapped + sec[i].VirtualAddress,
                    raw + sec[i].PointerToRawData,
                    sec[i].SizeOfRawData);
            }

            VirtualFree(raw, 0, MEM_RELEASE);
            *out_size = full_size;
            return mapped;
        }
    }

    /**
     * @namespace Parser
     * @brief Parses a mapped `ntdll.dll` image to extract syscall names and their SSNs.
     *
     * - `Exfil`: Scans the export table, finds all functions prefixed with `Zw`/`Nt`, and extracts the syscall number.
     *   Uses SIMD comparison to verify valid syscall export signatures.
     * - `ExtractSyscalls`: Top-level function that loads and parses the image, returning a name -> SSN map.
     *
     * Combined with `Crypto::hash`, this allows efficient stub lookup during runtime without relying on Windows exports.
     */
    namespace Parser {
        std::unordered_map<std::string, uint32_t> Exfil(void* mapped_base, size_t image_size) {
            static uint8_t ssn_pool[32 * 1024];
#if __cplusplus >= 202002L
            std::pmr::monotonic_buffer_resource arena(ssn_pool, sizeof(ssn_pool));
            std::pmr::unordered_map<std::string, uint32_t> tmp(&arena);
#else
            std::unordered_map<std::string, uint32_t> tmp;
#endif
            tmp.reserve(512);

            auto* base = (uint8_t*)mapped_base;
            auto* dos = (IMAGE_DOS_HEADER*)base;
            if (image_size < sizeof(IMAGE_DOS_HEADER) || dos->e_magic != IMAGE_DOS_SIGNATURE)
                throw std::runtime_error("DOS header corrupt");
            auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                throw std::runtime_error("NT sig corrupt");

            auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!dir.VirtualAddress || dir.VirtualAddress >= image_size)
                throw std::runtime_error("EXPORT dir corrupt");

            auto* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
            auto* names = (uint32_t*)(base + exp->AddressOfNames);
            auto* funcs = (uint32_t*)(base + exp->AddressOfFunctions);
            auto* ordinals = (uint16_t*)(base + exp->AddressOfNameOrdinals);

            std::string enc_0 = "\x4A", enc_1 = "\x79";
            Crypto::decstr(enc_0);
            Crypto::decstr(enc_1);
            char c0 = enc_0[0], c1 = enc_1[0];
            __m128i mask = _mm_setr_epi8(
                c0, c1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            );

            for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
                uint32_t rva = names[i];
                if (rva >= image_size) continue;
                auto* fn = (char*)(base + rva);

                __m128i prefix = _mm_loadu_si128((__m128i*)fn);
                __m128i match = _mm_cmpeq_epi8(prefix, mask);
                int result = _mm_movemask_epi8(match);
                if ((result & 0x03) != 0x03) continue;

                std::string name(fn);

                uint16_t ord = ordinals[i];
                if (ord >= exp->AddressOfFunctions) continue;
                uint32_t frva = funcs[ord];
                if (frva + 4 >= image_size) continue;

                uint32_t ssn = *(uint32_t*)(base + frva + 4);
                tmp.emplace(std::move(name), ssn);
            }

            return { tmp.begin(), tmp.end() };
        }

        std::unordered_map<std::string, uint32_t> ExtractSyscalls() {
            size_t size = 0;
            void* mapped = Loader::Buffer(&size);
            if (!mapped || !size) throw std::runtime_error("NT/Auth Failure");
            auto tbl = Exfil(mapped, size);
            Loader::Zero(mapped, size);
            return tbl;
        }
    }

    /**
     * @namespace Callback
     * @brief Post-syscall validation to detect excessive execution latency.
     *
     * - Measures elapsed cycles using `__rdtsc()` and the initial timestamp stored in `_SyscallState`.
     * - Raises a custom exception (`ACTIVEBREACH_SYSCALL_LONGSYSCALL`) if the syscall exceeds the time defined in header.
     *
     * This can indicate debugger breakpoints, execution delays from hooks, or instrumentation overhead.
     */
    namespace Callback {
        inline void Callback(const Types::_SyscallState& state) {
            uint64_t elapsed = __rdtsc() - state.start_time;
            if (elapsed > SYSCALL_TIME_THRESHOLD) {
                RaiseException(ACTIVEBREACH_SYSCALL_LONGSYSCALL, 0, 0, nullptr);
            }
        }
    }

    /**
     * @namespace Stubs
     * @brief Allocates, decrypts, and manages memory regions for syscall stubs.
     *
     * - `StubPool` holds a persistent pool of stubs indexed by function name hash.
     * - `InitializePool()` allocates memory, decrypts templates, injects SSNs, and stores lookup mappings.
     * - `CreateEphemeralStub()` builds a single stub on-the-fly with optional memory protection level.
     * - `g_pool` is the global persistent pool used for dispatching all registered syscalls.
     *
     * Each stub is 16 bytes and consists of a pre-decrypted template with a hardcoded SSN inserted at offset +4.
     */
    namespace Stubs {

        class StubPool {
        public:
            StubPool() = default;
            ~StubPool() { if (_mem) VirtualFree(_mem, 0, MEM_RELEASE); }

            void InitializePool(const std::unordered_map<std::string, uint32_t>& syscall_table) {
                constexpr size_t STUB_SIZE = 16;
                _size = syscall_table.size() * STUB_SIZE;
                _mem = static_cast<uint8_t*>(VirtualAlloc(nullptr, _size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
                if (!_mem) throw std::runtime_error("Stub pool allocation failed");

                _map.reserve(syscall_table.size());

                uint8_t* cursor = _mem;
                for (const auto& [name, ssn] : syscall_table) {
                    const uint64_t hash = Crypto::hash(name.c_str());
                    cursor = EmitStubToPool(cursor, ssn);
                    _map[hash] = cursor - STUB_SIZE;
                }

                DWORD old = 0;
                VirtualProtect(_mem, _size, PAGE_EXECUTE_READ, &old);
            }

            void* LookupStub(const char* name) const {
                const uint64_t hash = Crypto::hash(name);
                const auto it = _map.find(hash);
                return (it != _map.end()) ? it->second : nullptr;
            }

        private:
            static constexpr size_t STUB_SIZE = 16;

            uint8_t* EmitStubToPool(uint8_t* dst, uint32_t ssn) {
                Crypto::_decrypt_stub(dst, encrypted_stub, aes_key);
                *(uint32_t*)(dst + 4) = ssn;
                return dst + STUB_SIZE;
            }

            uint8_t* _mem = nullptr;
            size_t _size = 0;
            std::unordered_map<uint64_t, void*> _map;
        };

        inline void* CreateEphemeralStub(uint32_t ssn, DWORD prot = PAGE_EXECUTE_READ) {
            constexpr size_t STUB_SIZE = 16;
            uint8_t tmp[STUB_SIZE];
            Crypto::_decrypt_stub(tmp, encrypted_stub, aes_key);
            *(uint32_t*)(tmp + 4) = ssn;

            void* stub = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!stub) return nullptr;

            memcpy(stub, tmp, STUB_SIZE);

            DWORD old = 0;
            if (!VirtualProtect(stub, 0x1000, prot, &old)) {
                VirtualFree(stub, 0, MEM_RELEASE);
                return nullptr;
            }

            return stub;
        }

        static StubPool g_pool;

    }

    /**
     * @namespace Dispatch
     * @brief Implements asynchronous syscall execution using Windows Thread Pool infrastructure.
     *
     * - `CallRequest` is the structure passed to a worker thread; it contains the stub, arguments, return value, and sync handles.
     * - `TPWork()` executes the syscall via direct call, collects the return, calls anti-tamper, and signals completion.
     * - `ThreadProc()` is used to notify once the system is initialized — not critical outside early bootstrap.
     *
     * The caller does not invoke syscalls directly; they are proxied via this worker for stack cleanliness and security context separation.
     */
    namespace Dispatch {

        static HANDLE g_init_event = nullptr;

        struct CallRequest {
            void* stub;
            size_t arg_count;
            ULONG_PTR args[16];
            HANDLE complete;
            ULONG_PTR ret;
            Types::_SyscallState state;
        };

        VOID CALLBACK TPWork(PTP_CALLBACK_INSTANCE, PVOID ctx, PTP_WORK) {
            auto* req = static_cast<CallRequest*>(ctx);
            alignas(32) ULONG_PTR a[16] = {};
            for (size_t i = 0; i < req->arg_count; ++i) a[i] = req->args[i];

            AntiBreach::Evaluate();

            __try {
                req->ret = reinterpret_cast<Types::_ABStubFn>(req->stub)(
                    a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                    a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                req->ret = 0;
            }

            Callback::Callback(req->state);
            SetEvent(req->complete);
            delete req;
        }

        DWORD WINAPI ThreadProc(LPVOID) {
            if (g_init_event) SetEvent(g_init_event);
            return 0;
        }

    }

    /**
     * @brief Performs dynamic syscall dispatch by looking up a stub and executing it asynchronously.
     *
     * This function:
     * - Locates a syscall stub via hashed name in the global `Stubs::g_pool`.
     * - Builds a `Dispatch::CallRequest` structure containing args and execution metadata.
     * - Spawns a threadpool worker to execute the syscall cleanly off the caller's stack.
     * - Waits for completion and returns the result.
     *
     * If compiled with `AB_DEBUG` preprocessor, it logs syscall metadata and return status using the integrated debugger.
     *
     * @param name       The NT syscall name (e.g., "NtOpenProcess").
     * @param arg_count  Number of arguments to pass (max 16).
     * @param ...        Variadic list of arguments (castable to `ULONG_PTR`).
     *
     * @return           The syscall return value (cast to `ULONG_PTR`).
     */
    extern "C" ULONG_PTR ab_call_fn(const char* name, size_t arg_count, ...) {
        if (!name || arg_count > 16) return 0;

        void* stub = Stubs::g_pool.LookupStub(name);
        if (!stub) return 0;

        auto* req = new Dispatch::CallRequest{};
        req->stub = stub;
        req->arg_count = arg_count;
        req->complete = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        req->state.start_time = __rdtsc();

        va_list vl;
        va_start(vl, arg_count);
        for (size_t i = 0; i < arg_count; ++i)
            req->args[i] = va_arg(vl, ULONG_PTR);
        va_end(vl);

#ifdef AB_DEBUG
        ActiveBreachDebugger::Start(name, arg_count, req->args);
#endif

        auto work = CreateThreadpoolWork(Dispatch::TPWork, req, nullptr);
        if (!work) {
            CloseHandle(req->complete);
            delete req;
            return 0;
        }

        SubmitThreadpoolWork(work);

        DWORD w = WaitForSingleObject(req->complete, 5000);
        CloseHandle(req->complete);
        CloseThreadpoolWork(work);

#ifdef AB_DEBUG
        ActiveBreachDebugger::Return(name, static_cast<NTSTATUS>(req->ret & 0xFFFFFFFF));
#endif

        return (w == WAIT_OBJECT_0) ? req->ret : 0;
    }
}

extern "C" void ActiveBreach_launch() {
    using namespace ActiveBreach;

    try {
        auto table = Parser::ExtractSyscalls();
        Stubs::g_pool.InitializePool(table);

        Dispatch::g_init_event = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!Dispatch::g_init_event)
            throw std::runtime_error("init event failed");

        constexpr uint64_t h_cte = 0xbcc7c24bdcfe64d3;  // NtCreateThreadEx
        constexpr uint64_t h_sit = 0xee9ec0b2e2fe64f5;  // NtSetInformationThread

        uint32_t ssn_cte = 0, ssn_sit = 0;
        for (const auto& [name, ssn] : table) {
            const uint64_t hash = Crypto::hash(name.c_str());
            if (hash == h_cte) ssn_cte = ssn;
            else if (hash == h_sit) ssn_sit = ssn;
        }

        if (!ssn_cte || !ssn_sit)
            throw std::runtime_error("required services not found");

        void* stub_cte = Stubs::CreateEphemeralStub(ssn_cte);
        void* stub_sit = Stubs::CreateEphemeralStub(ssn_sit);

        if (!stub_cte) throw std::runtime_error("stub_cte allocation failed");

        AntiBreach::InitBounds();

        HANDLE hThread = nullptr;
        auto NtCreateThreadEx = reinterpret_cast<Types::_ABStubFn>(stub_cte);
        NTSTATUS status = NtCreateThreadEx(
            (ULONG_PTR)&hThread,
            (ULONG_PTR)THREAD_ALL_ACCESS,
            (ULONG_PTR)nullptr,
            (ULONG_PTR)(LONG_PTR)-1,
            (ULONG_PTR)Dispatch::ThreadProc,
            (ULONG_PTR)nullptr,
            (ULONG_PTR)0, (ULONG_PTR)0, (ULONG_PTR)0,
            (ULONG_PTR)0, (ULONG_PTR)nullptr,
            (ULONG_PTR)0, (ULONG_PTR)0, (ULONG_PTR)0,
            (ULONG_PTR)0, (ULONG_PTR)0
        );

        VirtualFree(stub_cte, 0, MEM_RELEASE);
        stub_cte = nullptr;

        if (status < 0 || !hThread)
            throw std::runtime_error("dispatcher thread creation failed");

        if (stub_sit) {
            using NtSIT_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
            auto NtSetInformationThread = reinterpret_cast<NtSIT_t>(stub_sit);
            NtSetInformationThread(hThread, 0x11, nullptr, 0);
            VirtualFree(stub_sit, 0, MEM_RELEASE);
        }

        WaitForSingleObject(Dispatch::g_init_event, INFINITE);

        CloseHandle(hThread);
        CloseHandle(Dispatch::g_init_event);
        Dispatch::g_init_event = nullptr;
    }
    catch (const std::exception& e) {
        std::cerr << "[ActiveBreach] launch failed: " << e.what() << std::endl;
        std::exit(1);
    }
}

extern "C" void* _ab_get_stub(const char* name) {
    using namespace ActiveBreach;
    return (name && *name) ? Stubs::g_pool.LookupStub(name) : nullptr;
}

extern "C" uint32_t ab_violation_count() {
    return AntiBreach::GetViolationCount();
}

extern "C" void* ab_create_ephemeral_stub(uint32_t ssn, DWORD prot) {
    return ActiveBreach::Stubs::CreateEphemeralStub(ssn, prot);
}