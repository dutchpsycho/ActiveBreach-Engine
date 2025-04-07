/*
 * ==================================================================================
 *  Repository:   Syscall Proxy
 *  Project:      ActiveBreach
 *  File:         ActiveBreach.hpp
 *  Author:       DutchPsycho
 *  Organization: TITAN Softwork Solutions
 *  Inspired by:  MDSEC Research
 *
 *  Description:
 *      ActiveBreach is a syscall abstraction layer that dynamically proxies syscalls
 *      by extracting system service numbers (SSNs) from ntdll.dll and constructing
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

#ifndef ACTIVEBREACH_HPP
#define ACTIVEBREACH_HPP

#ifdef __cplusplus
extern "C" {
#endif

#pragma warning(disable : 28251)

#include <Windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef LONG NTSTATUS;

constexpr DWORD ACTIVEBREACH_SYSCALL_RETURNMODIFIED = 0xE0001001;
constexpr DWORD ACTIVEBREACH_SYSCALL_STACKPTRMODIFIED = 0xE0001002;
constexpr DWORD ACTIVEBREACH_SYSCALL_LONGSYSCALL = 0xE0001003;

constexpr uint64_t SYSCALL_TIME_THRESHOLD = 50000000ULL;

struct _SyscallState {
    uint64_t start_time;
    void* stack_ptr;
    void* ret_addr;
};

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

/*
 * ActiveBreach_launch:
 * Launches the global ActiveBreach handler
 * Internally, it maps ntdll.dll & extracts ssns,builds syscall stubs, and sets up the ActiveBreach system
*/

    void ActiveBreach_launch(const char* notify = nullptr);
	void* _ab_get_stub(const char* name);

#ifdef __cplusplus
}
#endif

/*
 * ab_call macro:
 * The caller supplies the NT func type and args
 * eg; NTSTATUS status = ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", 5, buffer, buffer_size, &return_length);
*/

#define ab_call(nt_type, name, ...) \
    ([]() -> nt_type { \
        void* stub = _ab_get_stub(name); \
        if (!stub) { \
            fprintf(stderr, "Stub \"%s\" not found\n", name); \
            return (nt_type)0; \
        } \
        return reinterpret_cast<nt_type>(stub); \
    }())(__VA_ARGS__)

#endif

#ifdef __cplusplus
extern "C" ULONG_PTR ab_call_fn(const char* name, size_t arg_count, ...);

template<typename Ret = ULONG_PTR, typename... Args>
Ret ab_call_fn_cpp(const char* name, Args... args) {
    void* stub = _ab_get_stub(name);
    if (!stub) {
        fprintf(stderr, "ab_call_fn_cpp: stub for \"%s\" not found\n", name);
        return (Ret)0;
    }
    return (Ret)ab_call_fn(name, sizeof...(args), (ULONG_PTR)args...);
}
#endif