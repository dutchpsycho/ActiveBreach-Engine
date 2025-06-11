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

constexpr DWORD ACTIVEBREACH_FLOWGUARD_IDENTITY_MISMATCH = 0xE0002001;
constexpr DWORD ACTIVEBREACH_FLOWGUARD_REMOTE_EXECUTION = 0xE0002002;

constexpr uint64_t SYSCALL_TIME_THRESHOLD = 50000000ULL;

struct _SyscallState {
    uint64_t start_time;
};

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T Size;
    union {
        ULONG_PTR Value;
        PVOID Ptr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    ULONG CrossProcessFlags;
    ULONG NtGlobalFlag;
    PVOID KernelCallbackTable;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    PVOID ImageBaseAddress;
} PEB, * PPEB;

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _TEB {
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
} TEB, * PTEB;

/*
    * ActiveBreach_launch:
    * Launches the global ActiveBreach handler
    * Internally, it maps ntdll.dll & extracts ssns,builds syscall stubs, and sets up the ActiveBreach system
*/

void ActiveBreach_launch();
void* _ab_get_stub(const char* name);
void* ab_create_ephemeral_stub(uint32_t ssn, DWORD prot = PAGE_EXECUTE_READ);
uint32_t ab_violation_count();

#ifdef __cplusplus
}
#endif

/*
 * ab_call macro:
 * The caller supplies the NT func type and args
 * eg; NTSTATUS status = ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", 5, buffer, buffer_size, &return_length);
*/

static constexpr uint8_t encrypted_stub[16] = { 0x0D, 0xCA, 0x90, 0xF9, 0xEA, 0x8C, 0xAE, 0x40, 0x4E, 0x44, 0x82, 0x41, 0x41, 0x41, 0x41, 0x41 };
static constexpr uint8_t aes_key[16] = { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 };

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