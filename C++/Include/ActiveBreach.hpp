/*
 * ==================================================================================
 *  Repository:   ActiveBreach-Engine
 *  Project:      ActiveBreach
 *  File:         ActiveBreach.hpp
 *  Author:       DutchPsycho
 *  Organization: TITAN Softwork Solutions
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

    typedef LONG AB_NTSTATUS;

#define AB_SUCCESS               ((AB_NTSTATUS)0x00000000L)
#define AB_INFO_LEN_MISMATCH     ((AB_NTSTATUS)0xC0000004L)

    constexpr DWORD ACTIVEBREACH_SYSCALL_RETURNMODIFIED = 0xE0001001;
    constexpr DWORD ACTIVEBREACH_SYSCALL_STACKPTRMODIFIED = 0xE0001002;
    constexpr DWORD ACTIVEBREACH_SYSCALL_LONGSYSCALL = 0xE0001003;

    constexpr DWORD ACTIVEBREACH_FLOWGUARD_IDENTITY_MISMATCH = 0xE0002001;
    constexpr DWORD ACTIVEBREACH_FLOWGUARD_REMOTE_EXECUTION = 0xE0002002;

    constexpr uint64_t ACTIVEBREACH_SYSCALL_TIME_THRESHOLD = 50000000ULL;

    //-----------------------------------------
    // Internal Types (Prefixed, Collision-Free)
    //-----------------------------------------

    typedef struct _AB_UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } AB_UNICODE_STRING, * PAB_UNICODE_STRING;

    typedef struct _AB_OBJECT_ATTRIBUTES {
        ULONG               Length;
        HANDLE              RootDirectory;
        PAB_UNICODE_STRING  ObjectName;
        ULONG               Attributes;
        PVOID               SecurityDescriptor;
        PVOID               SecurityQualityOfService;
    } AB_OBJECT_ATTRIBUTES, * PAB_OBJECT_ATTRIBUTES;

    typedef struct _AB_PS_ATTRIBUTE {
        ULONG_PTR Attribute;
        SIZE_T Size;
        union {
            ULONG_PTR Value;
            PVOID Ptr;
        };
        PSIZE_T ReturnLength;
    } AB_PS_ATTRIBUTE, * PAB_PS_ATTRIBUTE;

    typedef struct _AB_PS_ATTRIBUTE_LIST {
        SIZE_T            TotalLength;
        AB_PS_ATTRIBUTE   Attributes[1];
    } AB_PS_ATTRIBUTE_LIST, * PAB_PS_ATTRIBUTE_LIST;

    typedef struct _AB_CLIENT_ID {
        PVOID UniqueProcess;
        PVOID UniqueThread;
    } AB_CLIENT_ID, * PAB_CLIENT_ID;

    typedef struct _AB_PEB {
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
    } AB_PEB, * PAB_PEB;

    typedef struct _AB_TEB {
        NT_TIB        NtTib;
        PVOID         EnvironmentPointer;
        AB_CLIENT_ID  ClientId;
    } AB_TEB, * PAB_TEB;

    typedef struct _AB_SYSCALL_STATE {
        uint64_t start_time;
    } AB_SYSCALL_STATE;

    //-----------------------------------------
    // API
    //-----------------------------------------

    void ActiveBreach_launch();

    void* _AbGetStub(const char* name);
    void* _AbCreateEphemeralStub(uint32_t ssn, DWORD prot /* = PAGE_EXECUTE_READ */);
    uint32_t _AbViolationCount();

#ifdef __cplusplus
}
#endif

//-----------------------------------------
// Call Resolver (C++ Only)
//-----------------------------------------

#ifdef __cplusplus

inline void* ab_resolve(const char* name) {
    void* stub = _AbGetStub(name);
    if (!stub) {
        fprintf(stderr, "ab_resolve: stub for \"%s\" not found\n", name);
    }
    return stub;
}

template<typename Fn>
inline Fn ab_resolve_as(const char* name) {
    return reinterpret_cast<Fn>(ab_resolve(name));
}

#define ab_call(name, type) ab_resolve_as<type>(name)

#endif // __cplusplus

static constexpr uint8_t encrypted_stub[16] = {
    0x0D, 0xCA, 0x90, 0xF9, 0xEA, 0x8C, 0xAE, 0x40,
    0x4E, 0x44, 0x82, 0x41, 0x41, 0x41, 0x41, 0x41
};

static constexpr uint8_t aes_key[16] = {
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41
};

#endif