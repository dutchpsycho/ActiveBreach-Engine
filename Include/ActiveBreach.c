/*
 * ==================================================================================
 *  Repository:   Syscall Proxy
 *  Project:      ActiveBreach
 *  File:         ActiveBreach.c
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

#include "ActiveBreach.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <intrin.h>

#ifdef _MSC_VER
#define NORETURN __declspec(noreturn)
#else
#define NORETURN __attribute__((noreturn))
#endif

ActiveBreach g_ab = { 0 };
HANDLE g_abInitializedEvent = NULL;

static NORETURN void fatal_err(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

void _Zero(void* buffer, size_t size) {
    SecureZeroMemory(buffer, size);
    VirtualFree(buffer, 0, MEM_RELEASE);
}

void* aballoc(size_t size) {
    void* ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!ptr) {
        fprintf(stderr, "aballoc failed (size: %zu, error: %lu)\n", size, GetLastError());
        ExitProcess(1);
    }
    return ptr;
}

void abfree(void* ptr) {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

void* _Buffer(size_t* out_size) {
    wchar_t system_dir[MAX_PATH];
    if (!GetSystemDirectoryW(system_dir, MAX_PATH))
        fatal_err("Failed to retrieve the system directory");

    wchar_t ntdll_path[MAX_PATH];
    if (swprintf(ntdll_path, MAX_PATH, L"%s\\ntdll.dll", system_dir) < 0)
        fatal_err("Failed to build ntdll.dll path");

    HANDLE file = CreateFileW(ntdll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        fatal_err("Failed to open ntdll.dll");

    DWORD file_size = GetFileSize(file, NULL);
    if (file_size == INVALID_FILE_SIZE)
        fatal_err("Failed to get ntdll.dll size");

    void* buffer = VirtualAlloc(NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer)
        fatal_err("Failed to allocate memory for ntdll.dll");

    DWORD bytes_read;
    if (!ReadFile(file, buffer, file_size, &bytes_read, NULL) || bytes_read != file_size)
        fatal_err("Failed to read ntdll.dll");

    CloseHandle(file);

    *out_size = file_size;
    return buffer;
}

void _Cleanup(void* mapped_base) {
    if (mapped_base)
        UnmapViewOfFile(mapped_base);
}

//------------------------------------------------------------------------------
// SSN Exfil
//------------------------------------------------------------------------------
SyscallTable _GetSyscallTable(void* mapped_base) {
    SyscallTable table = { 0 };

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)mapped_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        fatal_err("Invalid DOS header signature");

    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((uint8_t*)mapped_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
        fatal_err("Invalid NT header signature");

    IMAGE_DATA_DIRECTORY export_data = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_data.VirtualAddress == 0)
        fatal_err("No export directory found");

    IMAGE_EXPORT_DIRECTORY* export_dir = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)mapped_base + export_data.VirtualAddress);

    uint32_t* names = (uint32_t*)((uint8_t*)mapped_base + export_dir->AddressOfNames);
    uint32_t* functions = (uint32_t*)((uint8_t*)mapped_base + export_dir->AddressOfFunctions);
    uint16_t* ordinals = (uint16_t*)((uint8_t*)mapped_base + export_dir->AddressOfNameOrdinals);

    SyscallEntry* entries = (SyscallEntry*)calloc(export_dir->NumberOfNames, sizeof(SyscallEntry));
    if (!entries)
        fatal_err("Failed to allocate memory for syscall entries");

    size_t count = 0;
    for (uint32_t i = 0; i < export_dir->NumberOfNames; i++) {
        char* func_name = (char*)((uint8_t*)mapped_base + names[i]);

        if (strncmp(func_name, "Nt", 2) == 0) {
            uint32_t func_rva = functions[ordinals[i]];
            uint8_t* func_ptr = (uint8_t*)mapped_base + func_rva;

            if (func_ptr[0] == 0x4C && func_ptr[1] == 0x8B &&
                func_ptr[2] == 0xD1 && func_ptr[3] == 0xB8) 
            
            {

                uint32_t ssn = *(uint32_t*)(func_ptr + 4);
                entries[count].name = strdup(func_name);

                if (!entries[count].name)
                    fatal_err("Failed to duplicate function name");

                entries[count].ssn = ssn;

                count++;
            }
        }
    }

    if (count == 0) {
        free(entries);

        table.entries = NULL;
        table.count = 0;
    }

    else {
        SyscallEntry* resized_entries = (SyscallEntry*)realloc(entries, count * sizeof(SyscallEntry));

        if (!resized_entries) {
            free(entries);
            fatal_err("Failed to reallocate memory for syscall entries");
        }

        table.entries = resized_entries;
        table.count = count;
    }

    return table;
}

//------------------------------------------------------------------------------
// ABINTERNALS
//------------------------------------------------------------------------------

void _ActiveBreach_Init(ActiveBreach* ab) {
    if (!ab)
        fatal_err("ActiveBreach pointer is NULL");

    ab->stub_mem = NULL;
    ab->stub_mem_size = 0;
    ab->stubs = NULL;
    ab->stub_count = 0;
}

 /* TODO:
 * - Switch to a on-demand based creation model (no static stubs)
 * - Call syscall prologues in ntdll.dll with our args
 * Some enterprise EDR would check the callstack, syscall not originating from ntdll.dll would be flagged
 */
void CreateStub(void* target_address, uint32_t ssn) {
    /* Stub layout:
       0x4C, 0x8B, 0xD1, 0xB8, [4-byte ssn], 0x0F, 0x05, 0xC3, zero-pad to 16 bytes.
    */
    uint8_t* stub = (uint8_t*)target_address;
    stub[0] = 0x4C; // mov r10, rcx
    stub[1] = 0x8B;
    stub[2] = 0xD1;
    stub[3] = 0xB8; // mov eax, ssn
    *(uint32_t*)(stub + 4) = ssn;
    stub[8] = 0x0F; // syscall
    stub[9] = 0x05;
    stub[10] = 0xC3; // ret
}

// Allocate executable memory for stubs and populate them based on the syscall table
int _ActiveBreach_AllocStubs(ActiveBreach* ab, const SyscallTable* table) {
    if (!ab || !table)
        fatal_err("ActiveBreach or SyscallTable pointer is NULL");

    if (table->count == 0)
        return -1;

    ab->stub_mem_size = table->count * 16; // 16 bytes per stub
    ab->stub_mem = (uint8_t*)VirtualAlloc(NULL, ab->stub_mem_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ab->stub_mem)
        fatal_err("Failed to allocate executable memory for stubs");

    ab->stubs = (StubEntry*)calloc(table->count, sizeof(StubEntry));
    if (!ab->stubs) {
        VirtualFree(ab->stub_mem, 0, MEM_RELEASE);
        fatal_err("Failed to allocate memory for stub entries");
    }

    ab->stub_count = table->count;
    uint8_t* current_stub = ab->stub_mem;

    for (size_t i = 0; i < table->count; i++) {
        CreateStub(current_stub, table->entries[i].ssn);
        ab->stubs[i].name = strdup(table->entries[i].name);
        if (!ab->stubs[i].name)
            fatal_err("Failed to duplicate stub name");
        ab->stubs[i].stub = current_stub;
        current_stub += 16;
    }

    return 0;
}

void* _ActiveBreach_GetStub(ActiveBreach* ab, const char* name) {
    if (!ab || !ab->stubs)
        return NULL;

    for (size_t i = 0; i < ab->stub_count; i++) {
        if (strcmp(ab->stubs[i].name, name) == 0)
            return ab->stubs[i].stub;
    }

    return NULL;
}

void _ActiveBreach_Free(ActiveBreach* ab) {
    if (!ab)
        return;

    if (ab->stub_mem) {
        VirtualFree(ab->stub_mem, 0, MEM_RELEASE);
        ab->stub_mem = NULL;
    }

    if (ab->stubs) {
        for (size_t i = 0; i < ab->stub_count; i++) {
            if (ab->stubs[i].name)
                free(ab->stubs[i].name);
        }
        free(ab->stubs);
        ab->stubs = NULL;
    }

    ab->stub_count = 0;
    ab->stub_mem_size = 0;
}

void _ActiveBreach_Cleanup(void) {
    _ActiveBreach_Free(&g_ab);
}

//------------------------------------------------------------------------------
// Call Dispatcher
//------------------------------------------------------------------------------

// I assume that all stubs have signature: 
//    ULONG_PTR NTAPI Fn(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR)
// (i.e. up to 8 arguments). May adjust.
typedef ULONG_PTR(NTAPI* ABStubFn)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

typedef struct _ABCallRequest {
    void* stub;          // Func ptr to call
    size_t arg_count;    // Num of args (0..8)
    ULONG_PTR args[8];   // Args (unused slots are 0)
    ULONG_PTR ret;       // Ret value (to be filled in)
    HANDLE complete;     // Event to signal completion
} ABCallRequest;

static HANDLE g_abCallEvent = NULL; // Signaled when a new request is posted
static CRITICAL_SECTION g_abCallCS; // Protects g_abCallRequest
static ABCallRequest g_abCallRequest; // Shared request (one at a time)

// The worker thread enters this loop.
static DWORD WINAPI _ActiveBreach_Dispatcher(LPVOID lpParameter) {
    (void)lpParameter; // Unused

    if (!g_abCallEvent)
        fatal_err("Call event is not created");
    InitializeCriticalSection(&g_abCallCS);

    for (;;) {

        WaitForSingleObject(g_abCallEvent, INFINITE);

        EnterCriticalSection(&g_abCallCS);
        ABCallRequest req = g_abCallRequest;
        LeaveCriticalSection(&g_abCallCS);


        ABStubFn fn = (ABStubFn)req.stub;
        ULONG_PTR ret = 0;

        switch (req.arg_count) {
        case 0: ret = fn(0, 0, 0, 0, 0, 0, 0, 0); break;
        case 1: ret = fn(req.args[0], 0, 0, 0, 0, 0, 0, 0); break;
        case 2: ret = fn(req.args[0], req.args[1], 0, 0, 0, 0, 0, 0); break;
        case 3: ret = fn(req.args[0], req.args[1], req.args[2], 0, 0, 0, 0, 0); break;
        case 4: ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], 0, 0, 0, 0); break;
        case 5: ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], 0, 0, 0); break;
        case 6: ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], 0, 0); break;
        case 7: ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], 0); break;
        case 8: ret = fn(req.args[0], req.args[1], req.args[2], req.args[3],
            req.args[4], req.args[5], req.args[6], req.args[7]); break;

        default:
            fatal_err("Invalid argument count in call dispatcher");
        }

        EnterCriticalSection(&g_abCallCS);
        g_abCallRequest.ret = ret;
        LeaveCriticalSection(&g_abCallCS);

        SetEvent(req.complete);
    }

    // Never reached
    return 0;
}

void _ActiveBreach_Callback(const SyscallState* state) {
    uint64_t end_time = __rdtsc();
    uint64_t elapsed = end_time - state->start_time;

    void* current_stack_ptr = _AddressOfReturnAddress();
    void* current_ret_addr = _ReturnAddress();

    if (current_stack_ptr != state->stack_ptr) { RaiseException(ACTIVEBREACH_SYSCALL_STACKPTRMODIFIED, 0, 0, NULL); }
    if (current_ret_addr != state->ret_addr) { RaiseException(ACTIVEBREACH_SYSCALL_RETURNMODIFIED, 0, 0, NULL); }
    if (elapsed > SYSCALL_TIME_THRESHOLD) { RaiseException(ACTIVEBREACH_SYSCALL_LONGSYSCALL, 0, 0, NULL); }
}

ULONG_PTR _ActiveBreach_Call(void* stub, size_t arg_count, ...) {
    if (!stub)
        fatal_err("_ActiveBreach_Call: stub is NULL");

    if (arg_count > 8)
        fatal_err("_ActiveBreach_Call: Too many arguments (max 8)");

    SyscallState execState;
    execState.start_time = __rdtsc();
    execState.stack_ptr = _AddressOfReturnAddress();
    execState.ret_addr = _ReturnAddress();

    ABCallRequest req = { 0 };

    req.stub = stub;
    req.arg_count = arg_count;
    va_list vl;
    va_start(vl, arg_count);
    for (size_t i = 0; i < arg_count; i++) {
        req.args[i] = va_arg(vl, ULONG_PTR);
    }
    va_end(vl);

    req.complete = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!req.complete)
        fatal_err("Failed to create completion event");

    EnterCriticalSection(&g_abCallCS);
    g_abCallRequest = req;
    LeaveCriticalSection(&g_abCallCS);

    SetEvent(g_abCallEvent);
    WaitForSingleObject(req.complete, INFINITE);

    EnterCriticalSection(&g_abCallCS);
    ULONG_PTR ret = g_abCallRequest.ret;
    LeaveCriticalSection(&g_abCallCS);
    CloseHandle(req.complete);

    _ActiveBreach_Callback(&execState);

    return ret;
}

//------------------------------------------------------------------------------
// Worker Thread: Init & loop
//------------------------------------------------------------------------------
static DWORD WINAPI _ActiveBreach_ThreadProc(LPVOID lpParameter) {
    (void)lpParameter; // Unused

    size_t ntdll_size;
    void* ntdll_base = _Buffer(&ntdll_size);
    SyscallTable table = _GetSyscallTable(ntdll_base);
    _Zero(ntdll_base, ntdll_size);
    _ActiveBreach_Init(&g_ab);

    if (_ActiveBreach_AllocStubs(&g_ab, &table) != 0)
        fatal_err("Failed to allocate stubs");

    if (table.entries) {
        for (size_t i = 0; i < table.count; i++) {
            if (table.entries[i].name)
                free(table.entries[i].name);
        }
        free(table.entries);
    }
    atexit(_ActiveBreach_Cleanup);

    // Init done
    if (g_abInitializedEvent)
        SetEvent(g_abInitializedEvent);

    // Initialize the dispatcher globals
    g_abCallEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_abCallEvent)
        fatal_err("Failed to create dispatcher event");

    // Enter loop
    _ActiveBreach_Dispatcher(NULL);

    return 0;
}

void ActiveBreach_launch(void) {

    g_abInitializedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_abInitializedEvent)
        fatal_err("Failed to create initialization event");

    HANDLE hThread = CreateThread(
        NULL,
        0,
        _ActiveBreach_ThreadProc,
        NULL,
        0,
        NULL);
    if (!hThread)
        fatal_err("Failed to create ActiveBreach thread");

    WaitForSingleObject(g_abInitializedEvent, INFINITE);
    CloseHandle(g_abInitializedEvent);

    g_abInitializedEvent = NULL;

    CloseHandle(hThread);
}