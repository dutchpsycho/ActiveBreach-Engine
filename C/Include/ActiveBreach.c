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

#include <immintrin.h>
#include <intrin.h>  

#ifdef _MSC_VER
#define NORETURN __declspec(noreturn)
#else
#define NORETURN __attribute__((noreturn))
#endif

volatile bool g_ab_initialized = false;
ActiveBreach g_ab = { 0 };
HANDLE g_abInitializedEvent = NULL;

static NORETURN void fatal_err(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static int has_avx2(void) {
    int info[4];
    __cpuid(info, 0);
    if (info[0] >= 7) {
        __cpuidex(info, 7, 0);
        return (info[1] & (1 << 5)) != 0;
    }
    return 0;
}

uint64_t ab_hash(const char* str) {
    size_t len = strlen(str);
    uint64_t seed = 0xDEADC0DECAFEBEEF;

    if (has_avx2() && len >= 32) {
        __m256i acc = _mm256_set1_epi64x(seed);
        for (size_t i = 0; i + 32 <= len; i += 32) {
            __m256i chunk = _mm256_loadu_si256((const __m256i*)(str + i));
            __m256i shuffled = _mm256_shuffle_epi8(chunk, _mm256_set1_epi8(0x1B));
            acc = _mm256_xor_si256(acc, chunk);
            acc = _mm256_add_epi64(acc, shuffled);
            acc = _mm256_or_si256(acc, _mm256_slli_epi64(acc, 5));
            acc = _mm256_sub_epi64(acc, _mm256_srli_epi64(acc, 3));
        }

        uint64_t h[4];
        _mm256_storeu_si256((__m256i*)h, acc);
        return h[0] ^ h[1] ^ h[2] ^ h[3] ^ seed;
    }

    uint64_t hash = seed;
    while (*str) {
        hash ^= (uint8_t)(*str++);
        hash = (hash << 5) | (hash >> (64 - 5));
        hash += 0x1337BEEF;
    }

    return hash;
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

#define XOR_KEY 0x5A

// ntdll.dll, if plaintext then edr will pick it up
static const wchar_t enc[] = {
    0x0036, 0x0036, 0x003E, 0x0074, 0x0036, 0x0036, 0x003E, 0x002E, 0x0034
};

void _decode(wchar_t* decoded, size_t size) {
    for (size_t i = 0; i < size; i++) {
        decoded[i] = enc[size - i - 1] ^ XOR_KEY;
    }
    decoded[size] = L'\0';
}

void* _Buffer(size_t* out_size) {
    wchar_t decoded[10];
    _decode(decoded, 9);

    wchar_t sysdir[MAX_PATH];
    if (!GetEnvironmentVariableW(L"SystemRoot", sysdir, MAX_PATH))
        fatal_err("Failed to get SystemRoot");

    wchar_t path[MAX_PATH];
    if (swprintf(path, MAX_PATH, L"%s\\System32\\%s", sysdir, decoded) < 0)
        fatal_err("Failed to construct ntdll path");

    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        fatal_err("Failed to open ntdll");

    DWORD size = GetFileSize(file, NULL);
    if (size == INVALID_FILE_SIZE)
        fatal_err("Invalid file size");

    uint8_t* raw = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!raw)
        fatal_err("Alloc failed");

    DWORD read;
    if (!ReadFile(file, raw, size, &read, NULL) || read != size)
        fatal_err("Failed to read");

    CloseHandle(file);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)raw;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(raw + dos->e_lfanew);

    SIZE_T full_size = nt->OptionalHeader.SizeOfImage;
    uint8_t* mapped = VirtualAlloc(NULL, full_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mapped)
        fatal_err("Map alloc failed");

    memcpy(mapped, raw, nt->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sec[i].SizeOfRawData == 0) continue;

        if (sec[i].PointerToRawData + sec[i].SizeOfRawData > size) continue;
        if (sec[i].VirtualAddress + sec[i].SizeOfRawData > full_size) continue;

        memcpy(
            mapped + sec[i].VirtualAddress,
            raw + sec[i].PointerToRawData,
            sec[i].SizeOfRawData
        );
    }

    VirtualFree(raw, 0, MEM_RELEASE);
    *out_size = full_size;
    return mapped;
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

/* Stub layout:
   0x4C, 0x8B, 0xD1, 0xB8, [4-byte ssn], 0x0F, 0x05, 0xC3, zero-pad to 16 bytes.
*/
void CreateStub(void* target_address, uint32_t ssn) {
    uint8_t* stub = (uint8_t*)target_address;
    stub[0] = 0x4C; // mov r10, rcx
    stub[1] = 0x8B;
    stub[2] = 0xD1;
    stub[3] = 0xB8; // mov eax, ssn
    *(uint32_t*)(stub + 4) = ssn;
    stub[8] = 0x0F; // syscall
    stub[9] = 0x05;
    stub[10] = 0xC3; // ret
    /* Remaining bytes are zeroed */
}

int _ActiveBreach_AllocStubs(ActiveBreach* ab, const SyscallTable* table) {
    if (!ab || !table)
        fatal_err("ActiveBreach or SyscallTable pointer is NULL");

    if (table->count == 0)
        return -1;

    ab->stub_mem_size = table->count * 16;
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

        uint64_t hash = ab_hash(table->entries[i].name);
        ab->stubs[i].hash = hash;
        ab->stubs[i].stub = current_stub;

        current_stub += 16;
    }

    return 0;
}

void* _ActiveBreach_GetStub(ActiveBreach* ab, const char* name) {
    if (!g_ab_initialized || !ab || !ab->stubs)
        return (void*)NoOpStub;

    uint64_t hash = ab_hash(name);

    for (size_t i = 0; i < ab->stub_count; i++) {
        if (ab->stubs[i].hash == hash)
            return ab->stubs[i].stub;
    }

    return (void*)NoOpStub;
}

void _ActiveBreach_Free(ActiveBreach* ab) {
    if (!ab)
        return;

    if (ab->stub_mem) {
        VirtualFree(ab->stub_mem, 0, MEM_RELEASE);
        ab->stub_mem = NULL;
    }

    if (ab->stubs) {
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
typedef struct _ABCallRequest {
    void* stub;          // Func ptr to call
    size_t arg_count;    // Num of args (0..16)
    ULONG_PTR args[16];  // Args (unused slots are 0)
    ULONG_PTR ret;       // Ret value (to be filled in)
    HANDLE complete;     // Event to signal completion
} ABCallRequest;

static HANDLE g_abCallEvent = NULL; // Signaled when a new request is posted
static CRITICAL_SECTION g_abCallCS; // Protects g_abCallRequest
static ABCallRequest g_abCallRequest; // Shared request (one at a time)

static void _ActiveBreach_Callback(const SyscallState* state) {
    uint64_t end_time = __rdtsc();
    uint64_t elapsed = end_time - state->start_time;

    void* current_stack_ptr = _AddressOfReturnAddress();
    void* current_ret_addr = _ReturnAddress();

    if (current_stack_ptr != state->stack_ptr) {
        RaiseException(ACTIVEBREACH_SYSCALL_STACKPTRMODIFIED, 0, 0, NULL);
    }
    if (current_ret_addr != state->ret_addr) {
        RaiseException(ACTIVEBREACH_SYSCALL_RETURNMODIFIED, 0, 0, NULL);
    }
    if (elapsed > SYSCALL_TIME_THRESHOLD) {
        RaiseException(ACTIVEBREACH_SYSCALL_LONGSYSCALL, 0, 0, NULL);
    }
}

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

        case 0:  ret = fn(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); break;
        case 1:  ret = fn(req.args[0], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); break;
        case 2:  ret = fn(req.args[0], req.args[1], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); break;
        case 3:  ret = fn(req.args[0], req.args[1], req.args[2], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); break;
        case 4:  ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); break;
        case 5:  ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); break;
        case 6:  ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0); break;
        case 7:  ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], 0, 0, 0, 0, 0, 0, 0, 0, 0); break;
        case 8:  ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7], 0, 0, 0, 0, 0, 0, 0, 0); break;
        case 9:  ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7], req.args[8], 0, 0, 0, 0, 0, 0, 0); break;
        case 10: ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7], req.args[8], req.args[9], 0, 0, 0, 0, 0, 0); break;
        case 11: ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7], req.args[8], req.args[9], req.args[10], 0, 0, 0, 0, 0); break;
        case 12: ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7], req.args[8], req.args[9], req.args[10], req.args[11], 0, 0, 0, 0); break;
        case 13: ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7], req.args[8], req.args[9], req.args[10], req.args[11], req.args[12], 0, 0, 0); break;
        case 14: ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7], req.args[8], req.args[9], req.args[10], req.args[11], req.args[12], req.args[13], 0, 0); break;
        case 15: ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7], req.args[8], req.args[9], req.args[10], req.args[11], req.args[12], req.args[13], req.args[14], 0); break;
        case 16: ret = fn(req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], req.args[7], req.args[8], req.args[9], req.args[10], req.args[11], req.args[12], req.args[13], req.args[14], req.args[15]); break;

        default:
            fatal_err("Invalid argument count in call dispatcher");
        }

        EnterCriticalSection(&g_abCallCS);
        g_abCallRequest.ret = ret;
        LeaveCriticalSection(&g_abCallCS);

        SetEvent(req.complete);
    }
    return 0;
}

ULONG_PTR _ActiveBreach_Call(void* stub, size_t arg_count, ...) {
    if (!stub)
        fatal_err("_ActiveBreach_Call: stub is NULL");

    if (arg_count > 16)
        fatal_err("_ActiveBreach_Call: Too many arguments (max 16)");

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

static DWORD WINAPI _ActiveBreach_ThreadProc(LPVOID lpParameter) {
    (void)lpParameter;

    size_t ab_handle_size;
    void* ab_handle_base = _Buffer(&ab_handle_size);
    SyscallTable table = _GetSyscallTable(ab_handle_base);
    _Zero(ab_handle_base, ab_handle_size);
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

    if (g_abInitializedEvent)
        SetEvent(g_abInitializedEvent);

    g_abCallEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_abCallEvent)
        fatal_err("Failed to create dispatcher event");

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

    g_ab_initialized = true;
    CloseHandle(hThread);
}

ULONG_PTR NTAPI NoOpStub(ULONG_PTR a, ULONG_PTR b, ULONG_PTR c, ULONG_PTR d,
    ULONG_PTR e, ULONG_PTR f, ULONG_PTR g, ULONG_PTR h,
    ULONG_PTR i, ULONG_PTR j, ULONG_PTR k, ULONG_PTR l,
    ULONG_PTR m, ULONG_PTR n, ULONG_PTR o, ULONG_PTR p) {
    fprintf(stderr, "Warning: Called an uninitialized or missing stub in ActiveBreach!\n");
    return 0;
}

ULONG_PTR ab_call_func(const char* name, size_t arg_count, ...) {
    if (!g_ab_initialized) {
        fprintf(stderr, "Error: ActiveBreach not initialized. Cannot call '%s'.\n", name);
        return (ULONG_PTR)NoOpStub;
    }

    void* stub = _ActiveBreach_GetStub(&g_ab, name);
    if (!stub || stub == (void*)NoOpStub)
        return (ULONG_PTR)NoOpStub;

    va_list vl;
    va_start(vl, arg_count);

    ABCallRequest req = { 0 };
    req.stub = stub;
    req.arg_count = arg_count;

    for (size_t i = 0; i < arg_count && i < 16; i++) {
        req.args[i] = va_arg(vl, ULONG_PTR);
    }

    va_end(vl);

    req.complete = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!req.complete)
        fatal_err("ab_call_func: Failed to create completion event");

    EnterCriticalSection(&g_abCallCS);
    g_abCallRequest = req;
    LeaveCriticalSection(&g_abCallCS);

    SetEvent(g_abCallEvent);
    WaitForSingleObject(req.complete, INFINITE);

    EnterCriticalSection(&g_abCallCS);
    ULONG_PTR ret = g_abCallRequest.ret;
    LeaveCriticalSection(&g_abCallCS);
    CloseHandle(req.complete);

    SyscallState state;
    state.start_time = __rdtsc();
    state.stack_ptr = _AddressOfReturnAddress();
    state.ret_addr = _ReturnAddress();
    _ActiveBreach_Callback(&state);

    return ret;
}