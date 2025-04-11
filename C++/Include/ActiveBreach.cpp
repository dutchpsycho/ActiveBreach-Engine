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
#include <intrin.h>

#include <stdexcept>
#include <string>
#include <iostream>
#include <cstring>
#include <cstdarg>
#include <unordered_map>

#if __cplusplus >= 202002L
#include <memory_resource>
#endif

#include <immintrin.h>
#include <intrin.h>

using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    SIZE_T,
    SIZE_T,
    SIZE_T,
    PPS_ATTRIBUTE_LIST
    );

namespace {

    __forceinline bool _has_avx2() {
        int info[4];
        __cpuid(info, 0);
        if (info[0] >= 7) {
            __cpuidex(info, 7, 0);
            return (info[1] & (1 << 5)) != 0;
        }
        return false;
    }

    __declspec(noinline) uint64_t _ab_hash(const char* str) {
        const size_t len = strlen(str);
        uint64_t seed = 0xDEADC0DECAFEBEEF;

        if (_has_avx2() && len >= 32) {
            __m256i acc = _mm256_set1_epi64x(seed);
            for (size_t i = 0; i + 32 <= len; i += 32) {
                __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(str + i));
                acc = _mm256_xor_si256(acc, chunk);
                acc = _mm256_add_epi64(acc, _mm256_shuffle_epi8(chunk, _mm256_set1_epi8(0x1B)));
                acc = _mm256_or_si256(acc, _mm256_slli_epi64(acc, 5));
                acc = _mm256_sub_epi64(acc, _mm256_srli_epi64(acc, 3));
            }
            uint64_t h[4];
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(h), acc);
            return h[0] ^ h[1] ^ h[2] ^ h[3] ^ seed;
        }
        else {
            __m128i acc = _mm_set1_epi64x(seed);
            for (size_t i = 0; i + 16 <= len; i += 16) {
                __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(str + i));
                acc = _mm_xor_si128(acc, chunk);
                acc = _mm_or_si128(acc, _mm_slli_epi64(acc, 3));
                acc = _mm_add_epi64(acc, _mm_srli_epi64(acc, 2));
                acc = _mm_shuffle_epi8(acc, _mm_set_epi8(1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14));
            }
            uint64_t h[2];
            _mm_storeu_si128(reinterpret_cast<__m128i*>(h), acc);
            return h[0] ^ h[1] ^ seed;
        }
    }

    void _Zero(void* buffer, size_t size) {
        SecureZeroMemory(buffer, size);
        VirtualFree(buffer, 0, MEM_RELEASE);
    }

#define XOR_KEY 0x5A

    static const uint8_t enc_ntdll[] = { 0x0036, 0x0036, 0x003E, 0x0074, 0x0036, 0x0036, 0x003E, 0x002E, 0x0034 };

    void _decode(const uint8_t* input, wchar_t* output, size_t size, uint8_t key) { for (size_t i = 0; i < size; ++i) { output[i] = (wchar_t)(input[size - i - 1] ^ key); } output[size] = L'\0'; }

#if defined(_M_X64)

    void* _Buffer(size_t* out_size) {
        if (!out_size)
            return nullptr;

        *out_size = 0;

        typedef struct _UNICODE_STRING {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        } UNICODE_STRING, * PUNICODE_STRING;

        typedef struct _RTL_USER_PROCESS_PARAMETERS {
            BYTE Reserved1[0x80];
            PVOID Environment;
        } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

        typedef struct _PEB {
            BYTE Reserved1[0x20];
            PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        } PEB, * PPEB;

        PPEB peb = (PPEB)__readgsqword(0x60);
        if (!peb || !peb->ProcessParameters || !peb->ProcessParameters->Environment)
            return nullptr;

        wchar_t* env = (wchar_t*)peb->ProcessParameters->Environment;

        const wchar_t target[] = L"SystemRoot=";
        size_t target_len = ARRAYSIZE(target) - 1;

        wchar_t* sysroot = nullptr;
        while (*env) {
            if (wcsncmp(env, target, target_len) == 0) {
                sysroot = env + target_len;
                break;
            }
            env += wcslen(env) + 1;
        }

        if (!sysroot)
            return nullptr;

        wchar_t decoded[10];
        _decode(enc_ntdll, decoded, 9, XOR_KEY);

        wchar_t path[MAX_PATH];
        if (swprintf(path, MAX_PATH, L"%s\\System32\\%s", sysroot, decoded) < 0)
            return nullptr;

        HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return nullptr;

        DWORD file_size = GetFileSize(file, nullptr);
        if (file_size == INVALID_FILE_SIZE) {
            CloseHandle(file);
            return nullptr;
        }

        void* buffer = VirtualAlloc(nullptr, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            CloseHandle(file);
            return nullptr;
        }

        DWORD bytes_read;
        if (!ReadFile(file, buffer, file_size, &bytes_read, nullptr) || bytes_read != file_size) {
            CloseHandle(file);
            VirtualFree(buffer, 0, MEM_RELEASE);
            return nullptr;
        }

        CloseHandle(file);
        *out_size = file_size;
        return buffer;
    }

#endif // _M_X64


    std::unordered_map<std::string, uint32_t> _ExtractSSN(void* mapped_base) {
        static uint8_t ssn_pool[32 * 1024];
#if __cplusplus >= 202002L
        std::pmr::monotonic_buffer_resource arena(ssn_pool, sizeof(ssn_pool));
        std::pmr::unordered_map<std::string, uint32_t> tmp(&arena);
#else
        std::unordered_map<std::string, uint32_t> tmp;
#endif
        tmp.reserve(512);

        const auto* base = static_cast<uint8_t*>(mapped_base);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

        if (dos->e_magic != IMAGE_DOS_SIGNATURE) throw std::runtime_error("Invalid DOS header");

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);

        if (nt->Signature != IMAGE_NT_SIGNATURE) throw std::runtime_error("Invalid NT header");

        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (dir.VirtualAddress == 0) throw std::runtime_error("No export directory");

        const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
        const uint32_t* names = reinterpret_cast<const uint32_t*>(base + exp->AddressOfNames);
        const uint32_t* funcs = reinterpret_cast<const uint32_t*>(base + exp->AddressOfFunctions);
        const uint16_t* ordinals = reinterpret_cast<const uint16_t*>(base + exp->AddressOfNameOrdinals);

        for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
            const char* fn = reinterpret_cast<const char*>(base + names[i]);
            if (fn[0] == 'N' && fn[1] == 't') {
#if __cplusplus >= 202002L
                std::pmr::string name(fn, &arena);
#else
                std::string name(fn);
#endif
                const uint32_t rva = funcs[ordinals[i]];
                const uint32_t ssn = *reinterpret_cast<const uint32_t*>(base + rva + 4);
                tmp.emplace(std::move(name), ssn);
            }
        }

        return { tmp.begin(), tmp.end() };
    }


    //------------------------------------------------------------------------------
    // Internal class to build & manage stubs (_ActiveBreach_Internal)
    //------------------------------------------------------------------------------

    class _ActiveBreach_Internal {
    public:
        _ActiveBreach_Internal() : _stub_mem(nullptr), _stub_mem_size(0) {}

        ~_ActiveBreach_Internal() {
            if (_stub_mem) {
                VirtualFree(_stub_mem, 0, MEM_RELEASE);
            }
        }

        void _BuildStubs(const std::unordered_map<std::string, uint32_t>& syscall_table) {
            _stub_mem_size = syscall_table.size() * 16;
            _stub_mem = static_cast<uint8_t*>(VirtualAlloc(nullptr, _stub_mem_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

            if (!_stub_mem) {
                throw std::runtime_error("Failed to allocate executable memory for stubs");
            }

            uint8_t* current_stub = _stub_mem;
#if __cplusplus >= 201703L
            // Structured binding available in C++17/C++20
            for (const auto& [name, ssn] : syscall_table) {
                uint64_t hashed = _ab_hash(name.c_str());
                current_stub = _CreateStub(current_stub, ssn);
                _syscall_stubs[hashed] = current_stub - 16;
            }
#else
            // Fallback for C++14 without struct bindings
            for (auto it = syscall_table.begin(); it != syscall_table.end(); ++it) {
                uint64_t hashed = _ab_hash(it->first.c_str());
                current_stub = _CreateStub(current_stub, it->second);
                _syscall_stubs[hashed] = current_stub - 16;
            }
#endif
        }

        void* _GetStub(const char* name) const {
            uint64_t h = _ab_hash(name);
            auto it = _syscall_stubs.find(h);
            return (it != _syscall_stubs.end()) ? it->second : nullptr;
        }

    private:
        __forceinline uint8_t* _CreateStub(uint8_t* target, uint32_t ssn) {
            uint8_t stub[16] = {
                0x4C, 0x8B, 0xD1,             // mov r10, rcx
                0xB8, 0, 0, 0, 0,             // mov eax, <ssn>
                0x0F, 0x05,                   // syscall
                0xC3                          // ret
            };

            *reinterpret_cast<uint32_t*>(stub + 4) = ssn;
            memcpy(target, stub, sizeof(stub));
            return target + sizeof(stub);
        }

        uint8_t* _stub_mem;
        size_t _stub_mem_size;

        std::unordered_map<uint64_t, void*> _syscall_stubs;
    };

    static _ActiveBreach_Internal _g_ab_internal;


    //------------------------------------------------------------------------------
    // Dispatcher Globals & Structs
    //------------------------------------------------------------------------------

    // All stubs are assumed to have signature:
    // ULONG_PTR NTAPI Fn(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    //                     ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
    typedef ULONG_PTR(NTAPI* _ABStubFn)(
        ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
        ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
        ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
        ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

    struct _ABCallRequest {
        void* stub;          // Function pointer to call
        size_t arg_count;    // Number of arguments (0..16)
        ULONG_PTR args[16];  // Arguments (unused slots are 0)
        ULONG_PTR ret;       // Return value (set by the dispatcher)
        HANDLE complete;     // Event to signal completion
    };

    // Global dispatcher variables
    HANDLE _g_abCallEvent = nullptr;          // Signaled when a new request is posted
    CRITICAL_SECTION _g_abCallCS;             // Protects _g_abCallRequest
    _ABCallRequest _g_abCallRequest = {};     // Shared request (one at a time)
    HANDLE _g_abInitializedEvent = nullptr;   // Signaled when dispatcher thread is ready

#define DISPATCH_CALL(n, ...) case n: ret = fn(__VA_ARGS__); break;


    //------------------------------------------------------------------------------
    // Dispatcher Thread Function
    //------------------------------------------------------------------------------
    DWORD WINAPI _ActiveBreach_Dispatcher(LPVOID) {
        if (!_g_abCallEvent) {
            // if this fails at thread start, just bail cleanly
            return ERROR_INVALID_HANDLE;
        }

        for (;;) {
            if (WaitForSingleObject(_g_abCallEvent, INFINITE) != WAIT_OBJECT_0)
                continue; // event wait failed, skip and retry loop

            EnterCriticalSection(&_g_abCallCS);
            _ABCallRequest req = _g_abCallRequest;
            LeaveCriticalSection(&_g_abCallCS);

            _ABStubFn fn = reinterpret_cast<_ABStubFn>(req.stub);
            ULONG_PTR ret = 0;

            if (!fn || req.arg_count > 16) {
                // invalid call; fail-safe return, signal completion w/ zero
                EnterCriticalSection(&_g_abCallCS);
                _g_abCallRequest.ret = 0;
                LeaveCriticalSection(&_g_abCallCS);

                SetEvent(req.complete);
                continue;
            }

            alignas(32) ULONG_PTR padded[16];

            if (_has_avx2()) {
                __m256i zero = _mm256_setzero_si256();
                _mm256_store_si256((__m256i*) & padded[0], zero);
                _mm256_store_si256((__m256i*) & padded[4], zero);
                _mm256_store_si256((__m256i*) & padded[8], zero);
                _mm256_store_si256((__m256i*) & padded[12], zero);

                if (req.arg_count > 0) {
                    __m256i arg0 = _mm256_loadu_si256((__m256i*) & req.args[0]);
                    _mm256_store_si256((__m256i*) & padded[0], arg0);
                }
                if (req.arg_count > 4) {
                    __m256i arg1 = _mm256_loadu_si256((__m256i*) & req.args[4]);
                    _mm256_store_si256((__m256i*) & padded[4], arg1);
                }
                if (req.arg_count > 8) {
                    __m256i arg2 = _mm256_loadu_si256((__m256i*) & req.args[8]);
                    _mm256_store_si256((__m256i*) & padded[8], arg2);
                }
                if (req.arg_count > 12) {
                    __m256i arg3 = _mm256_loadu_si256((__m256i*) & req.args[12]);
                    _mm256_store_si256((__m256i*) & padded[12], arg3);
                }
            }
            else {
                for (size_t i = 0; i < 16; ++i)
                    padded[i] = 0;
                for (size_t i = 0; i < req.arg_count; ++i)
                    padded[i] = req.args[i];
            }

            __try {
                ret = fn(
                    padded[0], padded[1], padded[2], padded[3],
                    padded[4], padded[5], padded[6], padded[7],
                    padded[8], padded[9], padded[10], padded[11],
                    padded[12], padded[13], padded[14], padded[15]
                );
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ret = 0; // safe default on call failure
            }

            EnterCriticalSection(&_g_abCallCS);
            _g_abCallRequest.ret = ret;
            LeaveCriticalSection(&_g_abCallCS);

            SetEvent(req.complete);
        }

        return 0;
    }



    //------------------------------------------------------------------------------
    // Dispatcher Thread Initialization
    //------------------------------------------------------------------------------

    DWORD WINAPI _ActiveBreach_ThreadProc(LPVOID /*lpParameter*/) {
        InitializeCriticalSection(&_g_abCallCS);

        DWORD tid = __readgsdword(0x48); // TEB->ClientId.UniqueThread

        if (tid != __readgsdword(0x48)) {
            __fastfail(0xAB01); 
        }

        _g_abCallEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        if (!_g_abCallEvent) {
            std::cerr << "ActiveBreach_ThreadProc: failed to create dispatcher event" << std::endl;

            if (_g_abInitializedEvent)
                SetEvent(_g_abInitializedEvent);

            return ERROR_INVALID_HANDLE;
        }

        if (_g_abInitializedEvent)
            SetEvent(_g_abInitializedEvent);

        DWORD result = _ActiveBreach_Dispatcher(nullptr);

        return result;
    }


    //------------------------------------------------------------------------------
    // Callback Implementation
    //------------------------------------------------------------------------------

    void ActiveBreach_Callback(const _SyscallState& state) {
        uint64_t end_time = __rdtsc();
        uint64_t elapsed = end_time - state.start_time;

        void* current_stack_ptr = _AddressOfReturnAddress();
        void* current_ret_addr = _ReturnAddress();

        if (current_stack_ptr != state.stack_ptr) { RaiseException(ACTIVEBREACH_SYSCALL_STACKPTRMODIFIED, 0, 0, nullptr); }
        if (current_ret_addr != state.ret_addr) { RaiseException(ACTIVEBREACH_SYSCALL_RETURNMODIFIED, 0, 0, nullptr); }
        if (elapsed > SYSCALL_TIME_THRESHOLD) { RaiseException(ACTIVEBREACH_SYSCALL_LONGSYSCALL, 0, 0, nullptr); }
    }


    //------------------------------------------------------------------------------
    // Call Implementation
    //------------------------------------------------------------------------------

    extern "C" ULONG_PTR _ActiveBreach_Call(void* stub, size_t arg_count, ...) {
        if (!stub || arg_count > 8) {
            std::cerr << "_ActiveBreach_Call: invalid call (stub=null or arg_count > 8)" << std::endl;
            return 0;
        }

        _SyscallState execState;
        execState.start_time = __rdtsc();
        execState.stack_ptr = _AddressOfReturnAddress();
        execState.ret_addr = _ReturnAddress();

        _ABCallRequest req = {};
        req.stub = stub;
        req.arg_count = arg_count;

        va_list vl;
        va_start(vl, arg_count);
        for (size_t i = 0; i < arg_count; ++i)
            req.args[i] = va_arg(vl, ULONG_PTR);
        va_end(vl);

        req.complete = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!req.complete) {
            std::cerr << "_ActiveBreach_Call: failed to create completion event" << std::endl;
            return 0;
        }

        EnterCriticalSection(&_g_abCallCS);
        _g_abCallRequest = req;
        LeaveCriticalSection(&_g_abCallCS);

        if (_g_abCallEvent)
            SetEvent(_g_abCallEvent);
        else {
            std::cerr << "_ActiveBreach_Call: dispatcher event is missing" << std::endl;
            CloseHandle(req.complete);
            return 0;
        }

        DWORD wait_result = WaitForSingleObject(req.complete, 5000);
        CloseHandle(req.complete);

        if (wait_result != WAIT_OBJECT_0) {
            std::cerr << "_ActiveBreach_Call: dispatch wait failed (" << wait_result << ")" << std::endl;
            return 0;
        }

        EnterCriticalSection(&_g_abCallCS);
        ULONG_PTR ret = _g_abCallRequest.ret;
        LeaveCriticalSection(&_g_abCallCS);

        ActiveBreach_Callback(execState);
        return ret;
    }
}


//------------------------------------------------------------------------------
// Exports
//------------------------------------------------------------------------------

extern "C" void ActiveBreach_launch(const char* notify) {
    try {
        size_t ab_handle_size = 0;

        void* mapped_base = _Buffer(&ab_handle_size);
        auto syscall_table = _ExtractSSN(mapped_base);

        constexpr uint64_t hash_NtCreateThreadEx = 0xbcc7c24bdcfe64d3;

        uint32_t ssn = 0;
        for (const auto& [name, id] : syscall_table) {
            if (_ab_hash(name.c_str()) == hash_NtCreateThreadEx) {
                ssn = id;
                break;
            }
        }

        if (ssn == 0)
            throw std::runtime_error("SSN table corrupt");

        _Zero(mapped_base, ab_handle_size);
        _g_ab_internal._BuildStubs(syscall_table);

        _g_abInitializedEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!_g_abInitializedEvent)
            throw std::runtime_error("Failed to create initialization event");

        void* syscall_stub = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!syscall_stub)
            throw std::runtime_error("Failed to allocate syscall stub memory");

        uint8_t raw_stub[] = {
            0x4C, 0x8B, 0xD1,             // mov r10, rcx
            0xB8, 0, 0, 0, 0,             // mov eax, <ssn>
            0x0F, 0x05,                   // syscall
            0xC3                          // ret
        };

        memcpy(syscall_stub, raw_stub, sizeof(raw_stub));
        *reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(syscall_stub) + 4) = ssn;

        HANDLE hThread = nullptr;
        auto _sysNtCreateThreadEx = reinterpret_cast<NtCreateThreadEx_t>(syscall_stub);

        NTSTATUS status = _sysNtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            nullptr,
            (HANDLE)(LONG_PTR)-1,
            _ActiveBreach_ThreadProc,
            nullptr,
            0,
            0,
            0,
            0,
            nullptr
        );

        SecureZeroMemory(syscall_stub, sizeof(raw_stub));
        VirtualFree(syscall_stub, 0, MEM_RELEASE);

        if (status < 0 || !hThread)
            throw std::runtime_error(" syscall failed");

        WaitForSingleObject(_g_abInitializedEvent, INFINITE);
        CloseHandle(_g_abInitializedEvent);
        _g_abInitializedEvent = nullptr;
        CloseHandle(hThread);

        if (notify && strcmp(notify, "LMK") == 0)
            std::cout << "[AB] ACTIVEBREACH OPERATIONAL" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "ActiveBreach_launch err: " << e.what() << std::endl;
        exit(1);
    }
}

extern "C" void* _ab_get_stub(const char* name) {
    if (!name)
        return nullptr;
    return _g_ab_internal._GetStub(name);
}

extern "C" ULONG_PTR ab_call_fn(const char* name, size_t arg_count, ...) {
    if (!name || arg_count > 16) {
        std::cerr << "ab_call_fn: invalid input (null name or arg_count > 16)" << std::endl;
        return 0;
    }

    void* stub = _g_ab_internal._GetStub(name);
    if (!stub) {
        std::cerr << "ab_call_fn: stub not found for '" << name << "'" << std::endl;
        return 0;
    }

    _SyscallState execState;
    execState.start_time = __rdtsc();
    execState.stack_ptr = _AddressOfReturnAddress();
    execState.ret_addr = _ReturnAddress();

    _ABCallRequest req = {};
    req.stub = stub;
    req.arg_count = arg_count;

    va_list vl;
    va_start(vl, arg_count);
    for (size_t i = 0; i < arg_count; ++i)
        req.args[i] = va_arg(vl, ULONG_PTR);
    va_end(vl);

    req.complete = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!req.complete) {
        std::cerr << "ab_call_fn: failed to create completion event" << std::endl;
        return 0;
    }

    // sync request w/ dispatcher
    EnterCriticalSection(&_g_abCallCS);

    _g_abCallRequest = req;

    LeaveCriticalSection(&_g_abCallCS);

    if (_g_abCallEvent)
        SetEvent(_g_abCallEvent);
    else {
        std::cerr << "ab_call_fn: dispatcher event handle missing" << std::endl;
        CloseHandle(req.complete);
        return 0;
    }

    DWORD wait_result = WaitForSingleObject(req.complete, 5000); // 5s timeout to prevent hangs
    CloseHandle(req.complete);

    if (wait_result != WAIT_OBJECT_0) {
        std::cerr << "ab_call_fn: wait timeout or error (" << wait_result << ")" << std::endl;
        return 0;
    }

    EnterCriticalSection(&_g_abCallCS);
    ULONG_PTR ret = _g_abCallRequest.ret;
    LeaveCriticalSection(&_g_abCallCS);

    ActiveBreach_Callback(execState);
    return ret;
}

#pragma function(strlen) // haha...
extern "C" size_t __cdecl strlen(const char* str) {
    size_t len = 0;
    while (str[len] && len < 0x1000)
        len++;
    return len;
}

#pragma function(strcmp)
extern "C" int __cdecl strcmp(const char* s1, const char* s2) {
    while (*s1 && *s2) {
        if (*s1 != *s2) return (unsigned char)*s1 - (unsigned char)*s2;
        s1++; s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}