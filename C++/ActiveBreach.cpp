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

#include "ActiveBreach.hpp"

#include <windows.h>
#include <intrin.h>

#include <stdexcept>
#include <unordered_map>
#include <string>
#include <iostream>
#include <cstring>
#include <cstdarg>


namespace {

    [[noreturn]] void _fatal_err(const char* msg) {
        std::cerr << msg << std::endl;
        exit(1);
    }

    void _Zero(void* buffer, size_t size) {
        SecureZeroMemory(buffer, size);
        VirtualFree(buffer, 0, MEM_RELEASE);
    }

    #define XOR_KEY 0x5A

    // ntdll.dll, if plaintext then EDR will pick up it
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
        wchar_t system_dir[MAX_PATH];
        if (!GetSystemDirectoryW(system_dir, MAX_PATH))
            _fatal_err("Failed to retrieve the system directory");

        wchar_t decoded[10];
        _decode(decoded, 9);

        wchar_t path[MAX_PATH];
        if (swprintf(path, MAX_PATH, L"%s\\%s", system_dir, decoded) < 0)
            _fatal_err("Failed to build path");

        HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            _fatal_err("Failed to open file");

        DWORD file_size = GetFileSize(file, nullptr);
        if (file_size == INVALID_FILE_SIZE)
            _fatal_err("Failed to get file size");

        void* buffer = VirtualAlloc(nullptr, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer)
            _fatal_err("Failed to allocate memory for file");

        DWORD bytes_read;
        if (!ReadFile(file, buffer, file_size, &bytes_read, nullptr) || bytes_read != file_size)
            _fatal_err("Failed to read file");

        CloseHandle(file);

        *out_size = file_size;
        return buffer;
    }

    std::unordered_map<std::string, uint32_t> _ExtractSSN(void* mapped_base) {
        std::unordered_map<std::string, uint32_t> syscall_table;

        auto* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(mapped_base);
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
            throw std::runtime_error("Invalid DOS header signature");

        auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(mapped_base) + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
            throw std::runtime_error("Invalid NT header signature");

        IMAGE_DATA_DIRECTORY export_data = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (export_data.VirtualAddress == 0)
            throw std::runtime_error("No export directory found");

        auto* export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(reinterpret_cast<uint8_t*>(mapped_base) + export_data.VirtualAddress);
        auto* names = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(mapped_base) + export_dir->AddressOfNames);
        auto* functions = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(mapped_base) + export_dir->AddressOfFunctions);
        auto* ordinals = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(mapped_base) + export_dir->AddressOfNameOrdinals);

        for (uint32_t i = 0; i < export_dir->NumberOfNames; ++i) {
            std::string func_name(reinterpret_cast<char*>(
                reinterpret_cast<uint8_t*>(mapped_base) + names[i]));

            if (func_name.rfind("Nt", 0) == 0) {
                uint32_t ssn = *reinterpret_cast<uint32_t*>(
                    reinterpret_cast<uint8_t*>(mapped_base) + functions[ordinals[i]] + 4);
                syscall_table[func_name] = ssn;
            }
        }

        return syscall_table;
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

#if __cplusplus >= 202002L
            for (const auto& [name, ssn] : syscall_table) {
                _CreateStub(current_stub, ssn);
                _syscall_stubs[name] = current_stub;
                current_stub += 16;
            }
#else
            for (const auto& entry : syscall_table) {
                const std::string& name = entry.first;
                uint32_t ssn = entry.second;

                _CreateStub(current_stub, ssn);
                _syscall_stubs[name] = current_stub;
                current_stub += 16;
            }
#endif
        }

        void* _GetStub(const std::string& name) const {
            auto it = _syscall_stubs.find(name);
            return (it != _syscall_stubs.end()) ? it->second : nullptr;
        }

    /* TODO:
    * - Switch to a on-demand based creation model (no static stubs)
    * - Call syscall prologues in ntdll.dll with our args
    *   Some enterprise EDR would check the callstack, syscall not originating from ntdll.dll would be flagged
     */  
    private:
        void _CreateStub(void* target_address, uint32_t ssn) {
            // Stub layout (16 bytes):
            // 0x4C, 0x8B, 0xD1, 0xB8, [4-byte ssn], 0x0F, 0x05, 0xC3, zero-pad.
            uint8_t stub[16] = { 0 };
            stub[0] = 0x4C;
            stub[1] = 0x8B;
            stub[2] = 0xD1;
            stub[3] = 0xB8;
            *reinterpret_cast<uint32_t*>(stub + 4) = ssn;
            stub[8] = 0x0F;
            stub[9] = 0x05;
            stub[10] = 0xC3;
            memcpy(target_address, stub, sizeof(stub));
        }

        uint8_t* _stub_mem;
        size_t _stub_mem_size;
        std::unordered_map<std::string, void*> _syscall_stubs;
    };

    _ActiveBreach_Internal _g_ab_internal;


    //------------------------------------------------------------------------------
    // Dispatcher Globals and Structures
    //------------------------------------------------------------------------------

    // All stubs are assumed to have signature:
    // ULONG_PTR NTAPI Fn(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    //                     ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
    typedef ULONG_PTR(NTAPI* _ABStubFn)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
        ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

    struct _ABCallRequest {
        void* stub;          // Function pointer to call
        size_t arg_count;    // Number of arguments (0..8)
        ULONG_PTR args[8];   // Arguments (unused slots are 0)
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

    DWORD WINAPI _ActiveBreach_Dispatcher(LPVOID /*lpParameter*/) {
        if (!_g_abCallEvent)
            _fatal_err("Dispatcher event not created");
        for (;;) {
            WaitForSingleObject(_g_abCallEvent, INFINITE);

            EnterCriticalSection(&_g_abCallCS);
            _ABCallRequest req = _g_abCallRequest;
            LeaveCriticalSection(&_g_abCallCS);

            _ABStubFn fn = reinterpret_cast<_ABStubFn>(req.stub);
            ULONG_PTR ret = 0;
            switch (req.arg_count) {
                DISPATCH_CALL(0, 0, 0, 0, 0, 0, 0, 0, 0)
                    DISPATCH_CALL(1, req.args[0], 0, 0, 0, 0, 0, 0, 0)
                    DISPATCH_CALL(2, req.args[0], req.args[1], 0, 0, 0, 0, 0, 0)
                    DISPATCH_CALL(3, req.args[0], req.args[1], req.args[2], 0, 0, 0, 0, 0)
                    DISPATCH_CALL(4, req.args[0], req.args[1], req.args[2], req.args[3], 0, 0, 0, 0)
                    DISPATCH_CALL(5, req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], 0, 0, 0)
                    DISPATCH_CALL(6, req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], 0, 0)
                    DISPATCH_CALL(7, req.args[0], req.args[1], req.args[2], req.args[3], req.args[4], req.args[5], req.args[6], 0)
                    DISPATCH_CALL(8, req.args[0], req.args[1], req.args[2], req.args[3],
                        req.args[4], req.args[5], req.args[6], req.args[7])
            default:
                _fatal_err("Invalid argument count in call dispatcher");
            }

            EnterCriticalSection(&_g_abCallCS);
            _g_abCallRequest.ret = ret;
            LeaveCriticalSection(&_g_abCallCS);

            SetEvent(req.complete);
        }

        return 0; // Never reached
    }

    //------------------------------------------------------------------------------
    // Dispatcher Thread Initialization
    //------------------------------------------------------------------------------

    DWORD WINAPI _ActiveBreach_ThreadProc(LPVOID /*lpParameter*/) {
        InitializeCriticalSection(&_g_abCallCS);
        _g_abCallEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        if (!_g_abCallEvent)
            _fatal_err("Failed to create dispatcher event");
        if (_g_abInitializedEvent)
            SetEvent(_g_abInitializedEvent);
        _ActiveBreach_Dispatcher(nullptr);
        return 0;
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
    // ActiveBreach call Implementation
    //------------------------------------------------------------------------------

    extern "C" ULONG_PTR _ActiveBreach_Call(void* stub, size_t arg_count, ...) {
        if (!stub)
            _fatal_err("_ActiveBreach_Call: stub is NULL");
        if (arg_count > 8)
            _fatal_err("_ActiveBreach_Call: Too many arguments (max 8)");

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
        if (!req.complete)
            _fatal_err("Failed to create completion event");

        EnterCriticalSection(&_g_abCallCS);
        _g_abCallRequest = req;
        LeaveCriticalSection(&_g_abCallCS);

        SetEvent(_g_abCallEvent);
        WaitForSingleObject(req.complete, INFINITE);

        EnterCriticalSection(&_g_abCallCS);
        ULONG_PTR ret = _g_abCallRequest.ret;
        LeaveCriticalSection(&_g_abCallCS);
        CloseHandle(req.complete);

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

        _Zero(mapped_base, ab_handle_size);

        _g_ab_internal._BuildStubs(syscall_table);

        _g_abInitializedEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!_g_abInitializedEvent)
            throw std::runtime_error("Failed to create initialization event");

        HANDLE hThread = CreateThread(nullptr, 0, _ActiveBreach_ThreadProc, nullptr, 0, nullptr);
        if (!hThread)
            throw std::runtime_error("Failed to create ActiveBreach dispatcher thread");

        WaitForSingleObject(_g_abInitializedEvent, INFINITE);
        CloseHandle(_g_abInitializedEvent);
        _g_abInitializedEvent = nullptr;
        CloseHandle(hThread);

        if (notify && std::strcmp(notify, "LMK") == 0)
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