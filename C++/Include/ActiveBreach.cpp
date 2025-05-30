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
#include <iostream>
#include <cstring>
#include <unordered_map>

#if __cplusplus >= 202002L
  #include <memory_resource>
#endif

#include <immintrin.h>
#include <intrin.h>

using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST
);

#pragma function(strlen)
extern "C" /**
 * @brief Safe length check for null-terminated strings, bounds at 0x1000.
 * @param str  C-string
 * @return     length up to first null or 0x1000, whichever comes first
 */
size_t __cdecl strlen(const char* str) {
    size_t len = 0;
    while (str[len] && len < 0x1000)
        len++;
    return len;
}

#pragma function(strcmp)
extern "C" /**
 * @brief Lightweight strcmp implementation.
 * @param s1  first C-string
 * @param s2  second C-string
 * @return    <0 if s1<s2, 0 if equal, >0 if s1>s2
 */
int __cdecl strcmp(const char* s1, const char* s2) {
    while (*s1 && *s2) {
        if (*s1 != *s2) return (unsigned char)*s1 - (unsigned char)*s2;
        s1++; s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

/**
 * @brief XOR-decrypts a 16-byte stub using the given key.
 * @param out   destination buffer (16 bytes)
 * @param enc   encrypted stub
 * @param key   16-byte key
 */
__forceinline void _decrypt_stub(uint8_t* out, const uint8_t* enc, const uint8_t* key) {
    for (int i = 0; i < 16; ++i)
        out[i] = enc[i] ^ key[i];
}


namespace {

    /**
     * @brief Prototype for decrypted syscall stub functions taking up to 16 args.
     */
    typedef ULONG_PTR(NTAPI* _ABStubFn)(
        ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
        ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
        ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
        ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR
    );

    /**
     * @brief Per-call request context.
     */
    struct _ABCallRequest {
        void*            stub;          ///< pointer to the syscall stub to invoke
        size_t           arg_count;     ///< number of arguments passed
        ULONG_PTR        args[16];      ///< up to 16 raw arguments
        HANDLE           complete;      ///< event handle to signal completion
        ULONG_PTR        ret;           ///< return value
        _SyscallState    state;         ///< captured state for detection
    };

    HANDLE _g_abInitializedEvent = nullptr;  ///< set when dispatcher thread is ready

    /**
     * @brief CPU supports AVX2?
     */
    __forceinline bool _has_avx2() {
        int info[4];
        __cpuid(info, 0);
        if (info[0] >= 7) {
            __cpuidex(info, 7, 0);
            return (info[1] & (1 << 5)) != 0;
        }
        return false;
    }

    /**
     * @brief 64-bit hash of a null-terminated string, uses AVX2 or SSE fallback.
     * @param str  input C-string
     * @return     64-bit hash
     */
    __declspec(noinline) uint64_t _ab_hash(const char* str) {
        const size_t len  = strlen(str);
        uint64_t     seed = 0xDEADC0DECAFEBEEF;

        if (_has_avx2() && len >= 32) {
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
                    1,0,3,2,5,4,7,6,9,8,11,10,13,12,15,14
                ));
            }
            uint64_t h[2];
            _mm_storeu_si128((__m128i*)h, acc);
            return h[0] ^ h[1] ^ seed;
        }
    }

    /**
     * @brief Reverse-and-XOR decrypts a std::string in-place.
     * Used for runtime decoding of embedded data.
     */
    __declspec(noinline) void _decstr(std::string& str) {
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

    /**
     * @brief Zeroes and frees a memory region securely.
     * @param buffer  pointer to region
     * @param size    length in bytes
     */
    void _Zero(void* buffer, size_t size) {
        SecureZeroMemory(buffer, size);
        VirtualFree(buffer, 0, MEM_RELEASE);
    }

    /**
     * @brief Maps a fresh in-memory copy of ntdll.dll, returns pointer & size.
     *        Decrypts embedded “ntdll.dll” name and environment keys at runtime.
     *
     * @param out_size  receives the SizeOfImage of the mapped PE
     * @return          pointer to writable mapped image, or nullptr on error
     */
    void* _Buffer(size_t* out_size) {
        if (!out_size) return nullptr;
        *out_size = 0;

        // encrypted literals: "ntdll.dll", "SystemRoot", "System32"
        std::string enc_dll = "\xB1\xF6\x2F\xF2\xDD\xD3\x0B\xA0\x09";
        std::string enc_env = "\x51\xB1\x26\xB7\x24\x2D\xCB\xCA\x20\xDA";
        std::string enc_sys = "\xC9\xF8\xF4\x1D\xDB\x9B\xB0\xEA";

        _decstr(enc_dll);
        _decstr(enc_env);
        _decstr(enc_sys);

        // build full path %SystemRoot%\\System32\\ntdll.dll
        wchar_t sysdir[MAX_PATH], path[MAX_PATH], wide_env[MAX_PATH];
        wchar_t wide_dll[MAX_PATH], wide_sys[MAX_PATH];
        size_t conv=0;
        mbstowcs_s(&conv, wide_env, enc_env.c_str(), MAX_PATH);
        if (!GetEnvironmentVariableW(wide_env, sysdir, MAX_PATH)) return nullptr;
        mbstowcs_s(&conv, wide_dll, enc_dll.c_str(), MAX_PATH);
        mbstowcs_s(&conv, wide_sys, enc_sys.c_str(), MAX_PATH);
        if (swprintf(path, MAX_PATH, L"%s\\%s\\%s", sysdir, wide_sys, wide_dll) < 0)
            return nullptr;

        // open & read file into raw buffer
        HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return nullptr;
        DWORD size = GetFileSize(file, nullptr);
        if (size == INVALID_FILE_SIZE || size < sizeof(IMAGE_DOS_HEADER)) {
            CloseHandle(file);
            return nullptr;
        }
        uint8_t* raw = (uint8_t*)VirtualAlloc(nullptr, size,
                                              MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (!raw) {
            CloseHandle(file);
            return nullptr;
        }
        DWORD read=0;
        if (!ReadFile(file, raw, size, &read, nullptr) || read != size) {
            VirtualFree(raw, 0, MEM_RELEASE);
            CloseHandle(file);
            return nullptr;
        }
        CloseHandle(file);

        // parse DOS & NT headers
        const auto* dos = (IMAGE_DOS_HEADER*)raw;
        const auto* nt  = (IMAGE_NT_HEADERS*)(raw + dos->e_lfanew);

        // allocate & map full image
        SIZE_T full_size = nt->OptionalHeader.SizeOfImage;
        uint8_t* mapped = (uint8_t*)VirtualAlloc(nullptr, full_size,
                                                 MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (!mapped) {
            VirtualFree(raw, 0, MEM_RELEASE);
            return nullptr;
        }

        // copy headers
        memcpy(mapped, raw, nt->OptionalHeader.SizeOfHeaders);

        // copy each section
        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (!sec[i].SizeOfRawData) continue;
            if (sec[i].PointerToRawData  + sec[i].SizeOfRawData > size ||
                sec[i].VirtualAddress     + sec[i].SizeOfRawData > full_size)
                continue;
            memcpy(mapped + sec[i].VirtualAddress,
                   raw    + sec[i].PointerToRawData,
                   sec[i].SizeOfRawData);
        }

        VirtualFree(raw, 0, MEM_RELEASE);
        *out_size = full_size;
        return mapped;
    }

    /**
     * @brief Extracts valid “Nt*” SSNs from a mapped ntdll image.
     * @param mapped_base  pointer to PE in memory
     * @param image_size   total mapped image size
     * @return             map of function-name to SSN
     * @throws std::runtime_error on corrupt headers
     */
    std::unordered_map<std::string,uint32_t> _Exfil(void* mapped_base, size_t image_size) {
        static uint8_t ssn_pool[32*1024];

    #if __cplusplus >= 202002L
        std::pmr::monotonic_buffer_resource arena(ssn_pool,sizeof(ssn_pool));
        std::pmr::unordered_map<std::string,uint32_t> tmp(&arena);
    #else
        std::unordered_map<std::string,uint32_t> tmp;
    #endif
        tmp.reserve(512);

        const auto* base = (uint8_t*)mapped_base;
        const auto* dos  = (IMAGE_DOS_HEADER*)base;
        if (image_size < sizeof(IMAGE_DOS_HEADER) || dos->e_magic!=IMAGE_DOS_SIGNATURE)
            throw std::runtime_error("DOS header corrupt");
        const auto* nt = (IMAGE_NT_HEADERS*)(base+dos->e_lfanew);
        if (nt->Signature!=IMAGE_NT_SIGNATURE)
            throw std::runtime_error("NT sig corrupt");

        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!dir.VirtualAddress || dir.VirtualAddress>=image_size)
            throw std::runtime_error("EXPORT dir corrupt");

        auto* exp      = (IMAGE_EXPORT_DIRECTORY*)(base+dir.VirtualAddress);
        auto* names    = (uint32_t*)(base + exp->AddressOfNames);
        auto* funcs    = (uint32_t*)(base + exp->AddressOfFunctions);
        auto* ordinals = (uint16_t*)(base + exp->AddressOfNameOrdinals);

        // decode 'N','t'
        std::string enc_0="\x4A",enc_1="\x79";
        _decstr(enc_0); _decstr(enc_1);
        char c0=enc_0[0], c1=enc_1[0];

        for (uint32_t i=0; i<exp->NumberOfNames; ++i) {
            uint32_t rva = names[i];
            if (rva>=image_size) continue;
            auto* fn = (char*)(base+rva);
            if (fn[0]!=c0||fn[1]!=c1) continue;
            std::string name(fn);

            uint16_t ord = ordinals[i];
            if (ord>=exp->NumberOfFunctions) continue;
            uint32_t frva = funcs[ord];
            if (frva+4>=image_size) continue;

            // SSN is immediate at offset+4
            uint32_t ssn = *(uint32_t*)(base+frva+4);
            tmp.emplace(std::move(name), ssn);
        }
        return {tmp.begin(), tmp.end()};
    }

    /**
     * @brief High-level: map+extract+zero ntdll, return syscall table.
     */
    std::unordered_map<std::string,uint32_t> _ExtractSyscalls() {
        size_t size=0;
        void* mapped = _Buffer(&size);
        if (!mapped||!size) throw std::runtime_error("NT/Auth Failure");
        auto tbl = _Exfil(mapped,size);
        _Zero(mapped,size);
        return tbl;
    }

    /**
     * @brief Internal stub manager: builds & stores decrypted syscall stubs.
     */
    class _ActiveBreach_Internal {
    public:
        _ActiveBreach_Internal(): _stub_mem(nullptr),_stub_mem_size(0){}
        ~_ActiveBreach_Internal(){
            if (_stub_mem) VirtualFree(_stub_mem,0,MEM_RELEASE);
        }

        /**
         * @brief Allocates & writes all syscall stubs from SSN table.
         * @param syscall_table  name→SSN map
         */
        void _BuildStubs(const std::unordered_map<std::string,uint32_t>& syscall_table) {
            _stub_mem_size = syscall_table.size()*16;
            _stub_mem = (uint8_t*)VirtualAlloc(nullptr,_stub_mem_size,
                                               MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (!_stub_mem) throw std::runtime_error("Stub alloc fail");

            uint8_t* cur = _stub_mem;
    #if __cplusplus>=201703L
            for (auto const& [name,ssn]: syscall_table) {
                uint64_t h = _ab_hash(name.c_str());
                cur = _CreateStub(cur, ssn);
                _syscall_stubs[h] = cur-16;
            }
    #else
            for (auto it=syscall_table.begin(); it!=syscall_table.end(); ++it) {
                uint64_t h=_ab_hash(it->first.c_str());
                cur=_CreateStub(cur,it->second);
                _syscall_stubs[h]=cur-16;
            }
    #endif
            // make all pages RX
            DWORD old=0;
            if (!VirtualProtect(_stub_mem,_stub_mem_size,PAGE_EXECUTE_READ,&old))
                throw std::runtime_error("VirtualProtect failed");
        }

        /**
         * @brief Lookup a stub by hash of name.
         * @param name  syscall name
         * @return      pointer to 16-byte stub or nullptr
         */
        void* _GetStub(const char* name) const {
            uint64_t h = _ab_hash(name);
            auto it = _syscall_stubs.find(h);
            return it!=_syscall_stubs.end() ? it->second : nullptr;
        }

    private:
        /**
         * @brief Creates one 16-byte stub, writing SSN into decrypted template.
         * @param target  write pointer
         * @param ssn     syscall service number
         * @return        pointer +16
         */
        __forceinline uint8_t* _CreateStub(uint8_t* target, uint32_t ssn) {
            uint8_t tmp[16];
            _decrypt_stub(tmp, encrypted_stub, aes_key);
            *(uint32_t*)(tmp+4) = ssn;
            memcpy(target,tmp,16);
            return target+16;
        }

        uint8_t* _stub_mem;                      ///< allocated block for all stubs
        size_t   _stub_mem_size;                 
        std::unordered_map<uint64_t,void*> _syscall_stubs; ///< hash→stub pointer
    };

    static _ActiveBreach_Internal _g_ab_internal; ///< singleton instance

    /**
     * @brief Called after each syscall execution to detect timing or stack tampering.
     */
    void ActiveBreach_Callback(const _SyscallState& state) {
        uint64_t elapsed = __rdtsc() - state.start_time;
        if (elapsed > SYSCALL_TIME_THRESHOLD) {
            RaiseException(ACTIVEBREACH_SYSCALL_LONGSYSCALL,0,0,nullptr);
        }
    }

    /**
     * @brief Thread-pool work callback: actually invokes the stub and signals completion.
     */
    VOID CALLBACK _ActiveBreach_TPWork(
        PTP_CALLBACK_INSTANCE, PVOID Context, PTP_WORK
    ) {
        auto* req = (_ABCallRequest*)Context;
        alignas(32) ULONG_PTR args[16] = {};
        for (size_t i=0;i<req->arg_count;++i) args[i]=req->args[i];
        ULONG_PTR ret=0;
        __try {
            ret = ((_ABStubFn)req->stub)(
                args[0],args[1],args[2],args[3],
                args[4],args[5],args[6],args[7],
                args[8],args[9],args[10],args[11],
                args[12],args[13],args[14],args[15]
            );
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            ret=0;
        }
        req->ret = ret;
        ActiveBreach_Callback(req->state);
        SetEvent(req->complete);
        delete req;
    }

    /**
     * @brief Dispatcher thread simply signals readiness and exits.
     */
    DWORD WINAPI _ActiveBreach_ThreadProc(LPVOID) {
        if (_g_abInitializedEvent) SetEvent(_g_abInitializedEvent);
        return 0;
    }

} // anonymous namespace end


/**
 * @brief Entrypoint: extracts syscalls, builds stubs, spins a helper thread.
 * @param notify  if "LMK", prints success message to stdout
 */
extern "C" void ActiveBreach_launch(const char* notify) {
    try {
        // Extract syscall table and build persistent stubs
        auto tbl = _ExtractSyscalls();
        _g_ab_internal._BuildStubs(tbl);

        // init sync event
        _g_abInitializedEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!_g_abInitializedEvent)
            throw std::runtime_error("init event failed");

        // locate hashes
        constexpr uint64_t h_cte = 0xbcc7c24bdcfe64d3;  // NtCreateThreadEx
        constexpr uint64_t h_sit = 0xee9ec0b2e2fe64f5;  // NtSetInformationThread
        uint32_t ssn_cte = 0, ssn_sit = 0;

        for (const auto& kv : tbl) {
            uint64_t h = _ab_hash(kv.first.c_str());
            if (h == h_cte) ssn_cte = kv.second;
            else if (h == h_sit) ssn_sit = kv.second;
        }

        if (!ssn_cte || !ssn_sit)
            throw std::runtime_error("required services not found");

        // make stub helper (RX memory)
        auto make_stub = [&](uint32_t ssn) -> void* {
            uint8_t tmp[16];
            _decrypt_stub(tmp, encrypted_stub, aes_key);
            *(uint32_t*)(tmp + 4) = ssn;

            void* stub = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!stub) return nullptr;

            memcpy(stub, tmp, 16);

            DWORD old = 0;
            if (!VirtualProtect(stub, 0x1000, PAGE_EXECUTE_READ, &old)) {
                VirtualFree(stub, 0, MEM_RELEASE);
                return nullptr;
            }

            return stub;
            };

        // build both syscall stubs
        void* stub_cte = make_stub(ssn_cte);
        void* stub_sit = make_stub(ssn_sit);

        if (!stub_cte)
            throw std::runtime_error("stub_cte alloc failed");

        // create dispatcher thread
        auto NtCreateThreadEx = (NtCreateThreadEx_t)stub_cte;
        HANDLE hThread = nullptr;
        NTSTATUS st = NtCreateThreadEx(
            &hThread, THREAD_ALL_ACCESS, nullptr,
            (HANDLE)(LONG_PTR)-1, _ActiveBreach_ThreadProc,
            nullptr, 0, 0, 0, 0, nullptr
        );

        if (st < 0 || !hThread)
            throw std::runtime_error("CreateThread failed");

        // hide thread from debugger (only if stub_sit worked)
        if (stub_sit) {
            using NtSIT_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
            auto NtSetInformationThread = (NtSIT_t)stub_sit;
            constexpr ULONG HideFlag = 0x11;
            NtSetInformationThread(hThread, HideFlag, nullptr, 0);

            // no SecureZeroMemory — page may be RX/EX-only on Win Pro
            VirtualFree(stub_sit, 0, MEM_RELEASE);
            stub_sit = nullptr;
        }

        // wait for thread to signal ready
        WaitForSingleObject(_g_abInitializedEvent, INFINITE);

        if (stub_cte) {
            VirtualFree(stub_cte, 0, MEM_RELEASE); // no memset
            stub_cte = nullptr;
        }

        CloseHandle(_g_abInitializedEvent);
        _g_abInitializedEvent = nullptr;

        CloseHandle(hThread);
        hThread = nullptr;

        if (notify && strcmp(notify, "LMK") == 0)
            std::cout << "[AB] ACTIVEBREACH OPERATIONAL\n";
    }
    catch (const std::exception& e) {
        std::cerr << "ActiveBreach_launch err: " << e.what() << std::endl;
        exit(1);
    }
}


/**
 * @brief Public FFI: invokes a named syscall stub asynchronously, waits up to 5s.
 * @param name        null-terminated syscall name
 * @param arg_count   number of variadic args (≤16)
 * @param ...         up to 16 ULONG_PTR arguments
 * @return            return value of syscall or 0 on timeout/error
 */
extern "C" ULONG_PTR ab_call_fn(const char* name, size_t arg_count, ...) {
    if (!name || arg_count>16) return 0;
    void* stub = _g_ab_internal._GetStub(name);
    if (!stub) return 0;

    auto* req = new _ABCallRequest{};
    req->stub      = stub;
    req->arg_count = arg_count;
    req->complete  = CreateEvent(nullptr, TRUE, FALSE, nullptr);

    // capture timing/state
    req->state.start_time = __rdtsc();
    req->state.stack_ptr  = _AddressOfReturnAddress();
    req->state.ret_addr   = _ReturnAddress();

    // pack args
    va_list vl;
    va_start(vl, arg_count);
    for (size_t i=0;i<arg_count;++i)
        req->args[i]=va_arg(vl,ULONG_PTR);
    va_end(vl);

    // queue to threadpool
    auto work = CreateThreadpoolWork(_ActiveBreach_TPWork,req,nullptr);
    if (!work) { CloseHandle(req->complete); delete req; return 0; }
    SubmitThreadpoolWork(work);

    // wait up to 5s
    DWORD w = WaitForSingleObject(req->complete, 5000);
    CloseHandle(req->complete);
    CloseThreadpoolWork(work);

    return (w==WAIT_OBJECT_0)? req->ret : 0;
}

/**
 * @brief FFI helper: returns raw stub pointer for a named syscall.
 */
extern "C" void* _ab_get_stub(const char* name) {
    return name ? _g_ab_internal._GetStub(name) : nullptr;
}