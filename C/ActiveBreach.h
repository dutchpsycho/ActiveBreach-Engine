#pragma warning(disable : 4311)
#pragma warning(disable : 4302)

#ifndef ACTIVEBREACH_H
#define ACTIVEBREACH_H

#include <stdbool.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef _MSC_VER
#define strdup _strdup
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NTSTATUS
    typedef long NTSTATUS;
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

#ifndef ACTIVEBREACH_ERROR_CODES
#define ACTIVEBREACH_ERROR_CODES
#define ACTIVEBREACH_SYSCALL_RETURNMODIFIED    0xE0001001
#define ACTIVEBREACH_SYSCALL_STACKPTRMODIFIED  0xE0001002
#define ACTIVEBREACH_SYSCALL_LONGSYSCALL       0xE0001003 
#endif

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SYSCALL_TIME_THRESHOLD      50000000ULL

    extern volatile bool g_ab_initialized;
    extern HANDLE g_abInitializedEvent;

    typedef struct {
        char* name;
        uint32_t ssn;
    } SyscallEntry;

    typedef struct {
        SyscallEntry* entries;
        size_t count;
    } SyscallTable;

    typedef struct _SyscallState {
        uint64_t start_time;
        void* stack_ptr;
        void* ret_addr;
    } SyscallState;

    typedef struct {
        uint64_t hash;
        void* stub;
    } StubEntry;

    typedef struct {
        uint8_t* stub_mem;
        size_t stub_mem_size;
        StubEntry* stubs;
        size_t stub_count;
    } ActiveBreach;

    extern ActiveBreach g_ab;

    // 🔐 Hash resolver (custom-modified FNV-1)
    uint64_t ab_hash(const char* str);

    void* _Buffer(size_t* out_size);
    SyscallTable _GetSyscallTable(void* mapped_base);
    void _Cleanup(void* mapped_base);

    void _ActiveBreach_Init(ActiveBreach* ab);
    int  _ActiveBreach_AllocStubs(ActiveBreach* ab, const SyscallTable* table);
    void* _ActiveBreach_GetStub(ActiveBreach* ab, const char* name);
    void _ActiveBreach_Free(ActiveBreach* ab);
    void _ActiveBreach_Cleanup(void);
    void ActiveBreach_launch(void);

    ULONG_PTR _ActiveBreach_Call(void* stub, size_t arg_count, ...);
    ULONG_PTR ab_call_func(const char* name, size_t arg_count, ...);

    ULONG_PTR NTAPI NoOpStub(ULONG_PTR a, ULONG_PTR b, ULONG_PTR c, ULONG_PTR d,
        ULONG_PTR e, ULONG_PTR f, ULONG_PTR g, ULONG_PTR h,
        ULONG_PTR i, ULONG_PTR j, ULONG_PTR k, ULONG_PTR l,
        ULONG_PTR m, ULONG_PTR n, ULONG_PTR o, ULONG_PTR p);

    /* --- Macro Helpers to count args --- */
#define PP_NARG(...)  PP_NARG_(__VA_ARGS__, PP_RSEQ_N())
#define PP_NARG_(...) PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N( _1, _2, _3, _4, _5, _6, _7, _8, \
                  _9,_10,_11,_12,_13,_14,_15,_16,N,...) N
#define PP_RSEQ_N()   16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
template <typename Fn, typename... Args>
inline auto ab_call_cpp(const char* name, Args... args)
-> decltype(((Fn)nullptr)(args...))
{
    if (!g_ab_initialized) {
        fprintf(stderr, "Error: ActiveBreach is not initialized. Cannot call stub '%s'.\n", name);
        return (decltype(((Fn)nullptr)(args...)))NoOpStub;
    }
    void* stub = _ActiveBreach_GetStub(&g_ab, name);
    return (decltype(((Fn)nullptr)(args...)))_ActiveBreach_Call(stub, sizeof...(args), (ULONG_PTR)args...);
}
#define ab_call(nt_type, name, ...) ab_call_cpp<nt_type>(name, __VA_ARGS__)
#else
#define ab_call(nt_type, name, result, ...) do {                             \
    if (!g_ab_initialized) {                                                 \
        fprintf(stderr, "Error: ActiveBreach is not initialized.\n");       \
        result = (nt_type)NoOpStub;                                          \
    } else {                                                                 \
        void* _stub = _ActiveBreach_GetStub(&g_ab, (name));                  \
        result = ((nt_type)_ActiveBreach_Call(_stub, PP_NARG(__VA_ARGS__),  \
                    (ULONG_PTR)__VA_ARGS__));                                \
    }                                                                        \
} while(0)
#endif

typedef ULONG_PTR(NTAPI* ABStubFn)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

#endif // ACTIVEBREACH_H