#ifndef ACTIVEBREACH_H
#define ACTIVEBREACH_H

#ifdef _MSC_VER
#define strdup _strdup
#endif

#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NTSTATUS
    typedef long NTSTATUS;
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

    typedef struct SyscallEntry {
        char* name;
        uint32_t ssn;
    } SyscallEntry;

    typedef struct SyscallTable {
        SyscallEntry* entries;
        size_t count;
    } SyscallTable;

    void* MapNtdll(void);
    SyscallTable GetSyscallTable(void* mapped_base);
    void CleanupNtdll(void* mapped_base);

    typedef struct {
        char* name;
        void* stub;
    } StubEntry;

    typedef struct ActiveBreach {
        uint8_t* stub_mem;
        size_t stub_mem_size;
        StubEntry* stubs;
        size_t stub_count;
    } ActiveBreach;

    void ActiveBreach_Init(ActiveBreach* ab);
    int ActiveBreach_AllocStubs(ActiveBreach* ab, const SyscallTable* table);
    void* ActiveBreach_GetStub(ActiveBreach* ab, const char* name);
    void ActiveBreach_Free(ActiveBreach* ab);
    void ActiveBreach_launch(void);

    /* --- Global ActiveBreach instance --- */
    extern ActiveBreach g_ab;

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <type_traits>

template <typename Fn, typename... Args>
inline auto ab_call_cpp(const char* name, Args... args)
-> decltype(((Fn)nullptr)(args...))
{
    Fn stub = reinterpret_cast<Fn>(ActiveBreach_GetStub(&g_ab, name));
    if (stub)
        return stub(args...);
    else {
        fprintf(stderr, "Stub \"%s\" not found\n", name);
        return static_cast<decltype(stub(args...))>(0);
    }
}

#define ab_call(nt_type, name, ...) ab_call_cpp<nt_type>(name, __VA_ARGS__)
#else
#define ab_call(nt_type, name, result, ...) do {                              \
      nt_type _stub = (nt_type)ActiveBreach_GetStub(&g_ab, (name));           \
      if (_stub) {                                                            \
          result = _stub(__VA_ARGS__);                                        \
      } else {                                                                \
          fprintf(stderr, "Stub \"%s\" not found\n", (name));                 \
          result = 0;                                                         \
      }                                                                       \
  } while (0)
#endif

#endif // ACTIVEBREACH_H