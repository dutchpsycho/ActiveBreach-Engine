#ifndef FRAMEWORK_HPP
#define FRAMEWORK_HPP

#include <Windows.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#include <unordered_map>
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <cstring>
#include <cstdint>

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef LONG KPRIORITY;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0
} THREADINFOCLASS;

#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        void* Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}

#define ViewUnmap 2

class StubManager {
public:
    StubManager();
    ~StubManager();
    void AllocStubs(const std::unordered_map<std::string, uint32_t>& syscall_table);
    void* FetchStub(const std::string& syscall_name) const;

private:
    struct SyscallStub {
        std::string name;
        void* address;
    };

    uint8_t* stub_mem;
    size_t stub_mem_size;
    std::unordered_map<std::string, void*> syscall_stubs;

    void CreateStub(void* target_address, uint32_t ssn);
    void* AllocX(size_t size);
};

struct SyscallTableEntry {
    std::string name;
    uint32_t ssn;
};

class NtdllLoader {
public:
    static void* MapDLL();
    static std::unordered_map<std::string, uint32_t> ExtractSSN(void* mapped_base);
    static void Cleanup(void* mapped_base);
};

#endif