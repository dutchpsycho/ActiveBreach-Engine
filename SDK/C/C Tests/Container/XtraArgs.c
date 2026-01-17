#include "../Infra.h"

#include <windows.h>
#include <stdio.h>

// ===== manual typedefs since winternl.h leaves these out =====

typedef LONG KPRIORITY;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0
} THREADINFOCLASS;

typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

// ===== test wrapper for extended syscall =====

NTSTATUS test_extended_syscall() {
    THREAD_BASIC_INFORMATION info = { 0 };
    ULONG retLen = 0;
    HANDLE hThread = GetCurrentThread();

    NTSTATUS status = (NTSTATUS)ab_call_func(
        "NtQueryInformationThread", 5,
        hThread,  // ThreadHandle
        ThreadBasicInformation,  // ThreadInformationClass
        &info,  // ThreadInformation (structure to store info)
        sizeof(info),  // Length of the information buffer
        &retLen  // ReturnLength
    );

    if (status == STATUS_SUCCESS) {
        printf("[+] NtQueryInformationThread succeeded!\n");
        printf("    ExitStatus:      0x%lx\n", (ULONG)info.ExitStatus);
        printf("    TebBaseAddress:  %p\n", info.TebBaseAddress);
        printf("    UniqueProcess:   %p\n", info.ClientId.UniqueProcess);
        printf("    UniqueThread:    %p\n", info.ClientId.UniqueThread);
        return STATUS_SUCCESS;
    }
    else {
        printf("[-] NtQueryInformationThread failed: 0x%lx\n", status);
        return status;
    }
}