#include "../Infra.h"

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

NTSTATUS abthunk_query_sysinfo() {
    ULONG_PTR ret = ab_call_func("NtQuerySystemInformation", 4,
        SystemBasicInformation,
        NULL,
        0,
        (PULONG)NULL
    );

    NTSTATUS status = (NTSTATUS)ret;

    if (status == STATUS_INFO_LENGTH_MISMATCH)
        printf("[OK] NtQuerySystemInformation: Length mismatch as expected\n");
    else
        fprintf(stderr, "[-] NtQuerySystemInformation failed: 0x%I64x\n", (unsigned long long)status);

    return status;
}

NTSTATUS abthunk_alloc_mem() {
    PVOID baseAddress = NULL;
    SIZE_T regionSize = 0x1000;

    ULONG_PTR ret = ab_call_func("NtAllocateVirtualMemory", 6,
        GetCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if ((NTSTATUS)ret == STATUS_SUCCESS && baseAddress) {
        printf("[OK] NtAllocateVirtualMemory: Allocated at %p (0x%zx bytes)\n", baseAddress, regionSize);
        return STATUS_SUCCESS;
    }

    fprintf(stderr, "[-] NtAllocateVirtualMemory failed: 0x%I64x\n", (unsigned long long)ret);
    return (NTSTATUS)ret;
}

NTSTATUS abthunk_close_handle(HANDLE h) {
    ULONG_PTR ret = ab_call_func("NtClose", 1, h);

    if ((NTSTATUS)ret == STATUS_SUCCESS) {
        printf("[OK] NtClose: Handle %p closed successfully\n", h);
        return STATUS_SUCCESS;
    }

    fprintf(stderr, "[-] NtClose failed: 0x%I64x\n", (unsigned long long)ret);
    return (NTSTATUS)ret;
}