#include "../Infra.h"

#include <windows.h>
#include <cstdio>

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

NTSTATUS test_vmem() {
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 0x1000;
    ULONG allocationType = MEM_COMMIT | MEM_RESERVE;
    ULONG protect = PAGE_READWRITE;
    NTSTATUS status = 0;

    // call NtAllocateVirtualMemory through ab_call
    while (true) {
        status = ab_call(NtAllocateVirtualMemory_t, "NtAllocateVirtualMemory",
            GetCurrentProcess(), &baseAddress, 0, &regionSize, allocationType, protect);

        if (status == STATUS_SUCCESS) {
            std::printf("[+] NtAllocateVirtualMemory succeeded. Base address: %p, Region size: 0x%zx\n",
                baseAddress, regionSize);
            return STATUS_SUCCESS;
        }

        else if (status == STATUS_INFO_LENGTH_MISMATCH) {
            regionSize *= 2;
            continue;
        }

        else {
            std::fprintf(stderr, "[-] NtAllocateVirtualMemory failed with status: 0x%lx, retrying...\n", status);
            Sleep(100);
        }
    }
}