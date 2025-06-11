#include "../Include/ActiveBreach.hpp"

#include "Suite/page.h"

#include <Windows.h>
#include <iostream>

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG
    );

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID,
    PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID
    );

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    ULONG, PVOID, ULONG, PULONG
    );

int main() {
    ActiveBreach_launch();
    std::cout << "=== ActiveBreach Test Suite (C++) ===\n\n";

    TestSectionMapping();

    // -- test 1: NtAllocateVirtualMemory
    PVOID base = nullptr;
    SIZE_T regionSize = 0x1000;

    NTSTATUS status = ab_call(NtAllocateVirtualMemory_t, "NtAllocateVirtualMemory",
        GetCurrentProcess(), &base, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (status == STATUS_SUCCESS && base) {
        std::cout << "[OK] NtAllocateVirtualMemory: Allocated at " << base
            << " (" << std::hex << regionSize << " bytes)\n";

        // write shellcode
        unsigned char sc[] = { 0xC3 }; // ret
        memcpy(base, sc, sizeof(sc));

        // -- test 2: NtCreateThreadEx
        HANDLE thread = nullptr;
        NTSTATUS th_status = ab_call(NtCreateThreadEx_t, "NtCreateThreadEx",
            &thread,
            THREAD_ALL_ACCESS,
            nullptr,
            GetCurrentProcess(),
            base,
            nullptr,
            0,
            0,
            0,
            0,
            nullptr);

        if (th_status == STATUS_SUCCESS && thread) {
            std::cout << "[OK] NtCreateThreadEx: Thread created, handle: " << thread << "\n";
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread);
        }
        else {
            std::cerr << "[-] NtCreateThreadEx failed: 0x"
                << std::hex << th_status << "\n";
        }
    }
    else {
        std::cerr << "[-] NtAllocateVirtualMemory failed: 0x"
            << std::hex << status << "\n";
    }

    // -- test 3: NtQuerySystemInformation via ab_call_fn_cpp
    // -- test 3: NtQuerySystemInformation via ab_call_fn_cpp
    ULONG returnLength = 0;
    SIZE_T bufferSize = 0x1000;
    PVOID infoBuf = nullptr;
    NTSTATUS qsi_status;

    const ULONG infoClass = 5; // SystemProcessInformation

    do {
        if (infoBuf) VirtualFree(infoBuf, 0, MEM_RELEASE);

        infoBuf = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!infoBuf) {
            std::cerr << "[-] Failed to allocate buffer for NtQuerySystemInformation\n";
            return 1;
        }

        // sizeof...(args) == 4 is inferred automatically here
        qsi_status = ab_call_fn_cpp<NTSTATUS>("NtQuerySystemInformation",
            infoClass,
            infoBuf,
            (ULONG)bufferSize,
            &returnLength);

        if (qsi_status == STATUS_INFO_LENGTH_MISMATCH)
            bufferSize *= 2;

    } while (qsi_status == STATUS_INFO_LENGTH_MISMATCH);

    if (qsi_status == STATUS_SUCCESS) {
        std::cout << "[OK] NtQuerySystemInformation: ReturnLength = "
            << std::dec << returnLength << "\n";
    }
    else {
        std::cerr << "[-] NtQuerySystemInformation failed: 0x"
            << std::hex << qsi_status << "\n";
    }

    if (infoBuf) VirtualFree(infoBuf, 0, MEM_RELEASE);

    std::cout << "\n=== Test Complete ===\n";
    return 0;
}