#include "../../Include/ActiveBreach.hpp"
#include "page.h"

#include <Windows.h>
#include <iostream>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

void TestSectionMapping() {
    std::cout << "=== Section Mapping Test ===\n";

    const SIZE_T SectionSize = 0x2000;
    HANDLE hSection = nullptr;
    LARGE_INTEGER maxSize = {};
    maxSize.QuadPart = SectionSize;

    // Use ab_call_fn_cpp with correct arg count to avoid calling convention issues
    NTSTATUS st = ab_call_fn_cpp<NTSTATUS>("NtCreateSection", 6,
        &hSection,
        (ACCESS_MASK)SECTION_ALL_ACCESS,
        nullptr,
        &maxSize,
        (ULONG)PAGE_READWRITE,     // <- safer than PAGE_EXECUTE_READWRITE
        (ULONG)SEC_COMMIT,
        nullptr);

    if (!NT_SUCCESS(st)) {
        std::cerr << "[-] NtCreateSection failed: 0x" << std::hex << st << "\n";
        return;
    }

    std::cout << "[OK] Section created. Handle: " << std::hex << hSection << "\n";

    PVOID localBase = nullptr;
    SIZE_T viewSize = 0;
    st = ab_call_fn_cpp<NTSTATUS>("NtMapViewOfSection", 10,
        hSection,
        GetCurrentProcess(),
        &localBase,
        (ULONG_PTR)0,
        (SIZE_T)0,
        (PLARGE_INTEGER)nullptr,
        &viewSize,
        (DWORD)2,             // ViewUnmap
        (ULONG)0,
        (ULONG)PAGE_READWRITE);

    if (!NT_SUCCESS(st)) {
        std::cerr << "[-] NtMapViewOfSection failed: 0x" << std::hex << st << "\n";
        CloseHandle(hSection);
        return;
    }

    std::cout << "[OK] Section mapped at local address: " << localBase
        << " (size = " << std::hex << viewSize << ")\n";

    // Write test
    const char* msg = "AB Section Mapping Test";
    strcpy_s((char*)localBase, strlen(msg) + 1, msg);
    std::cout << "[*] Wrote to section: " << (char*)localBase << "\n";

    // Unmap view
    st = ab_call_fn_cpp<NTSTATUS>("NtUnmapViewOfSection", 2,
        GetCurrentProcess(),
        localBase);

    if (NT_SUCCESS(st)) {
        std::cout << "[OK] NtUnmapViewOfSection: unmapped successfully\n";
    }
    else {
        std::cerr << "[-] NtUnmapViewOfSection failed: 0x" << std::hex << st << "\n";
    }

    CloseHandle(hSection);
    std::cout << "[OK] Section handle closed\n";
}
