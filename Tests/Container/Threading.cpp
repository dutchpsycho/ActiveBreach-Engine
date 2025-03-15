#include "../Infra.h"

#include <windows.h>
#include <cstdio>

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

DWORD WINAPI DummyThread(LPVOID) {
    std::printf("[+] Thread executed successfully.\n");
    return 0;
}

NTSTATUS test_threads() {
    HANDLE threadHandle = nullptr;
    NTSTATUS status = 0;
    void* threadStart = (void*)DummyThread;

    status = ab_call(NtCreateThreadEx_t, "NtCreateThreadEx",
        &threadHandle, THREAD_ALL_ACCESS, nullptr, GetCurrentProcess(),
        threadStart, nullptr, 0, 0, 0, 0, nullptr);

    if (status == STATUS_SUCCESS) {
        std::printf("[+] NtCreateThreadEx succeeded. Thread Handle: %p\n", threadHandle);
        WaitForSingleObject(threadHandle, INFINITE);
        CloseHandle(threadHandle);
        return STATUS_SUCCESS;
    }

    std::fprintf(stderr, "[-] NtCreateThreadEx failed with status: 0x%lx\n", status);
    return status;
}