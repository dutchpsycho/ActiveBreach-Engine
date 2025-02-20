#include "../Include/ActiveBreach.h"

#include <windows.h>

#include <cstdio>

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);

int main() {
   ActiveBreach_launch();

    ULONG infoClass = 5;
    ULONG bufferSize = 0x1000;
    void* buffer = nullptr;
    NTSTATUS status = 0;
    ULONG returnLength = 0;

    // Call NtQuerySystemInformation through ab_call
    // in C++ the macro returns the result so we can assign it directly
    while (true) {
        buffer = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            std::fprintf(stderr, "[-] Failed to allocate memory.\n");
            return -1;
        }

        status = ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", infoClass, buffer, bufferSize, &returnLength);

        if (status == STATUS_SUCCESS) {
            std::printf("[+] NtQuerySystemInformation succeeded, return length: %lu\n", returnLength);
            VirtualFree(buffer, 0, MEM_RELEASE);
            break;
        }

        else if (status == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            bufferSize *= 2;
            continue;
        }

        else {
            std::fprintf(stderr, "[-] NtQuerySystemInformation failed with status: 0x%lx\n", status);
            VirtualFree(buffer, 0, MEM_RELEASE);
            break;
        }
    }

    return 0;
}