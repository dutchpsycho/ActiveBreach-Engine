#include "ActiveBreach.hpp"

#include <Windows.h>

#include <iostream>

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);

int main() {
    // remove the " " if u dont want operational msg
    ActiveBreach_launch("LMK");

    ULONG buffer_size = 0x1000;
    PVOID buffer = nullptr;
    ULONG return_length = 0;
    NTSTATUS status;

    do {
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);

        buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            std::cerr << "Failed to allocate buffer" << std::endl;
            return 1;
        }

        status = ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation",
            5, buffer, buffer_size, &return_length);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            buffer_size *= 2;
        }

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status == STATUS_SUCCESS) {
        std::cout << "NtQuerySystemInformation succeeded, return length: " << return_length << std::endl;
    }
    else {
        std::cerr << "NtQuerySystemInformation failed with status: 0x" << std::hex << status << std::endl;
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    std::cin.get();
    return 0;
}
