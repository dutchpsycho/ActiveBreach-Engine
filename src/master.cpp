#include "framework.h"

#include <Windows.h>

#include <iostream>
#include <stdexcept>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

void* AllocBuffer(ULONG& buffer_size) {
    void* buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        throw std::runtime_error("failed to allocate buffer for system information");
    }

    return buffer;
}

void ExampleCall(NtQuerySystemInformation_t nt_query_sys_info) {
    ULONG buffer_size = 0x1000;
    void* buffer = nullptr;
    ULONG return_length = 0;
    NTSTATUS status;

    do {
        if (buffer) {
            VirtualFree(buffer, 0, MEM_RELEASE);
        }
        buffer = AllocBuffer(buffer_size);
        status = nt_query_sys_info(5, buffer, buffer_size, &return_length);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            buffer_size *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status == STATUS_SUCCESS) {
        std::cout << "NtQuerySystemInformation succeeded, buffer size: " << return_length << '\n';
    }
    else {
        std::cerr << "NtQuerySystemInformation failed with status: 0x" << std::hex << status << '\n';
    }

    if (buffer) {
        VirtualFree(buffer, 0, MEM_RELEASE);
    }
}

void Run() {
    void* ntdll_base = NtdllLoader::MapDLL();
    auto syscall_table = NtdllLoader::ExtractSSN(ntdll_base);

    StubManager stub_manager;
    stub_manager.AllocStubs(syscall_table);

    void* nt_query_sys_info_stub = stub_manager.FetchStub("NtQuerySystemInformation");
    if (!nt_query_sys_info_stub) {
        std::cerr << "NtQuerySystemInformation stub not found\n";
        NtdllLoader::Cleanup(ntdll_base);
        return;
    }

    std::cout << "NtQuerySystemInformation stub address: " << nt_query_sys_info_stub << '\n';

    auto nt_query_sys_info = reinterpret_cast<NtQuerySystemInformation_t>(nt_query_sys_info_stub);
    ExampleCall(nt_query_sys_info);

    NtdllLoader::Cleanup(ntdll_base);
}

int main() {
    try {
        Run();
    }
    catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
    }

    return 0;
}