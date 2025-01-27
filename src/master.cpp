#include "framework.hpp"

using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtAllocateVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

void* AllocBuffer(ULONG& buffer_size) {
    void* buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        throw std::runtime_error("Failed to allocate buffer for system information");
    }
    return buffer;
}

void ExampleQuerySystemInformation(NtQuerySystemInformation_t nt_query_sys_info) {
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

void ExampleAllocateVirtualMemory(NtAllocateVirtualMemory_t nt_allocate_vm) {
    void* base_address = nullptr;
    SIZE_T region_size = 0x1000;
    ULONG allocation_type = MEM_COMMIT | MEM_RESERVE;
    ULONG protect = PAGE_READWRITE;

    NTSTATUS status = nt_allocate_vm(
        GetCurrentProcess(),
        &base_address,  
        0,
        &region_size,
        allocation_type,
        protect
    );

    if (status == STATUS_SUCCESS) {
        std::cout << "NtAllocateVirtualMemory succeeded, allocated at: " << base_address
            << ", size: " << region_size << '\n';
        VirtualFree(base_address, 0, MEM_RELEASE);
    }
    else {
        std::cerr << "NtAllocateVirtualMemory failed with status: 0x" << std::hex << status << '\n';
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
    ExampleQuerySystemInformation(nt_query_sys_info);

    void* nt_allocate_vm_stub = stub_manager.FetchStub("NtAllocateVirtualMemory");
    if (!nt_allocate_vm_stub) {
        std::cerr << "NtAllocateVirtualMemory stub not found\n";
        NtdllLoader::Cleanup(ntdll_base);
        return;
    }

    std::cout << "NtAllocateVirtualMemory stub address: " << nt_allocate_vm_stub << '\n';
    auto nt_allocate_vm = reinterpret_cast<NtAllocateVirtualMemory_t>(nt_allocate_vm_stub);
    ExampleAllocateVirtualMemory(nt_allocate_vm);

    NtdllLoader::Cleanup(ntdll_base);
}

int main() {
    try {
        Run();
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
    }

    std::cin.get();
    return 0;
}
