#include "framework.h"
#include <unordered_map>
#include <string>
#include <stdexcept>
#include <Windows.h>
#include <iostream>

StubManager::StubManager() : stub_mem(nullptr), stub_mem_size(0) {}

StubManager::~StubManager() {
    if (stub_mem) {
        VirtualFree(stub_mem, 0, MEM_RELEASE);
    }
}

void StubManager::AllocStubs(const std::unordered_map<std::string, uint32_t>& syscall_table) {
    stub_mem_size = syscall_table.size() * 32;
    stub_mem = static_cast<uint8_t*>(AllocX(stub_mem_size));

    uint8_t* current_stub = stub_mem;
    for (const auto& [name, ssn] : syscall_table) {
        CreateStub(current_stub, ssn);
        syscall_stubs.emplace(name, current_stub);
        current_stub += 32;
    }
}

void* StubManager::FetchStub(const std::string& syscall_name) const {
    auto it = syscall_stubs.find(syscall_name);
    return (it != syscall_stubs.end()) ? it->second : nullptr;
}

void StubManager::CreateStub(void* target_address, uint32_t ssn) {
    uint8_t stub[] = {
        0x4C, 0x8B, 0xD1, // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, ssn
        0x0F, 0x05, // syscall
        0xC3        // ret
    };

    *reinterpret_cast<uint32_t*>(&stub[4]) = ssn;
    memcpy(target_address, stub, sizeof(stub));
}

void* StubManager::AllocX(size_t size) {
    void* memory = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!memory) {
        throw std::runtime_error("failed to allocate executable memory");
    }
    return memory;
}