#include "ActiveBreach.hpp"

#include <stdexcept>
#include <unordered_map>
#include <string>
#include <iostream>
#include <cstring>

namespace {

    class ActiveBreachInternal {
    public:
        ActiveBreachInternal() : stub_mem(nullptr), stub_mem_size(0) {}
        ~ActiveBreachInternal() {
            if (stub_mem) {
                VirtualFree(stub_mem, 0, MEM_RELEASE);
            }
        }

        void BuildStubs(const std::unordered_map<std::string, uint32_t>& syscall_table) {
            stub_mem_size = syscall_table.size() * 16; // each stub is 16 bytes
            stub_mem = static_cast<uint8_t*>(VirtualAlloc(nullptr, stub_mem_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
            if (!stub_mem) {
                throw std::runtime_error("Failed to allocate executable memory");
            }
            uint8_t* current_stub = stub_mem;
            for (const auto& [name, ssn] : syscall_table) {
                CreateStub(current_stub, ssn);
                syscall_stubs[name] = current_stub;
                current_stub += 16;
            }
        }

        void* GetStub(const std::string& name) const {
            auto it = syscall_stubs.find(name);
            return (it != syscall_stubs.end()) ? it->second : nullptr;
        }

    private:
        void CreateStub(void* target_address, uint32_t ssn) {
            constexpr uint8_t stub_template[] = {
                0x4C, 0x8B, 0xD1,              // mov r10, rcx
                0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, ssn
                0x0F, 0x05,                    // syscall
                0xC3                           // ret
            };
            uint8_t stub[sizeof(stub_template)];
            memcpy(stub, stub_template, sizeof(stub_template));
            *reinterpret_cast<uint32_t*>(stub + 4) = ssn;
            memcpy(target_address, stub, sizeof(stub));
        }

        uint8_t* stub_mem;
        size_t stub_mem_size;
        std::unordered_map<std::string, void*> syscall_stubs;
    };

    class ab_Internal {
    public:
        static void* Map() {
            wchar_t system_dir[MAX_PATH];
            if (!GetSystemDirectoryW(system_dir, MAX_PATH)) {
                throw std::runtime_error("Failed to retrieve the system directory");
            }
            std::wstring ntdll_path = std::wstring(system_dir) + L"\\ntdll.dll";
            HANDLE file = CreateFileW(ntdll_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) {
                throw std::runtime_error("Failed to open ntdll.dll");
            }
            HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (!mapping) {
                CloseHandle(file);
                throw std::runtime_error("Failed to create file mapping");
            }
            void* mapped_base = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
            CloseHandle(mapping);
            CloseHandle(file);
            if (!mapped_base) {
                throw std::runtime_error("Failed to map ntdll.dll into memory");
            }

            ZeroOutSections(mapped_base);

            return mapped_base;
        }

        static void ZeroOutSections(void* mapped_base) {
            auto* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(mapped_base);
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
                throw std::runtime_error("invalid DOS header signature");
            }
            auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(
                reinterpret_cast<uint8_t*>(mapped_base) + dos_header->e_lfanew);
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
                throw std::runtime_error("invalid NT header signature");
            }

            auto* section = IMAGE_FIRST_SECTION(nt_headers);
            for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section) {
                std::string section_name(reinterpret_cast<char*>(section->Name), 8);

                if (section_name != ".text" && section_name != ".rdata") {
                    void* section_addr = reinterpret_cast<void*>(
                        reinterpret_cast<uint8_t*>(mapped_base) + section->VirtualAddress);

                    DWORD old_protection;
                    if (VirtualProtect(section_addr, section->Misc.VirtualSize, PAGE_READWRITE, &old_protection)) {
                        std::memset(section_addr, 0, section->Misc.VirtualSize);

                        VirtualProtect(section_addr, section->Misc.VirtualSize, old_protection, &old_protection);
                    }
                }
            }
        }

        static std::unordered_map<std::string, uint32_t> ExtractSSN(void* mapped_base) {
            std::unordered_map<std::string, uint32_t> syscall_table;
            auto* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(mapped_base);
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
                throw std::runtime_error("Invalid DOS header signature");
            }
            auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(
                reinterpret_cast<uint8_t*>(mapped_base) + dos_header->e_lfanew);
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
                throw std::runtime_error("Invalid NT header signature");
            }

            auto* export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
                reinterpret_cast<uint8_t*>(mapped_base) +
                nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            auto* names = reinterpret_cast<uint32_t*>(
                reinterpret_cast<uint8_t*>(mapped_base) + export_dir->AddressOfNames);
            auto* functions = reinterpret_cast<uint32_t*>(
                reinterpret_cast<uint8_t*>(mapped_base) + export_dir->AddressOfFunctions);
            auto* ordinals = reinterpret_cast<uint16_t*>(
                reinterpret_cast<uint8_t*>(mapped_base) + export_dir->AddressOfNameOrdinals);

            for (uint32_t i = 0; i < export_dir->NumberOfNames; ++i) {
                std::string func_name(reinterpret_cast<char*>(
                    reinterpret_cast<uint8_t*>(mapped_base) + names[i]));

                if (func_name.rfind("Nt", 0) == 0) {
                    uint32_t ssn = *reinterpret_cast<uint32_t*>(
                        reinterpret_cast<uint8_t*>(mapped_base) + functions[ordinals[i]] + 4);
                    syscall_table[func_name] = ssn;
                }
            }
            return syscall_table;
        }

        static void Cleanup(void* mapped_base) {
            if (mapped_base) {
                UnmapViewOfFile(mapped_base);
            }
        }
    };

    ActiveBreachInternal g_ab_internal;

}

extern "C" void ActiveBreach_launch(const char* notify) {
    try {
        void* mapped_base = ab_Internal::Map();
        auto syscall_table = ab_Internal::ExtractSSN(mapped_base);
        ab_Internal::Cleanup(mapped_base);
        g_ab_internal.BuildStubs(syscall_table);

        if (notify && std::strcmp(notify, "LMK") == 0) {
            std::cout << "[AB] ACTIVEBREACH OPERATIONAL" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "ActiveBreach_launch err: " << e.what() << std::endl;
        exit(1);
    }
}

extern "C" void* _ab_get_stub(const char* name) {
    if (!name) return nullptr;
    return g_ab_internal.GetStub(name);
}