#include "framework.h"

template <typename T>
class DllMapper {
public:
    void* MapDLL(const std::wstring& dll_name) {
        HANDLE file = CreateFileW(
            dll_name.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (file == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("failed to open dll: " + std::string(dll_name.begin(), dll_name.end()));
        }

        HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        
        if (!mapping) {
            CloseHandle(file);
            throw std::runtime_error("failed to create file mapping for: " + std::string(dll_name.begin(), dll_name.end()));
        }

        void* mapped_base = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);

        CloseHandle(mapping);
        CloseHandle(file);

        if (!mapped_base) {
            throw std::runtime_error("failed to map dll into memory: " + std::string(dll_name.begin(), dll_name.end()));
        }

        return mapped_base;
    }

    std::unordered_map<std::string, uint32_t> ExtractSSN(void* mapped_base) {
        auto* dos_header = static_cast<IMAGE_DOS_HEADER*>(mapped_base);
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            throw std::runtime_error("invalid dos header signature");
        }

        auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(
            static_cast<uint8_t*>(mapped_base) + dos_header->e_lfanew
            );

        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
            throw std::runtime_error("invalid nt header signature");
        }

        auto* export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(static_cast<uint8_t*>(mapped_base) +nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        auto* names = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(mapped_base) + export_dir->AddressOfNames);
        auto* functions = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(mapped_base) + export_dir->AddressOfFunctions);
        auto* ordinals = reinterpret_cast<uint16_t*>(static_cast<uint8_t*>(mapped_base) + export_dir->AddressOfNameOrdinals);

        std::unordered_map<std::string, uint32_t> syscall_table;

        for (uint32_t i = 0; i < export_dir->NumberOfNames; ++i) {
            const char* func_name = reinterpret_cast<const char*>(
                static_cast<uint8_t*>(mapped_base) + names[i]
                );

            if (std::string_view(func_name).starts_with("Nt")) {
                auto* func_ptr = static_cast<uint8_t*>(mapped_base) + functions[ordinals[i]];
                if (func_ptr[0] == 0x4C && func_ptr[1] == 0x8B && func_ptr[2] == 0xD1 && func_ptr[3] == 0xB8) {
                    uint32_t ssn = *reinterpret_cast<uint32_t*>(func_ptr + 4);
                    syscall_table[func_name] = ssn;
                }
            }
        }

        return syscall_table;
    }

    void Cleanup(void* mapped_base) {
        if (mapped_base) {
            UnmapViewOfFile(mapped_base);
        }
    }
};

void* NtdllLoader::MapDLL() {
    const std::wstring ntdll_path = L"C:\\Windows\\System32\\ntdll.dll";
    HANDLE file = CreateFileW(
        ntdll_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

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

    return mapped_base;
}

std::unordered_map<std::string, uint32_t> NtdllLoader::ExtractSSN(void* mapped_base) {
    auto* dos_header = static_cast<IMAGE_DOS_HEADER*>(mapped_base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        throw std::runtime_error("Invalid DOS header signature");
    }

    auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(
        static_cast<uint8_t*>(mapped_base) + dos_header->e_lfanew
        );

    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        throw std::runtime_error("Invalid NT header signature");
    }

    auto* export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(static_cast<uint8_t*>(mapped_base) +nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    auto* names = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(mapped_base) + export_dir->AddressOfNames);
    auto* functions = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(mapped_base) + export_dir->AddressOfFunctions);
    auto* ordinals = reinterpret_cast<uint16_t*>(static_cast<uint8_t*>(mapped_base) + export_dir->AddressOfNameOrdinals);

    std::unordered_map<std::string, uint32_t> syscall_table;    

    for (uint32_t i = 0; i < export_dir->NumberOfNames; ++i) {
        const char* func_name = reinterpret_cast<const char*>(
            static_cast<uint8_t*>(mapped_base) + names[i]
            );

        if (std::string_view(func_name).starts_with("Nt")) {
            auto* func_ptr = static_cast<uint8_t*>(mapped_base) + functions[ordinals[i]];
            if (func_ptr[0] == 0x4C && func_ptr[1] == 0x8B && func_ptr[2] == 0xD1 && func_ptr[3] == 0xB8) {
                uint32_t ssn = *reinterpret_cast<uint32_t*>(func_ptr + 4);
                syscall_table[func_name] = ssn;
            }
        }
    }

    return syscall_table;
}

void NtdllLoader::Cleanup(void* mapped_base) {
    if (mapped_base) {
        UnmapViewOfFile(mapped_base);
    }
}