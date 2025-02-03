#include "framework.hpp"

void* NtdllLoader::MapDLL() {
    wchar_t system_dir[MAX_PATH];
    if (!GetSystemDirectoryW(system_dir, MAX_PATH)) {
        throw std::runtime_error("Failed to retrieve the system directory");
    }

    std::wstring ntdll_path = std::wstring(system_dir) + L"\\ntdll.dll";

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

    auto* export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        static_cast<uint8_t*>(mapped_base) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    auto* names = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(mapped_base) + export_dir->AddressOfNames);
    auto* functions = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(mapped_base) + export_dir->AddressOfFunctions);
    auto* ordinals = reinterpret_cast<uint16_t*>(static_cast<uint8_t*>(mapped_base) + export_dir->AddressOfNameOrdinals);

    auto exception_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    auto exception_dir_size = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (!exception_dir_rva || !exception_dir_size) {
        throw std::runtime_error("Exception directory is not present");
    }

    auto* exception_dir = reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(
        static_cast<uint8_t*>(mapped_base) + exception_dir_rva
    );

    size_t exception_count = exception_dir_size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    std::unordered_map<std::string, uint32_t> syscall_table;

    for (uint32_t i = 0; i < export_dir->NumberOfNames; ++i) {
        const char* func_name = reinterpret_cast<const char*>(
            static_cast<uint8_t*>(mapped_base) + names[i]
        );

        if (std::string_view(func_name).rfind("Nt", 0) == 0) {
            auto* func_ptr = static_cast<uint8_t*>(mapped_base) + functions[ordinals[i]];
            if (func_ptr[0] == 0x4C && func_ptr[1] == 0x8B && func_ptr[2] == 0xD1 && func_ptr[3] == 0xB8) {
                uint32_t ssn = *reinterpret_cast<uint32_t*>(func_ptr + 4);

                // xref with exception directory
                bool valid = false;
                for (size_t j = 0; j < exception_count; ++j) {
                    auto* runtime_entry = &exception_dir[j];
                    auto function_start = static_cast<uint8_t*>(mapped_base) + runtime_entry->BeginAddress;
                    auto function_end = static_cast<uint8_t*>(mapped_base) + runtime_entry->EndAddress;

                    if (func_ptr >= function_start && func_ptr < function_end) {
                        valid = true;
                        break;
                    }
                }

                if (!valid) {
                    throw std::runtime_error("Detected tampering in syscall function address");
                }

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