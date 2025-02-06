#include "ActiveBreach.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#ifdef _MSC_VER
#define NORETURN __declspec(noreturn)
#else
#define NORETURN __attribute__((noreturn))
#endif

static NORETURN void fatal_err(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

void ZeroOutSections(void* mapped_base) {
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)mapped_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        fatal_err("invalid dos header signature");
    }

    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((uint8_t*)mapped_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        fatal_err("invalid nt header signature");
    }

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section) {
        char section_name[9] = { 0 };
        memcpy(section_name, section->Name, 8);

        if (strcmp(section_name, ".text") != 0 && strcmp(section_name, ".rdata") != 0) {
            void* section_addr = (void*)((uint8_t*)mapped_base + section->VirtualAddress);

            DWORD old_protection;
            if (VirtualProtect(section_addr, section->Misc.VirtualSize, PAGE_READWRITE, &old_protection)) {
                memset(section_addr, 0, section->Misc.VirtualSize);
                VirtualProtect(section_addr, section->Misc.VirtualSize, old_protection, &old_protection);
            }
        }
    }
}

void* MapNtdll(void) {
    wchar_t system_dir[MAX_PATH];
    if (!GetSystemDirectoryW(system_dir, MAX_PATH))
        fatal_err("Failed to retrieve the system directory");

    wchar_t ntdll_path[MAX_PATH];
    if (swprintf(ntdll_path, MAX_PATH, L"%s\\ntdll.dll", system_dir) < 0)
        fatal_err("Failed to build ntdll.dll path");

    HANDLE file = CreateFileW(ntdll_path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        fatal_err("Failed to open ntdll.dll");

    HANDLE mapping = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mapping) {
        CloseHandle(file);
        fatal_err("Failed to create file mapping for ntdll.dll");
    }

    void* mapped_base = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!mapped_base) {
        CloseHandle(mapping);
        CloseHandle(file);
        fatal_err("Failed to map ntdll.dll into memory");
    }

    CloseHandle(mapping);
    CloseHandle(file);
    return mapped_base;
}

SyscallTable GetSyscallTable(void* mapped_base) {
    SyscallTable table = { 0 };
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)mapped_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        fatal_err("Invalid DOS header signature");

    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((uint8_t*)mapped_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
        fatal_err("Invalid NT header signature");

    IMAGE_DATA_DIRECTORY exportData = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportData.VirtualAddress == 0)
        fatal_err("No export directory found");

    IMAGE_EXPORT_DIRECTORY* export_dir = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)mapped_base + exportData.VirtualAddress);
    uint32_t* names = (uint32_t*)((uint8_t*)mapped_base + export_dir->AddressOfNames);
    uint32_t* functions = (uint32_t*)((uint8_t*)mapped_base + export_dir->AddressOfFunctions);
    uint16_t* ordinals = (uint16_t*)((uint8_t*)mapped_base + export_dir->AddressOfNameOrdinals);

    SyscallEntry* entries = (SyscallEntry*)malloc(export_dir->NumberOfNames * sizeof(SyscallEntry));
    if (!entries)
        fatal_err("Failed to allocate memory for syscall entries");

    size_t count = 0;
    for (uint32_t i = 0; i < export_dir->NumberOfNames; i++) {
        char* func_name = (char*)((uint8_t*)mapped_base + names[i]);
        if (strncmp(func_name, "Nt", 2) == 0) {
            uint32_t funcRVA = functions[ordinals[i]];
            uint8_t* func_ptr = (uint8_t*)mapped_base + funcRVA;
            /* expected -> 0x4C, 0x8B, 0xD1, 0xB8 */
            if (func_ptr[0] == 0x4C && func_ptr[1] == 0x8B &&
                func_ptr[2] == 0xD1 && func_ptr[3] == 0xB8) {
                uint32_t ssn = *(uint32_t*)(func_ptr + 4);
                entries[count].name = strdup(func_name);
                if (!entries[count].name)
                    fatal_err("Failed to duplicate function name");
                entries[count].ssn = ssn;
                count++;
            }
        }
    }
    if (count == 0) {
        free(entries);
        table.entries = NULL;
        table.count = 0;
    }
    else {
        SyscallEntry* new_entries = (SyscallEntry*)realloc(entries, count * sizeof(SyscallEntry));
        if (!new_entries) {
            free(entries);
            fatal_err("Failed to reallocate memory for syscall entries");
        }
        table.entries = new_entries;
        table.count = count;
    }
    return table;
}

void CleanupNtdll(void* mapped_base) {
    if (mapped_base)
        UnmapViewOfFile(mapped_base);
}

void ActiveBreach_Init(ActiveBreach* ab) {
    if (!ab)
        fatal_err("ActiveBreach pointer is NULL");
    ab->stub_mem = NULL;
    ab->stub_mem_size = 0;
    ab->stubs = NULL;
    ab->stub_count = 0;
}

static void CreateStub(void* target_address, uint32_t ssn) {
    /* stub;
       0x4C, 0x8B, 0xD1, 0xB8, [4-byte ssn], 0x0F, 0x05, 0xC3, zero-pad 16b
    */
    uint8_t stub[16] = { 0 };
    stub[0] = 0x4C;
    stub[1] = 0x8B;
    stub[2] = 0xD1;
    stub[3] = 0xB8;
    *(uint32_t*)(stub + 4) = ssn;
    stub[8] = 0x0F;
    stub[9] = 0x05;
    stub[10] = 0xC3;
    memcpy(target_address, stub, 16);
}

int ActiveBreach_AllocStubs(ActiveBreach* ab, const SyscallTable* table) {
    if (!ab || !table)
        fatal_err("ActiveBreach or SyscallTable pointer is NULL");
    if (table->count == 0)
        return -1;
    ab->stub_mem_size = table->count * 16; /* 16 bytes per stub */
    ab->stub_mem = (uint8_t*)VirtualAlloc(NULL, ab->stub_mem_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ab->stub_mem)
        fatal_err("Failed to allocate executable memory for stubs");

    ab->stubs = (StubEntry*)malloc(table->count * sizeof(StubEntry));
    if (!ab->stubs) {
        VirtualFree(ab->stub_mem, 0, MEM_RELEASE);
        fatal_err("Failed to allocate memory for stub entries");
    }

    ab->stub_count = table->count;
    uint8_t* current_stub = ab->stub_mem;
    for (size_t i = 0; i < table->count; i++) {
        CreateStub(current_stub, table->entries[i].ssn);
        ab->stubs[i].name = strdup(table->entries[i].name);
        if (!ab->stubs[i].name)
            fatal_err("Failed to duplicate stub name");
        ab->stubs[i].stub = current_stub;
        current_stub += 16;
    }
    return 0;
}

void* ActiveBreach_GetStub(ActiveBreach* ab, const char* name) {
    if (!ab || !ab->stubs)
        return NULL;
    for (size_t i = 0; i < ab->stub_count; i++) {
        if (strcmp(ab->stubs[i].name, name) == 0)
            return ab->stubs[i].stub;
    }
    return NULL;
}

void ActiveBreach_Free(ActiveBreach* ab) {
    if (!ab)
        return;
    if (ab->stub_mem) {
        VirtualFree(ab->stub_mem, 0, MEM_RELEASE);
        ab->stub_mem = NULL;
    }
    if (ab->stubs) {
        for (size_t i = 0; i < ab->stub_count; i++) {
            if (ab->stubs[i].name)
                free(ab->stubs[i].name);
        }
        free(ab->stubs);
        ab->stubs = NULL;
    }
    ab->stub_count = 0;
    ab->stub_mem_size = 0;
}

// global instance
ActiveBreach g_ab;

void ActiveBreach_Cleanup(void) {
    ActiveBreach_Free(&g_ab);
}

void ActiveBreach_launch(void) {
    void* ntdll_base = MapNtdll();
    SyscallTable table = GetSyscallTable(ntdll_base);
    CleanupNtdll(ntdll_base);

    ActiveBreach_Init(&g_ab);
    if (ActiveBreach_AllocStubs(&g_ab, &table) != 0)
        fatal_err("Failed to allocate stubs");

    if (table.entries) {
        for (size_t i = 0; i < table.count; i++) {
            if (table.entries[i].name)
                free(table.entries[i].name);
        }
        free(table.entries);
    }

    atexit(ActiveBreach_Cleanup);
}

/* --- Example AB_CALL (C) ---
 * In this example the syscall returns NTSTATUS
 * In C the macro is used as a statement that assigns the result into a var
*/
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);

void ab_call_NtQuerySysInfo(void) {
    ULONG buffer_size = 0x1000;
    NTSTATUS status;
    ULONG return_length = 0;
    PVOID buffer = NULL;

    while (1) {
        buffer = VirtualAlloc(NULL, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            fprintf(stderr, "[-] Failed to allocate buffer for syscall\n");
            return;
        }
        /* in C, use the macro as a statement that sets 'status'; */
        ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", status, 5, buffer, buffer_size, &return_length);
        if (status == STATUS_SUCCESS) {
            printf("[+] Example syscall succeeded, return length: %lu\n", return_length);
            VirtualFree(buffer, 0, MEM_RELEASE);
            break;
        }
        else if (status == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            buffer_size *= 2;
            continue;
        }
        else {
            fprintf(stderr, "[-] Example syscall failed with status: 0x%lx\n", status);
            VirtualFree(buffer, 0, MEM_RELEASE);
            break;
        }
    }
}

/*
void Run(void) {
    ActiveBreach_launch();
    ab_call_NtQuerySysInfo();
}

int main(void) {
    Run();
    (void)getchar();
    return 0;
}
*/