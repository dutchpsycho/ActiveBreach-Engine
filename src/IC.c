#include <windows.h>
#include <string.h>
#include <stdio.h>

#ifdef _M_X64
#define TEB_INSTRUMENTATION_CALLBACK_OFFSET 0x2F8
#else
#error "x64 Only"
#endif

static const unsigned char NewHandler[] = {
    0x48, 0x31, 0xC0, // xor rax, rax
    0xC3              // ret
};

void* ResolveNt(const char* functionName) {
    static HMODULE ntdll = NULL;
    if (!ntdll) {
        ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) {
            fprintf(stderr, "Failed to get ntdll handle\n");
            return NULL;
        }
    }

    void* func = GetProcAddress(ntdll, functionName);
    if (!func) {
        fprintf(stderr, "Failed to resolve function: %s\n", functionName);
        return NULL;
    }

    return func;
}

int GetIC(HANDLE threadHandle, void** callbackAddress) {
    typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
    static NtQueryInformationThread_t NtQueryInformationThread = NULL;

    if (!NtQueryInformationThread) {
        NtQueryInformationThread = (NtQueryInformationThread_t)ResolveNt("NtQueryInformationThread");
        if (!NtQueryInformationThread) {
            return 0;
        }
    }

    THREAD_BASIC_INFORMATION threadInfo = { 0 };
    NTSTATUS status = NtQueryInformationThread(threadHandle, ThreadBasicInformation, &threadInfo, sizeof(threadInfo), NULL);

    if (status != 0) {
        return 0;
    }

    *callbackAddress = (void*)((uintptr_t)threadInfo.TebBaseAddress + TEB_INSTRUMENTATION_CALLBACK_OFFSET);
    return 1;
}

int RemoveIC(HANDLE processHandle, void* callbackAddress) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };

    if (VirtualQueryEx(processHandle, callbackAddress, &mbi, sizeof(mbi)) == 0) {
        return 0;
    }

    if (!(mbi.Protect & PAGE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_READWRITE)) {
        return 0;
    }

    SIZE_T bytesWritten = 0;

    if (WriteProcessMemory(processHandle, callbackAddress, NewHandler, sizeof(NewHandler), &bytesWritten) &&
        bytesWritten == sizeof(NewHandler)) {
        return 1;
    }

    return 0;
}

int VerifyCallbackRemoval(HANDLE processHandle, void* callbackAddress) {
    unsigned char currentBytes[sizeof(NewHandler)] = { 0 };
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(processHandle, callbackAddress, currentBytes, sizeof(NewHandler), &bytesRead) ||
        bytesRead != sizeof(NewHandler)) {
        return 0;
    }

    return memcmp(currentBytes, NewHandler, sizeof(NewHandler)) == 0;
}

int DisableIC(HANDLE processHandle, HANDLE* threadHandles, size_t threadCount) {
    for (size_t i = 0; i < threadCount; ++i) {
        void* callbackAddress = NULL;

        if (!GetIC(threadHandles[i], &callbackAddress)) {
            return 0;
        }

        if (!RemoveIC(processHandle, callbackAddress)) {
            return 0;
        }

        if (!VerifyCallbackRemoval(processHandle, callbackAddress)) {
            return 0;
        }
    }

    return 1;
}