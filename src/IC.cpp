#include "Framework.h"

#ifdef _M_X64
constexpr size_t TEB_INSTRUMENTATION_CALLBACK_OFFSET = 0x2F8;
#else
#error "This implementation is for x64 only"
#endif

static const unsigned char NewHandler[] = {
    0x48, 0x31, 0xC0, // xor rax, rax
    0xC3              // ret
};

void* ICManager::ResolveNt(const std::string& functionName) {
    static HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        throw std::runtime_error("Failed to get ntdll handle");
    }

    void* func = GetProcAddress(ntdll, functionName.c_str());
    if (!func) {
        throw std::runtime_error("Failed to resolve function: " + functionName);
    }

    return func;
}

bool ICManager::GetIC(HANDLE threadHandle, void*& callbackAddress) {
    using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
    static auto NtQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(ResolveNt("NtQueryInformationThread"));

    THREAD_BASIC_INFORMATION threadInfo = {};
    NTSTATUS status = NtQueryInformationThread(threadHandle, ThreadBasicInformation, &threadInfo, sizeof(threadInfo), nullptr);

    if (status != 0) {
        return false;
    }

    callbackAddress = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(threadInfo.TebBaseAddress) + TEB_INSTRUMENTATION_CALLBACK_OFFSET);
    return true;
}

bool ICManager::RemoveIC(HANDLE processHandle, void* callbackAddress) {
    MEMORY_BASIC_INFORMATION mbi = {};

    if (VirtualQueryEx(processHandle, callbackAddress, &mbi, sizeof(mbi)) == 0) {
        return false;
    }

    if (!(mbi.Protect & PAGE_READWRITE) && !(mbi.Protect & PAGE_EXECUTE_READWRITE)) {
        return false;
    }

    SIZE_T bytesWritten = 0;

    if (WriteProcessMemory(processHandle, callbackAddress, NewHandler, sizeof(NewHandler), &bytesWritten) &&
        bytesWritten == sizeof(NewHandler)) {
        return true;
    }

    return false;
}

bool ICManager::VerifyCallbackRemoval(HANDLE processHandle, void* callbackAddress) {
    unsigned char currentBytes[sizeof(NewHandler)] = {};
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(processHandle, callbackAddress, currentBytes, sizeof(NewHandler), &bytesRead) ||
        bytesRead != sizeof(NewHandler)) {
        return false;
    }

    return std::memcmp(currentBytes, NewHandler, sizeof(NewHandler)) == 0;
}

bool ICManager::DisableIC(HANDLE processHandle, const std::vector<HANDLE>& threadHandles) {
    for (HANDLE threadHandle : threadHandles) {
        void* callbackAddress = nullptr;

        if (!GetIC(threadHandle, callbackAddress)) {
            return false;
        }

        if (!RemoveIC(processHandle, callbackAddress)) {
            return false;
        }

        if (!VerifyCallbackRemoval(processHandle, callbackAddress)) {
            return false;
        }
    }

    return true;
}