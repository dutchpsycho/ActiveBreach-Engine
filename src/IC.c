#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef _M_X64
#define TEB_INSTRUMENTATION_CALLBACK_OFFSET 0x2F8
#else
#error "x64 Only"
#endif

#define MAX_INSTRUCTION_LEN 15

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG Reserved[3];
} THREAD_BASIC_INFORMATION;

#ifndef _THREAD_INFORMATION_CLASS
#define _THREAD_INFORMATION_CLASS
typedef enum _THREAD_INFORMATION_CLASS {
    ThreadBasicInformation = 0
} THREAD_INFORMATION_CLASS;
#endif

typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(
    HANDLE ThreadHandle,
    THREAD_INFORMATION_CLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );


typedef struct {
    const unsigned char* pattern;
    size_t length;
    size_t iLength;
    bool exit;
} InstructionPattern;

SIZE_T ICLength(HANDLE processHandle, ULONG_PTR callbackAddress) {
    unsigned char instructionBuffer[MAX_INSTRUCTION_LEN];
    SIZE_T bytesRead = 0;

    InstructionPattern patterns[] = {
        {(unsigned char[]) { 0xC3 }, 1, 1, true},                // RET
        {(unsigned char[]) { 0xC2 }, 1, 3, true},                // RET imm16
        {(unsigned char[]) { 0x48, 0x83, 0xC4 }, 3, 4, false},   // ADD RSP, imm8
        {(unsigned char[]) { 0x48, 0x81, 0xC4 }, 3, 7, false},   // ADD RSP, imm32
        {(unsigned char[]) { 0xC9 }, 1, 1, true},                // LEAVE
    };

    SIZE_T len = 0;
    while (true) {

        if (!ReadProcessMemory(processHandle, (LPCVOID)(callbackAddress + len), instructionBuffer, MAX_INSTRUCTION_LEN, &bytesRead)) {
            printf("Failed to read memory at callback addr\n");
            return 0;
        }

        bool matched = false;
        for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); ++i) {
            InstructionPattern* pattern = &patterns[i];
            if (memcmp(instructionBuffer, pattern->pattern, pattern->length) == 0) {
                len += pattern->iLength;
                if (pattern->exit) {
                    return len;
                }
                matched = true;
                break;
            }
        }

        if (!matched) {
            len += 1;
        }

        if (len > 256) {
            printf("Failed to determine the callback length, exceeded maximum allowed size (256)\n");
            return 0;
        }
    }
}

int SkipIC(HANDLE processHandle, HANDLE threadHandle) {

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        printf("Failed to get ntdll handle\n");
        return 0;
    }

    NtQueryInformationThread_t NtQueryInformationThread =
        (NtQueryInformationThread_t)GetProcAddress(ntdll, "NtQueryInformationThread");
    if (!NtQueryInformationThread) {
        printf("Failed to resolve NtQueryInformationThread\n");
        return 0;
    }

    THREAD_BASIC_INFORMATION threadInfo = { 0 };
    NTSTATUS status = NtQueryInformationThread(threadHandle, ThreadBasicInformation, &threadInfo, sizeof(threadInfo), NULL);
    if (status != 0) {
        printf("Failed to query thread information, status: 0x%08X\n", status);
        return 0;
    }

    PVOID tebAddress = threadInfo.TebBaseAddress;
    ULONG_PTR icPointer = (ULONG_PTR)tebAddress + TEB_INSTRUMENTATION_CALLBACK_OFFSET;

    ULONG_PTR callbackAddress = 0;
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(processHandle, (LPCVOID)icPointer, &callbackAddress, sizeof(callbackAddress), &bytesRead) ||
        bytesRead != sizeof(callbackAddress)) {
        printf("Failed to read instrumentation callback ptr\n");
        callbackAddress = 0; // if parsing ic fails, (assume memory is protected) nullify it by TEB entry
    }

    if (callbackAddress == 0) {
        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(processHandle, (LPVOID)icPointer, &callbackAddress, sizeof(callbackAddress), &bytesWritten) ||
            bytesWritten != sizeof(callbackAddress)) {
            printf("Failed to delete the IC entry\n");
            return 0;
        }
        printf("Instrumentation callback entry deleted\n");
        return 1; // if not succcess, probably protected aswell
    }

    SIZE_T callbackLength = ICLength(processHandle, callbackAddress);
    if (callbackLength == 0) {
        printf("Failed to get the IC length, deleting instead\n");

        SIZE_T bytesWritten = 0;
        ULONG_PTR nullPtr = 0;
        if (!WriteProcessMemory(processHandle, (LPVOID)icPointer, &nullPtr, sizeof(nullPtr), &bytesWritten) ||
            bytesWritten != sizeof(nullPtr)) {
            printf("Failed to nullify the IC entry\n");
            return 0;
        }

        printf("IC entry deleted (TEB)\n");
        return 1;
    }

    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_CONTROL; // only need control related
    SIZE_T bytesWritten = 0;

    if (!ReadProcessMemory(processHandle, (LPCVOID)((ULONG_PTR)tebAddress + offsetof(CONTEXT, Rip)),
        &context.Rip, sizeof(context.Rip), &bytesRead) ||
        bytesRead != sizeof(context.Rip)) {
        printf("Failed to read thread ctx\n");
        return 0;
    }

    // adjust rip to skip ic
    context.Rip += callbackLength;

    if (!WriteProcessMemory(processHandle, (LPVOID)((ULONG_PTR)tebAddress + offsetof(CONTEXT, Rip)),
        &context.Rip, sizeof(context.Rip), &bytesWritten) ||
        bytesWritten != sizeof(context.Rip)) {
        printf("Failed to modify thread ctx\n");
        return 0;
    }

    printf("Instrumentation callback disabled successfully\n");
    return 1;
}