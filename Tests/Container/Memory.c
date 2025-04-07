#include "../Infra.h"

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma warning(disable : 4047)

typedef NTSTATUS(NTAPI* NtCreateProcessEx_t)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob
    );

NTSTATUS test_proc_ex() {
    HANDLE hProc = NULL;
    NTSTATUS status = 0;
    HANDLE parent = GetCurrentProcess();

    ab_call(NtCreateProcessEx_t, "NtCreateProcessEx", status,
        &hProc,
        PROCESS_ALL_ACCESS,
        NULL,            // ObjectAttributes
        parent,          // Parent process
        0,               // Flags
        NULL,            // SectionHandle
        NULL,            // DebugPort
        NULL,            // ExceptionPort
        FALSE            // InJob
    );

    if (status == STATUS_SUCCESS) {
        printf("[OK] NtCreateProcessEx succeeded. Handle: %p\n", hProc);
        CloseHandle(hProc);
        return STATUS_SUCCESS;
    }
    else {
        fprintf(stderr, "[-] NtCreateProcessEx failed with status: 0x%lx\n", status);
        return status;
    }
}