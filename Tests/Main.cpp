#include "Infra.h"

#include <windows.h>
#include <cstdio>

int main() {
    ActiveBreach_launch();

    std::printf("=== ActiveBreach Test Harness ===\n\n");

    // -- test 1: memory allocation via C++
    if (test_vmem() == STATUS_SUCCESS)
        std::printf("[OK] test_vmem (C++): Passed\n");
    else
        std::fprintf(stderr, "[x] test_vmem (C++): Failed\n");

    // -- test 2: system info query via C++
    if (test_sysinfo() == STATUS_SUCCESS)
        std::printf("[OK] test_sysinfo (C++): Passed\n");
    else
        std::fprintf(stderr, "[x] test_sysinfo (C++): Failed\n");

    // -- test 3: thread creation via C++
    if (test_threads() == STATUS_SUCCESS)
        std::printf("[OK] test_threads (C++): Passed\n");
    else
        std::fprintf(stderr, "[x] test_threads (C++): Failed\n");

    // -- test 4: process creation via C
    if (test_proc_ex() == STATUS_SUCCESS)
        std::printf("[OK] test_proc_ex (C): Passed\n");
    else
        std::fprintf(stderr, "[x] test_proc_ex (C): Failed\n");

    // -- test 5: syscall info mismatch check (ab_call_func)
    abthunk_query_sysinfo();

    // -- test 6: syscall memory allocation via ab_call_func
    abthunk_alloc_mem();

    // -- test 7: syscall close handle (ab_call_func)
    HANDLE dummy = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (dummy)
        abthunk_close_handle(dummy);
    else
        std::fprintf(stderr, "[x] failed to create dummy handle for NtClose\n");

    std::printf("\n=== Test Complete ===\n");
    return 0;
}