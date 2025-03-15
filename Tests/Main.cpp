#include "Infra.h"

#include <windows.h>
#include <cstdio>

int main() {
    ActiveBreach_launch();

    if (test_vmem() == STATUS_SUCCESS)
        std::printf("[+] Memory allocation test passed.\n");
    else
        std::fprintf(stderr, "[-] Memory allocation test failed.\n");

    if (test_sysinfo() == STATUS_SUCCESS)
        std::printf("[+] System info query test passed.\n");
    else
        std::fprintf(stderr, "[-] System info query test failed.\n");

    if (test_threads() == STATUS_SUCCESS)
        std::printf("[+] Thread creation test passed.\n");
    else
        std::fprintf(stderr, "[-] Thread creation test failed.\n");

    return 0;
}