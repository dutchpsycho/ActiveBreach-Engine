/*
ACTIVEBREACH System
@developer DutchPsycho
@inspo MDSEC
*/

#ifndef ACTIVEBREACH_HPP
#define ACTIVEBREACH_HPP

#ifdef __cplusplus
extern "C" {
#endif

#pragma warning(disable : 28251)
#include <Windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef LONG NTSTATUS;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

/*
 * ActiveBreach_launch:
 * launches the global ActiveBreach handler
 * Internally, it maps ntdll.dll & extracts ssns,builds syscall stubs, and sets up the activebreach system
*/

    void ActiveBreach_launch(const char* notify = nullptr);
	void* _ab_get_stub(const char* name);

#ifdef __cplusplus
}
#endif

/*
 * ab_call macro:
 * The caller supplies the NT func type and args
 * eg; NTSTATUS status = ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", 5, buffer, buffer_size, &return_length);
*/

#define ab_call(nt_type, name, ...) \
    ([]() -> nt_type { \
        void* stub = _ab_get_stub(name); \
        if (!stub) { \
            fprintf(stderr, "Stub \"%s\" not found\n", name); \
            return (nt_type)0; \
        } \
        return reinterpret_cast<nt_type>(stub); \
    }())(__VA_ARGS__)

#endif