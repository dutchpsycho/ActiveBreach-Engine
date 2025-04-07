#ifndef INFRA_H
#define INFRA_H

#include <windows.h>

#include "../Include/ActiveBreach.h"

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

NTSTATUS test_vmem(void);
NTSTATUS test_sysinfo(void);
NTSTATUS test_threads(void);

#ifdef __cplusplus
extern "C" {
#endif

	NTSTATUS test_proc_ex(void);
	NTSTATUS abthunk_query_sysinfo(void);
	NTSTATUS abthunk_alloc_mem(void);
	NTSTATUS abthunk_close_handle(HANDLE h);

#ifdef __cplusplus
}
#endif

#endif // INFRA_H