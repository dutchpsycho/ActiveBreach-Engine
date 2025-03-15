#ifndef INFRA_H
#define INFRA_H

#include <windows.h>

#include "../C/ActiveBreach.h"

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifdef __cplusplus
extern "C" {
#endif

	NTSTATUS test_vmem();
	NTSTATUS test_sysinfo();
	NTSTATUS test_threads();

#ifdef __cplusplus
}
#endif

#endif // INFRA_H