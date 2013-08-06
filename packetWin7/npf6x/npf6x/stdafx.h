#pragma warning(disable: 4005 4201 4324)
// #define NDIS620 1
// #define PROTOCOL_MAJOR_DRIVER_VERSION 6
// #define PROTOCOL_MINOR_DRIVER_VERSION 20

#ifndef _WIN64
	#define WIN32
#endif
#define WIN_NT_DRIVER

#define NDIS60 1
#define PROTOCOL_MAJOR_DRIVER_VERSION 6
#define PROTOCOL_MINOR_DRIVER_VERSION 0

#define NPF6X_ALLOC_TAG '1234'

//#pragma comment(lib, "ndis.lib")

#define WIN9X_COMPAT_SPINLOCK

#include <ntddk.h>
#include <ndis.h>
//#include <wdf.h>
#include <wmistr.h>
#include <wdmsec.h>
#include <wdmguid.h>
#include "debug.h"
#include "macros.h"
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

