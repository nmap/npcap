#pragma warning(disable: 4005 4201 4324)

#ifndef _WIN64
	#define WIN32
#endif
#define WIN_NT_DRIVER

//#define NDIS620 1 //NDIS 6.2 version (for Windows 7 above) 
#define NDIS60 1 //NDIS 6.0 version (for Windows Vista above) is currently used

// Specify which version of the NDIS contract you will use here.
// In many cases, 6.0 is the best choice.  You only need to select a later
// version if you need a feature that is not available in 6.0.
//
// Legal values include:
//    6.0  Available starting with Windows Vista RTM
//    6.1  Available starting with Windows Vista SP1 / Windows Server 2008
//    6.20 Available starting with Windows 7 / Windows Server 2008 R2
//    6.30 Available starting with Windows 8 / Windows Server "8"
// Or, just use NDIS_FILTER_MAJOR_VERSION / NDIS_FILTER_MINOR_VERSION
// to pick up whatever version is defined by your build system
// (for example, "-DNDIS630").

#define NPF_ALLOC_TAG '1234'
#define NPF_REQUEST_ID '5678'

//#pragma comment(lib, "ndis.lib")

#define WIN9X_COMPAT_SPINLOCK

#include <ntddk.h>
#include <ndis.h>
#include <wmistr.h>
#include <wdmsec.h>
#include <wdmguid.h>
#include "debug.h"
#include "macros.h"
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

