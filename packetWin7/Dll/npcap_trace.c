/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *
 * Npcap (https://npcap.com) is a Windows packet sniffing driver and library and
 * is copyright (c) 2013-2025 by Nmap Software LLC ("The Nmap Project").  All
 * rights reserved.
 *
 * Even though Npcap source code is publicly available for review, it is not
 * open source software and may not be redistributed or used in other software
 * without special permission from the Nmap Project. The standard (free) version
 * is usually limited to installation on five systems. For more details, see the
 * LICENSE file included with Npcap and also available at
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header file
 * summarizes a few important aspects of the Npcap license, but is not a
 * substitute for that full Npcap license agreement.
 *
 * We fund the Npcap project by selling two types of commercial licenses to a
 * special Npcap OEM edition:
 *
 * 1) The Npcap OEM Redistribution License allows companies distribute Npcap OEM
 * within their products. Licensees generally use the Npcap OEM silent
 * installer, ensuring a seamless experience for end users. Licensees may choose
 * between a perpetual unlimited license or a quarterly term license, along with
 * options for commercial support and updates. Prices and details:
 * https://npcap.com/oem/redist.html
 *
 * 2) The Npcap OEM Internal-Use License is for organizations that wish to use
 * Npcap OEM internally, without redistribution outside their organization. This
 * allows them to bypass the 5-system usage cap of the Npcap free edition. It
 * includes commercial support and update options, and provides the extra Npcap
 * OEM features such as the silent installer for automated deployment. Prices
 * and details: https://npcap.com/oem/internal.html
 *
 * Both of these licenses include updates and support as well as a warranty.
 * Npcap OEM also includes a silent installer for unattended installation.
 * Further details about Npcap OEM are available from https://npcap.com/oem/,
 * and you are also welcome to contact us at sales@nmap.com to ask any questions
 * or set up a license for your organization.
 *
 * Free and open source software producers are also welcome to contact us for
 * redistribution requests. However, we normally recommend that such authors
 * instead ask your users to download and install Npcap themselves. It will be
 * free for them if they need 5 or fewer copies.
 *
 * If the Nmap Project (directly or through one of our commercial licensing
 * customers) has granted you additional rights to Npcap or Npcap OEM, those
 * additional rights take precedence where they conflict with the terms of the
 * license agreement.
 *
 * Since the Npcap source code is available for download and review, users
 * sometimes contribute code patches to fix bugs or add new features. By sending
 * these changes to the Nmap Project (including through direct email or our
 * mailing lists or submitting pull requests through our source code
 * repository), it is understood unless you specify otherwise that you are
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,
 * modify, and relicense your code contribution so that we may (but are not
 * obligated to) incorporate it into Npcap. If you wish to specify special
 * license conditions or restrictions on your contributions, just say so when
 * you send them.
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. Warranty rights and commercial support are
 * available for the OEM Edition described above.
 *
 * Other copyright notices and attribution may appear below this license header.
 * We have kept those for attribution purposes, but any license terms granted by
 * those notices apply only to their original work, and not to any changes made
 * by the Nmap Project or to this entire file.
 *
 ***************************************************************************/
/*
 * Event Tracing for Windows back end for the TRACE_* macros. See
 * npcap_trace.h for the rationale and for how to collect a trace.
 *
 * This file is compiled into each binary that traces, so each one registers
 * the provider on its own behalf, which is what ETW expects.
 *
 * Trace calls frequently sit between an operation and the GetLastError() that
 * reports on it, so every entry point below restores the calling thread's
 * last error before it returns.
 */

#include "npcap_trace.h"

#if NPCAP_TRACE_ENABLED

#include <winmeta.h>
#include <strsafe.h>
#if NPCAP_TRACE_TO_FILE
#include <stdio.h>
#endif

/* Routing every trace call through this file is what keeps the event
 * metadata and the formatting out of the call sites, of which there are
 * several hundred. Link-time code generation inlines these bodies back
 * into every one of them unless it is told not to, which grows the image
 * for no gain: when no session is listening the call is not reached at
 * all, and when one is, the cost is in ETW rather than here.
 */
#define NPCAP_TRACE_OUTOFLINE __declspec(noinline)

// Longest formatted message an event will carry, terminator included.
#define NPCAP_TRACE_MESSAGE_LENGTH 1024

TRACELOGGING_DEFINE_PROVIDER(
	g_hNpcapTraceProvider,
	NPCAP_TRACE_PROVIDER_NAME,
	(0x5fed140c, 0xc8a2, 0x5a73, 0x7b, 0x61, 0xc3, 0xf3, 0xbb, 0xb0, 0x0b, 0x48));

/* Registering a handle that is already registered is documented as an error
 * that can crash, so the state is tracked here rather than left to callers to
 * pair the calls exactly.
 */
static volatile LONG g_bNpcapTraceRegistered = 0;

#if NPCAP_TRACE_TO_FILE

/* Opens the log for appending, retrying briefly in case another process is
 * between its own open and close. Returns NULL if the file cannot be opened,
 * which is the normal outcome when the caller is not elevated; a trace is
 * never important enough to report a failure over.
 */
static FILE *NpcapTraceOpenLog(VOID)
{
	FILE *f = NULL;
	int loops = 0;

	do
	{
		if (_wfopen_s(&f, NPCAP_TRACE_FILE_PATH, L"a,ccs=UTF-8") == 0)
		{
			return f;
		}

		Sleep(0);
	} while (++loops <= 10);

	return NULL;
}

/* Writes one line in the format used by Npcap 1.88 and earlier, so that a log
 * from this release still reads the same way:
 *
 *     [threadid] yyyy-mm-dd hh:mm:ss <prefix><text>
 */
static VOID NpcapTraceWriteLogPrefix(_In_ FILE *f)
{
	SYSTEMTIME LocalTime;

	GetLocalTime(&LocalTime);
	fwprintf(f, L"[%.08X] %.04u-%.02u-%.02u %.02u:%02u:%02u ",
			GetCurrentThreadId(),
			LocalTime.wYear,
			LocalTime.wMonth,
			LocalTime.wDay,
			LocalTime.wHour,
			LocalTime.wMinute,
			LocalTime.wSecond);
}

static VOID NpcapTraceWriteLogA(_In_z_ LPCSTR Prefix, _In_z_ LPCSTR Text)
{
	FILE *f = NpcapTraceOpenLog();

	if (f == NULL)
	{
		return;
	}

	NpcapTraceWriteLogPrefix(f);
	fwprintf(f, L"%hs%hs\n", Prefix, Text);
	fclose(f);
}

static VOID NpcapTraceWriteLogW(_In_z_ LPCSTR Prefix, _In_z_ LPCWSTR Text)
{
	FILE *f = NpcapTraceOpenLog();

	if (f == NULL)
	{
		return;
	}

	NpcapTraceWriteLogPrefix(f);
	fwprintf(f, L"%hs%s\n", Prefix, Text);
	fclose(f);
}

#endif // NPCAP_TRACE_TO_FILE

VOID NpcapTraceRegister(VOID)
{
	if (InterlockedCompareExchange(&g_bNpcapTraceRegistered, 1, 0) == 0)
	{
		const DWORD dwLastError = GetLastError();

		/* Failure leaves the provider permanently disabled, which the enabled
		 * test at each call site already accounts for.
		 */
		TraceLoggingRegister(g_hNpcapTraceProvider);
		SetLastError(dwLastError);
	}
}

VOID NpcapTraceUnregister(VOID)
{
	if (InterlockedCompareExchange(&g_bNpcapTraceRegistered, 0, 1) == 1)
	{
		const DWORD dwLastError = GetLastError();

		TraceLoggingUnregister(g_hNpcapTraceProvider);
		SetLastError(dwLastError);
	}
}

/* TraceLoggingLevel and TraceLoggingOpcode require compile-time constants, so
 * entry and exit are separate functions rather than one taking a flag. That
 * also spares the several hundred call sites an argument each.
 */
NPCAP_TRACE_OUTOFLINE VOID NpcapTraceEnter(_In_z_ LPCSTR Function)
{
	const DWORD dwLastError = GetLastError();

#if NPCAP_TRACE_TO_FILE
	NpcapTraceWriteLogA("--> ", Function);
#endif

	TraceLoggingWrite(g_hNpcapTraceProvider, "FunctionEnter",
			TraceLoggingLevel(NPCAP_TRACE_LEVEL_SCOPE),
			TraceLoggingOpcode(WINEVENT_OPCODE_START),
			TraceLoggingString(Function, "Function"));

	SetLastError(dwLastError);
}

NPCAP_TRACE_OUTOFLINE VOID NpcapTraceExit(_In_z_ LPCSTR Function)
{
	const DWORD dwLastError = GetLastError();

#if NPCAP_TRACE_TO_FILE
	NpcapTraceWriteLogA("<-- ", Function);
#endif

	TraceLoggingWrite(g_hNpcapTraceProvider, "FunctionExit",
			TraceLoggingLevel(NPCAP_TRACE_LEVEL_SCOPE),
			TraceLoggingOpcode(WINEVENT_OPCODE_STOP),
			TraceLoggingString(Function, "Function"));

	SetLastError(dwLastError);
}

NPCAP_TRACE_OUTOFLINE VOID NpcapTraceMessageA(_In_z_ LPCSTR Function, _In_z_ _Printf_format_string_ LPCSTR Format, ...)
{
	const DWORD dwLastError = GetLastError();
	CHAR Message[NPCAP_TRACE_MESSAGE_LENGTH];
	va_list Marker;
	HRESULT hrStatus;

	va_start(Marker, Format);
	hrStatus = StringCchVPrintfA(Message, ARRAYSIZE(Message), Format, Marker);
	va_end(Marker);

	/* A truncated message is still terminated and still worth logging. Any
	 * other failure leaves the buffer undefined, so report nothing rather than
	 * the contents of the stack.
	 */
	if (FAILED(hrStatus) && hrStatus != STRSAFE_E_INSUFFICIENT_BUFFER)
	{
		Message[0] = '\0';
	}

#if NPCAP_TRACE_TO_FILE
	NpcapTraceWriteLogA("    ", Message);
#endif

	TraceLoggingWrite(g_hNpcapTraceProvider, "Message",
			TraceLoggingLevel(NPCAP_TRACE_LEVEL_MESSAGE),
			TraceLoggingString(Function, "Function"),
			TraceLoggingString(Message, "Message"));

	SetLastError(dwLastError);
}

NPCAP_TRACE_OUTOFLINE VOID NpcapTraceMessageW(_In_z_ LPCSTR Function, _In_z_ _Printf_format_string_ LPCWSTR Format, ...)
{
	const DWORD dwLastError = GetLastError();
	WCHAR Message[NPCAP_TRACE_MESSAGE_LENGTH];
	va_list Marker;
	HRESULT hrStatus;

	va_start(Marker, Format);
	hrStatus = StringCchVPrintfW(Message, ARRAYSIZE(Message), Format, Marker);
	va_end(Marker);

	if (FAILED(hrStatus) && hrStatus != STRSAFE_E_INSUFFICIENT_BUFFER)
	{
		Message[0] = L'\0';
	}

#if NPCAP_TRACE_TO_FILE
	NpcapTraceWriteLogW("    ", Message);
#endif

	TraceLoggingWrite(g_hNpcapTraceProvider, "Message",
			TraceLoggingLevel(NPCAP_TRACE_LEVEL_MESSAGE),
			TraceLoggingString(Function, "Function"),
			TraceLoggingWideString(Message, "Message"));

	SetLastError(dwLastError);
}

/* Reads a REG_SZ value into Buffer, leaving it empty if the value is missing,
 * of the wrong type, or too long to fit.
 */
static VOID NpcapTraceReadRegSz(
		_In_z_ LPCWSTR SubKey,
		_In_z_ LPCWSTR Value,
		_Out_writes_z_(cchBuffer) LPWSTR Buffer,
		_In_ DWORD cchBuffer)
{
	HKEY hKey;
	DWORD dwType = 0;
	DWORD cbValue = (cchBuffer - 1) * sizeof(WCHAR);

	Buffer[0] = L'\0';

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SubKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
	{
		return;
	}

	if (RegQueryValueExW(hKey, Value, NULL, &dwType, (LPBYTE)Buffer, &cbValue) == ERROR_SUCCESS
			&& dwType == REG_SZ)
	{
		// RegQueryValueEx does not promise a terminator; room for one was
		// withheld from cbValue above.
		Buffer[cbValue / sizeof(WCHAR)] = L'\0';
	}
	else
	{
		Buffer[0] = L'\0';
	}

	RegCloseKey(hKey);
}

NPCAP_TRACE_OUTOFLINE VOID NpcapTraceOsInfo(VOID)
{
	WCHAR Architecture[128];
	WCHAR CurrentType[128];
	DWORD dwLastError;

	/* Unlike the message and scope macros, this one has no enabled test around
	 * it at the call site, so make one here before touching the registry.
	 */
#if !NPCAP_TRACE_TO_FILE
	if (!NpcapTraceEnabled(NPCAP_TRACE_LEVEL_MESSAGE))
	{
		return;
	}
#endif

	dwLastError = GetLastError();

	/* An ETL file already records the OS build, processor count, pointer size
	 * and CPU speed in its header, so only the two values ETW does not supply
	 * are logged here.
	 */
	NpcapTraceReadRegSz(L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
			L"PROCESSOR_ARCHITECTURE", Architecture, ARRAYSIZE(Architecture));
	NpcapTraceReadRegSz(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
			L"CurrentType", CurrentType, ARRAYSIZE(CurrentType));

	TraceLoggingWrite(g_hNpcapTraceProvider, "OsInfo",
			TraceLoggingLevel(NPCAP_TRACE_LEVEL_MESSAGE),
			TraceLoggingWideString(Architecture, "ProcessorArchitecture"),
			TraceLoggingWideString(CurrentType, "WindowsCurrentType"));

	SetLastError(dwLastError);
}

#endif // NPCAP_TRACE_ENABLED
