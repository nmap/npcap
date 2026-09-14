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
 * Event Tracing for Windows back end for the TRACE_* macros declared in
 * debug.h.
 *
 * Earlier releases appended each trace call to a log file, reopening and
 * closing that file every time. That was slow enough that the tracing could
 * not be left in a shipping build, so diagnosing a user's problem meant
 * building and delivering a private binary first, and the log itself grew
 * without bound in a directory the user may not be able to write.
 * An ETW trace call costs a load, a comparison and a branch while no session
 * is listening, so the calls are compiled into every configuration and
 * tracing is enabled when it is needed rather than when the binary is built.
 *
 * To collect a trace, from an elevated command prompt:
 *
 *     logman create trace Npcap -ets -o npcap.etl -f bincirc -max 64 ^
 *         -p "{5FED140C-C8A2-5A73-7B61-C3F3BBB00B48}" 0xffffffffffffffff 5
 *     logman stop Npcap -ets
 *     tracerpt npcap.etl -o npcap.csv -of CSV -y
 *
 * NPFInstall.exe additionally keeps its own log file, because an install
 * happens once and cannot be asked to reproduce itself with a trace
 * session already running. Define NPCAP_TRACE_TO_FILE as 1 to select that
 * behavior; every other binary relies on ETW alone.
 *
 * Level 5 records everything. Level 4 omits the function entry and exit
 * events, which account for most of the volume. The -max switch bounds the
 * file rather than allowing it to grow indefinitely. installer\Npcap.wprp
 * provides the equivalent profile for Windows Performance Recorder.
 */

#ifndef __NPCAP_TRACE_H_5FED140CC8A25A737B61C3F3BBB00B48
#define __NPCAP_TRACE_H_5FED140CC8A25A737B61C3F3BBB00B48

// Define as 0 to remove every trace call from the binary.
#ifndef NPCAP_TRACE_ENABLED
#define NPCAP_TRACE_ENABLED 1
#endif

/* Define as 1 to also append every trace call to a log file. Reopening the
 * file for each call is far more expensive than writing an ETW event, so
 * this suits only a one-shot program that has to leave a record behind
 * without anyone having arranged to collect one first. NPFInstall.exe is
 * the only such program here.
 */
#ifndef NPCAP_TRACE_TO_FILE
#define NPCAP_TRACE_TO_FILE 0
#endif

#if NPCAP_TRACE_TO_FILE && !defined(NPCAP_TRACE_FILE_PATH)
#define NPCAP_TRACE_FILE_PATH L"C:\\Program Files\\Npcap\\NPFInstall.log"
#endif

#if NPCAP_TRACE_ENABLED

/* When WINVER is 0x0602 or greater, which is the SDK default,
 * TraceLoggingProvider.h imports EventSetInformation directly from
 * advapi32.dll. Windows 7 does not export that function, so the import alone
 * would prevent the binary from loading there. A value of 2 directs the
 * header to locate the function through GetModuleHandleExW and GetProcAddress
 * instead. Confirm with "dumpbin /imports" after changing this.
 */
#ifndef TLG_HAVE_EVENT_SET_INFORMATION
#define TLG_HAVE_EVENT_SET_INFORMATION 2
#endif

#include <windows.h>
#include <tchar.h>
#include <evntrace.h>
#include <TraceLoggingProvider.h>

/* Provider "Npcap", {5FED140C-C8A2-5A73-7B61-C3F3BBB00B48}. The GUID is the
 * standard hash of the provider name, so collection tools also accept
 * "*Npcap" and derive the GUID themselves. It is reproduced by
 * [System.Diagnostics.Tracing.EventSource]::new("Npcap").Guid; the name and
 * the GUID must be changed together.
 */
#define NPCAP_TRACE_PROVIDER_NAME "Npcap"

TRACELOGGING_DECLARE_PROVIDER(g_hNpcapTraceProvider);

/* Function entry and exit are high volume and of limited interest, so they
 * are logged above the level a caller receives by default.
 */
#define NPCAP_TRACE_LEVEL_SCOPE   TRACE_LEVEL_VERBOSE
#define NPCAP_TRACE_LEVEL_MESSAGE TRACE_LEVEL_INFORMATION

#ifdef __cplusplus
extern "C" {
#endif

/* Registration is idempotent, but ETW does not permit a registration and an
 * unregistration to run concurrently, so both belong in process startup and
 * shutdown only. A module that can be unloaded must unregister before it is
 * unmapped, because ETW retains a callback pointer into it.
 */
VOID NpcapTraceRegister(VOID);
VOID NpcapTraceUnregister(VOID);

VOID NpcapTraceEnter(_In_z_ LPCSTR Function);
VOID NpcapTraceExit(_In_z_ LPCSTR Function);
VOID NpcapTraceMessageA(_In_z_ LPCSTR Function, _In_z_ _Printf_format_string_ LPCSTR Format, ...);
VOID NpcapTraceMessageW(_In_z_ LPCSTR Function, _In_z_ _Printf_format_string_ LPCWSTR Format, ...);
VOID NpcapTraceOsInfo(VOID);

#ifdef __cplusplus
}
#endif

#ifdef UNICODE
#define NpcapTraceMessage NpcapTraceMessageW
#else
#define NpcapTraceMessage NpcapTraceMessageA
#endif

#define NpcapTraceEnabled(_Level) \
	TraceLoggingProviderEnabled(g_hNpcapTraceProvider, (_Level), 0)

/* Only the enabled test is inlined at the call site. Formatting and the
 * TraceLoggingWrite calls stay out of line in npcap_trace.c, which keeps the
 * event metadata that TraceLoggingWrite emits from being repeated at each of
 * the several hundred call sites.
 *
 * A build with the log file enabled has to record every call whether or not
 * a session is listening, so it omits the test.
 */
#if NPCAP_TRACE_TO_FILE

#define NPCAP_TRACE_ENTER_AT(_Function)	NpcapTraceEnter(_Function)
#define NPCAP_TRACE_EXIT_AT(_Function)	NpcapTraceExit(_Function)
#define NPCAP_TRACE_MSG(...)		NpcapTraceMessage(__FUNCTION__, __VA_ARGS__)
#define NPCAP_TRACE_MSGA(...)		NpcapTraceMessageA(__FUNCTION__, __VA_ARGS__)

#else // NPCAP_TRACE_TO_FILE

#define NPCAP_TRACE_ENTER_AT(_Function) \
	do { \
		if (NpcapTraceEnabled(NPCAP_TRACE_LEVEL_SCOPE)) \
			NpcapTraceEnter(_Function); \
	} while (0)

#define NPCAP_TRACE_EXIT_AT(_Function) \
	do { \
		if (NpcapTraceEnabled(NPCAP_TRACE_LEVEL_SCOPE)) \
			NpcapTraceExit(_Function); \
	} while (0)

#define NPCAP_TRACE_MSG(...) \
	do { \
		if (NpcapTraceEnabled(NPCAP_TRACE_LEVEL_MESSAGE)) \
			NpcapTraceMessage(__FUNCTION__, __VA_ARGS__); \
	} while (0)

/* For callers whose format strings and arguments are narrow regardless of the
 * project's character set.
 */
#define NPCAP_TRACE_MSGA(...) \
	do { \
		if (NpcapTraceEnabled(NPCAP_TRACE_LEVEL_MESSAGE)) \
			NpcapTraceMessageA(__FUNCTION__, __VA_ARGS__); \
	} while (0)

#endif // NPCAP_TRACE_TO_FILE

#define NPCAP_TRACE_ENTER() NPCAP_TRACE_ENTER_AT(__FUNCTION__)
#define NPCAP_TRACE_EXIT()  NPCAP_TRACE_EXIT_AT(__FUNCTION__)

#else // !NPCAP_TRACE_ENABLED

#define NpcapTraceRegister()
#define NpcapTraceUnregister()
#define NpcapTraceOsInfo()
#define NPCAP_TRACE_ENTER_AT(_Function)
#define NPCAP_TRACE_EXIT_AT(_Function)
#define NPCAP_TRACE_ENTER()
#define NPCAP_TRACE_EXIT()
#define NPCAP_TRACE_MSG(...)
#define NPCAP_TRACE_MSGA(...)

#endif // NPCAP_TRACE_ENABLED

#endif //__NPCAP_TRACE_H_5FED140CC8A25A737B61C3F3BBB00B48
