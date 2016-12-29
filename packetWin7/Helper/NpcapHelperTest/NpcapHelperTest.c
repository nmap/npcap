/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2016 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and my not be redistributed or incorporated    *
 * into other software without special permission from the Nmap Project.   *
 * We fund the Npcap project by selling a commercial license which allows  *
 * companies to redistribute Npcap with their products and also provides   *
 * for support, warranty, and indemnification rights.  For details on      *
 * obtaining such a license, please contact:                               *
 *                                                                         *
 * sales@nmap.com                                                          *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests.  However, we normally recommend that such  *
 * authors instead ask your users to download and install Npcap            *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  By sending these changes to the Nmap Project (including      *
 * through direct email or our mailing lists or submitting pull requests   *
 * through our source code repository), it is understood unless you        *
 * specify otherwise that you are offering the Nmap Project the            *
 * unlimited, non-exclusive right to reuse, modify, and relicence your     *
 * code contribution so that we may (but are not obligated to)             *
 * incorporate it into Npcap.  If you wish to specify special license      *
 * conditions or restrictions on your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
 * This header summarizes a few important aspects of the Npcap license,    *
 * but is not a substitute for the full Npcap license agreement, which is  *
 * in the LICENSE file included with Npcap and also available at           *
 * https://github.com/nmap/npcap/blob/master/LICENSE.                      *
 *                                                                         *
 ***************************************************************************/
/***************************************************************************
 * NpcapHelperTest.c -- A program used to test NpcapHelper.exe             *
 * Note: this code is now integrated into packet.dll, this file is only    *
 * used for test. This is for "Admin-only mode", as packet.dll runs on     *
 * non-Admin level and NpcapHelper.exe runs on Admin level. If user denies *
 * the UAC prompt, NpcapHelper.exe will not start.                         *
 *                                                                         *
 * This program is based on Microsoft example:                             *
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa365592%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa365588%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
 ***************************************************************************/

#include <stdio.h>
#include <windows.h>
//#define _DBG
#include "../debug.h"

#define BUFSIZE 512
#define MAX_SEM_COUNT 10
#define MAX_TRY_TIME 50
#define SLEEP_TIME 50
// Handle for NpcapHelper named pipe.
HANDLE g_NpcapHelperPipe = INVALID_HANDLE_VALUE;
// Whether this process is running in Administrator mode.
BOOL g_IsAdminMode = FALSE;
// Whether we have already tried NpcapHelper.
BOOL g_NpcapHelperTried = FALSE;
// The handle to this DLL.
HANDLE g_DllHandle = NULL;

BOOL NPcapCreatePipe(char *pipeName, HANDLE moduleName)
{
	int pid = GetCurrentProcessId();
	char params[BUFSIZE];
	SHELLEXECUTEINFOA shExInfo = {0};
	DWORD nResult;
	char lpFilename[BUFSIZE];
	char szDrive[BUFSIZE];
	char szDir[BUFSIZE];

	TRACE_ENTER("NPcapCreatePipe");

	// Get Path to This Module
	nResult = GetModuleFileNameA((HMODULE) moduleName, lpFilename, BUFSIZE);
	if (nResult == 0)
	{
		TRACE_PRINT1("GetModuleFileNameA failed. GLE=%d\n", GetLastError() ); 
		TRACE_EXIT("NPcapCreatePipe");
		return FALSE;
	}
	_splitpath_s(lpFilename, szDrive, BUFSIZE, szDir, BUFSIZE, NULL, 0, NULL, 0);
	_makepath_s(lpFilename, BUFSIZE, szDrive, szDir, "NpcapHelper", ".exe");

	sprintf_s(params, BUFSIZE, "%s %d", pipeName, pid);

	shExInfo.cbSize = sizeof(shExInfo);
	shExInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	shExInfo.hwnd = 0;
	shExInfo.lpVerb = "runas";				// Operation to perform
	shExInfo.lpFile = lpFilename;			// Application to start    
	shExInfo.lpParameters = params;			// Additional parameters
	shExInfo.lpDirectory = 0;
	shExInfo.nShow = SW_SHOW;
	shExInfo.hInstApp = 0;  

	if (!ShellExecuteExA(&shExInfo))
	{
		DWORD dwError = GetLastError();
		if (dwError == ERROR_CANCELLED)
		{
			// The user refused to allow privileges elevation.
			// Do nothing ...
		}
		TRACE_EXIT("NPcapCreatePipe");
		return FALSE;
	}
	else
	{
		TRACE_EXIT("NPcapCreatePipe");
		return TRUE;
		//		hChildProcess = shExInfo.hProcess;
		// 		WaitForSingleObject(shExInfo.hProcess, INFINITE);
		// 		CloseHandle(shExInfo.hProcess);
	}
}

HANDLE NPcapConnect(char *pipeName)
{
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	int tryTime = 0;
	char lpszPipename[BUFSIZE];

	TRACE_ENTER("NPcapConnect");

	sprintf_s(lpszPipename, BUFSIZE, "\\\\.\\pipe\\%s", pipeName);

	// Try to open a named pipe; wait for it, if necessary. 
	while (tryTime < MAX_TRY_TIME) 
	{ 
		hPipe = CreateFileA( 
			lpszPipename,   // pipe name 
			GENERIC_READ |  // read and write access 
			GENERIC_WRITE, 
			0,              // no sharing 
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe 
			0,              // default attributes 
			NULL);          // no template file 

		// Break if the pipe handle is valid. 

		if (hPipe != INVALID_HANDLE_VALUE)
		{
			break;
		}
		else
		{
			tryTime ++;
			Sleep(SLEEP_TIME);
		}

		// Exit if an error other than ERROR_PIPE_BUSY occurs. 

		// 		if (GetLastError() != ERROR_PIPE_BUSY) 
		// 		{
		// 			printf("Could not open pipe. GLE=%d\n", GetLastError());
		// 			return INVALID_HANDLE_VALUE;
		// 		}

		// 		// All pipe instances are busy, so wait for 20 seconds. 
		// 
		// 		if ( ! WaitNamedPipe(lpszPipename, 2000)) 
		// 		{ 
		// 			printf("Could not open pipe: 2 second wait timed out."); 
		// 			return INVALID_HANDLE_VALUE;
		// 		} 
	}

	TRACE_EXIT("NPcapConnect");
	return hPipe;
}

HANDLE NPcapRequestHandle(char *sMsg)
{
	LPSTR lpvMessage = sMsg; 
	char  chBuf[BUFSIZE]; 
	BOOL   fSuccess = FALSE; 
	DWORD  cbRead, cbToWrite, cbWritten, dwMode; 
	HANDLE hPipe = g_NpcapHelperPipe;

	TRACE_ENTER("NPcapRequestHandle");

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		TRACE_EXIT("NPcapRequestHandle");
		return INVALID_HANDLE_VALUE;
	}

	// The pipe connected; change to message-read mode. 
	dwMode = PIPE_READMODE_MESSAGE; 
	fSuccess = SetNamedPipeHandleState( 
		hPipe,    // pipe handle 
		&dwMode,  // new pipe mode 
		NULL,     // don't set maximum bytes 
		NULL);    // don't set maximum time 
	if ( ! fSuccess) 
	{
		TRACE_PRINT1("SetNamedPipeHandleState failed. GLE=%d\n", GetLastError() ); 
		TRACE_EXIT("NPcapRequestHandle");
		return INVALID_HANDLE_VALUE;
	}

	// Send a message to the pipe server. 

	cbToWrite = (DWORD) (strlen(lpvMessage) + 1) * sizeof(char);
	TRACE_PRINT2("\nSending %d byte message: \"%s\"\n", cbToWrite, lpvMessage); 

	fSuccess = WriteFile( 
		hPipe,                  // pipe handle 
		lpvMessage,             // message 
		cbToWrite,              // message length 
		&cbWritten,             // bytes written 
		NULL);                  // not overlapped 

	if ( ! fSuccess) 
	{
		TRACE_PRINT1("WriteFile to pipe failed. GLE=%d\n", GetLastError() ); 
		TRACE_EXIT("NPcapRequestHandle");
		return INVALID_HANDLE_VALUE;
	}

	TRACE_PRINT("Message sent to server, receiving reply as follows:\n");

	do 
	{ 
		// Read from the pipe. 

		fSuccess = ReadFile( 
			hPipe,    // pipe handle 
			chBuf,    // buffer to receive reply 
			BUFSIZE*sizeof(char),  // size of buffer 
			&cbRead,  // number of bytes read 
			NULL);    // not overlapped 

		if ( ! fSuccess && GetLastError() != ERROR_MORE_DATA )
			break; 

		//printf("\"%s\"\n", chBuf ); 
	} while ( ! fSuccess);  // repeat loop if ERROR_MORE_DATA 

	if ( ! fSuccess)
	{
		TRACE_PRINT1("ReadFile from pipe failed. GLE=%d\n", GetLastError() );
		TRACE_EXIT("NPcapRequestHandle");
		return INVALID_HANDLE_VALUE;
	}

	//printf("\n<End of message, press ENTER to terminate connection and exit\n>");
	if (cbRead != 0)
	{
		//int hd = atoi(chBuf);
		HANDLE hd = (HANDLE) strtoul(chBuf, NULL, 16);
		TRACE_PRINT1("Received Driver Handle: 0x%08x\n", hd);
		TRACE_EXIT("NPcapRequestHandle");
		return hd;
	}
	else
	{
		TRACE_EXIT("NPcapRequestHandle");
		return INVALID_HANDLE_VALUE;
	}
}

BOOL NPcapIsAdminMode()
{
	BOOL bIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;
	// Allocate and initialize a SID of the administrators group.
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

	TRACE_ENTER("NPcapIsAdminMode");

	if (!AllocateAndInitializeSid(
		&NtAuthority, 
		2, 
		SECURITY_BUILTIN_DOMAIN_RID, 
		DOMAIN_ALIAS_RID_ADMINS, 
		0, 0, 0, 0, 0, 0, 
		&pAdministratorsGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Determine whether the SID of administrators group is enabled in 
	// the primary access token of the process.
	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &bIsRunAsAdmin))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (pAdministratorsGroup)
	{
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		TRACE_PRINT1("IsProcessRunningAsAdminMode failed. GLE=%d\n", dwError);
	}

	TRACE_PRINT1("IsProcessRunningAsAdminMode result: %s\n", bIsRunAsAdmin? "yes" : "no");
	TRACE_EXIT("NPcapIsAdminMode");
	return bIsRunAsAdmin;
}

void NPcapStartHelper()
{
	TRACE_ENTER("NPcapStartHelper");

	g_NpcapHelperTried = TRUE;

	// Check if this process is running in Administrator mode.
	g_IsAdminMode = NPcapIsAdminMode();

	if (!g_IsAdminMode)
	{
		char pipeName[BUFSIZE];
		int pid = GetCurrentProcessId();
		sprintf_s(pipeName, BUFSIZE, "npcap-%d", pid);
		if (NPcapCreatePipe(pipeName, g_DllHandle))
		{
			g_NpcapHelperPipe = NPcapConnect(pipeName);
			if (g_NpcapHelperPipe == INVALID_HANDLE_VALUE)
			{
				// NpcapHelper failed, let g_IsAdminMode be TRUE to avoid next requestHandleFromNpcapHelper() calls.
				g_IsAdminMode = TRUE;
			}
		}
		else
		{
			// NpcapHelper failed, let g_IsAdminMode be TRUE to avoid next requestHandleFromNpcapHelper() calls.
			g_IsAdminMode = TRUE;
		}
	}

	TRACE_EXIT("NPcapStartHelper");
}

void NPcapStopHelper()
{
	TRACE_ENTER("NPcapStopHelper");

	if (g_NpcapHelperPipe != INVALID_HANDLE_VALUE)
	{
		CloseHandle(g_NpcapHelperPipe);
		g_NpcapHelperPipe = INVALID_HANDLE_VALUE;
	}

	TRACE_EXIT("NPcapStopHelper");
}

int main(int argc, char* argv[])
{
	HANDLE hFile;
	char SymbolicLink1[BUFSIZE] = "\\\\.\\Global\\NPCAP_{14AFDBFA-FD9E-48D4-8FF5-C7FD0EB924A4}";
	char SymbolicLink2[BUFSIZE] = "\\\\.\\Global\\NPCAP_{14AFDBFA-FD9E-48D4-1111-C7FD0EB924A5}";

	//g_DllHandle = DllHandle;

	// NpcapHelper Initialization, used for accessing the driver with Administrator privilege.
	if (!g_NpcapHelperTried)
	{
		NPcapStartHelper();
	}

	// do the job
	if (!g_IsAdminMode)
	{
		hFile = NPcapRequestHandle(SymbolicLink1);
	}
	else
	{
		hFile = CreateFileA(SymbolicLink1,GENERIC_WRITE | GENERIC_READ,
			0,NULL,OPEN_EXISTING,0,0);
	}
	if (!g_IsAdminMode)
	{
		hFile = NPcapRequestHandle(SymbolicLink2);
	}
	else
	{
		hFile = CreateFileA(SymbolicLink2,GENERIC_WRITE | GENERIC_READ,
			0,NULL,OPEN_EXISTING,0,0);
	}

	getchar();

	if (!g_IsAdminMode)
	{
		// NpcapHelper De-Initialization.
		NPcapStopHelper();
	}

	return 0;
}

