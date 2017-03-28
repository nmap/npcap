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
 * NpcapHelper.cpp -- A program used to fetch driver handles for packet.dll*
 * , it is started by packet.dll and uses Named Pipe to communicate with   *
 * packet.dll. This is for "Admin-only mode", as packet.dll runs on        *
 * non-Admin level and NpcapHelper.exe runs on Admin level. If user denies *
 * the UAC prompt, NpcapHelper.exe will not start.                         *
 *                                                                         *
 * This program is based on Microsoft example:                             *
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa365592%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa365588%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
 ***************************************************************************/

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <strsafe.h>
//#define _DBG
#include "../debug.h"

#define BUFSIZE 512

#pragma comment(linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")

int g_sourcePID = 0;

typedef struct _DeviceCache
{
	CHAR SymbolicLinkA[BUFSIZE];
	HANDLE handle;
	_DeviceCache *next;
} DeviceCache;

DeviceCache *g_DeviceCache = NULL;

DWORD WINAPI InstanceThread(LPVOID); 
VOID GetAnswerToRequest(LPSTR, LPSTR, LPDWORD); 


void terminateSelf()
{
	HANDLE hself = GetCurrentProcess();
	TerminateProcess(hself, 0);
}

HANDLE getDeviceHandleInternal(char *SymbolicLinkA, DWORD *pdwError)
{
	HANDLE hFile = CreateFileA(SymbolicLinkA, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
	HANDLE hFileDup;
	DWORD dwError;
	BOOL bResult;
	HANDLE hClientProcess;

	TRACE_PRINT1("Original handle: %08p.\n", hFile);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		*pdwError = dwError = GetLastError();
		TRACE_PRINT1("CreateFileA failed, GLE=%d.\n", dwError);
		return INVALID_HANDLE_VALUE;
	}
	hClientProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, g_sourcePID);
	if (hClientProcess == NULL)
	{
		*pdwError = dwError = GetLastError();
		TRACE_PRINT1("OpenProcess failed, GLE=%d.\n", dwError);
		return INVALID_HANDLE_VALUE;
	}

	bResult = DuplicateHandle(GetCurrentProcess(), 
		hFile, 
		hClientProcess,
		&hFileDup, 
		GENERIC_WRITE | GENERIC_READ,
		FALSE,
		DUPLICATE_CLOSE_SOURCE);
	TRACE_PRINT1("Duplicated handle: %08p.\n", hFileDup);

	if (!bResult)
	{
		TRACE_PRINT1("CreateNamedPipe failed, GLE=%d.\n", GetLastError());
		*pdwError = 1234;
		return INVALID_HANDLE_VALUE;
	}
	else
	{
		*pdwError = 0;
		return hFileDup;
	}
}

BOOL createPipe(char *pipeName)
{
	BOOL   fConnected = FALSE; 
	DWORD  dwThreadId = 0; 
	HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL; 
	char lpszPipename[BUFSIZE];
	sprintf_s(lpszPipename, BUFSIZE, "\\\\.\\pipe\\%s", pipeName);

	// The main loop creates an instance of the named pipe and 
	// then waits for a client to connect to it. When the client 
	// connects, a thread is created to handle communications 
	// with that client, and this loop is free to wait for the
	// next client connect request. It is an infinite loop.

	for (;;) 
	{ 
		SECURITY_DESCRIPTOR sd;
		InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorDacl(&sd, TRUE, 0, FALSE);
		SECURITY_ATTRIBUTES sa = { sizeof sa, &sd, FALSE };

		TRACE_PRINT1("\nPipe Server: Main thread awaiting client connection on %s\n", lpszPipename);
		hPipe = CreateNamedPipeA( 
			lpszPipename,             // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_MESSAGE |       // message type pipe 
			PIPE_READMODE_MESSAGE |   // message-read mode 
			PIPE_WAIT,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFSIZE,                  // output buffer size 
			BUFSIZE,                  // input buffer size 
			0,                        // client time-out 
			&sa);                    // default security attribute 

		if (hPipe == INVALID_HANDLE_VALUE) 
		{
			TRACE_PRINT1("CreateNamedPipe failed, GLE=%d.\n", GetLastError());
			return FALSE;
		}

		// Wait for the client to connect; if it succeeds, 
		// the function returns a nonzero value. If the function
		// returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 

		fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 

		if (fConnected) 
		{ 
			TRACE_PRINT("Client connected, creating a processing thread.\n");

			// Create a thread for this client. 
			hThread = CreateThread( 
				NULL,              // no security attribute 
				0,                 // default stack size 
				InstanceThread,    // thread proc
				(LPVOID) hPipe,    // thread parameter 
				0,                 // not suspended 
				&dwThreadId);      // returns thread ID 

			if (hThread == NULL) 
			{
				TRACE_PRINT1("CreateThread failed, GLE=%d.\n", GetLastError());
				return FALSE;
			}
			else CloseHandle(hThread); 
		} 
		else 
			// The client could not connect, so close the pipe. 
			CloseHandle(hPipe); 
	} 

	return TRUE; 
}

DWORD WINAPI InstanceThread(LPVOID lpvParam)
// This routine is a thread processing function to read from and reply to a client
// via the open pipe connection passed from the main loop. Note this allows
// the main loop to continue executing, potentially creating more threads of
// of this procedure to run concurrently, depending on the number of incoming
// client connections.
{ 
	HANDLE hHeap      = GetProcessHeap();
	char* pchRequest = (char*) HeapAlloc(hHeap, 0, BUFSIZE * sizeof(char));
	char* pchReply   = (char*) HeapAlloc(hHeap, 0, BUFSIZE * sizeof(char));

	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0; 
	BOOL fSuccess = FALSE;
	HANDLE hPipe  = NULL;
	TRACE_ENTER();

	// Do some extra error checking since the app will keep running even if this
	// thread fails.

	if (lpvParam == NULL)
	{
		TRACE_PRINT( "\nERROR - Pipe Server Failure:\n");
		TRACE_PRINT( "   InstanceThread got an unexpected NULL value in lpvParam.\n");
		TRACE_PRINT( "   InstanceThread exitting.\n");
		if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
		if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
		return (DWORD)-1;
	}

	if (pchRequest == NULL)
	{
		TRACE_PRINT( "\nERROR - Pipe Server Failure:\n");
		TRACE_PRINT( "   InstanceThread got an unexpected NULL heap allocation.\n");
		TRACE_PRINT( "   InstanceThread exitting.\n");
		if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
		return (DWORD)-1;
	}

	if (pchReply == NULL)
	{
		TRACE_PRINT( "\nERROR - Pipe Server Failure:\n");
		TRACE_PRINT( "   InstanceThread got an unexpected NULL heap allocation.\n");
		TRACE_PRINT( "   InstanceThread exitting.\n");
		if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
		return (DWORD)-1;
	}

	// Print verbose messages. In production code, this should be for debugging only.
	TRACE_PRINT("InstanceThread created, receiving and processing messages.\n");

	// The thread's parameter is a handle to a pipe object instance. 

	hPipe = (HANDLE) lpvParam; 

	// Loop until done reading
	while (1) 
	{ 
		// Read client requests from the pipe. This simplistic code only allows messages
		// up to BUFSIZE characters in length.
		fSuccess = ReadFile( 
			hPipe,        // handle to pipe 
			pchRequest,    // buffer to receive data 
			BUFSIZE*sizeof(TCHAR), // size of buffer 
			&cbBytesRead, // number of bytes read 
			NULL);        // not overlapped I/O 

		if (!fSuccess || cbBytesRead == 0)
		{   
			if (GetLastError() == ERROR_BROKEN_PIPE)
			{
				TRACE_PRINT("InstanceThread: client disconnected.\n");
			}
			else
			{
				TRACE_PRINT1("InstanceThread ReadFile failed, GLE=%d.\n", GetLastError());
			}
			break;
		}

		// Process the incoming message.
		GetAnswerToRequest(pchRequest, pchReply, &cbReplyBytes); 

		// Write the reply to the pipe. 
		fSuccess = WriteFile( 
			hPipe,        // handle to pipe 
			pchReply,     // buffer to write from 
			cbReplyBytes, // number of bytes to write 
			&cbWritten,   // number of bytes written 
			NULL);        // not overlapped I/O 

		if (!fSuccess || cbReplyBytes != cbWritten)
		{   
			TRACE_PRINT1("InstanceThread WriteFile failed, GLE=%d.\n", GetLastError());
			break;
		}
	}

	// Flush the pipe to allow the client to read the pipe's contents 
	// before disconnecting. Then disconnect the pipe, and close the 
	// handle to this pipe instance. 

	FlushFileBuffers(hPipe); 
	DisconnectNamedPipe(hPipe); 
	CloseHandle(hPipe); 

	HeapFree(hHeap, 0, pchRequest);
	HeapFree(hHeap, 0, pchReply);

	TRACE_EXIT();
	terminateSelf();
	return 1;
}

VOID GetAnswerToRequest( LPSTR pchRequest, 
						LPSTR pchReply, 
						LPDWORD pchBytes )
						// This routine is a simple function to print the client request to the console
						// and populate the reply buffer with a default data string. This is where you
						// would put the actual client request processing code that runs in the context
						// of an instance thread. Keep in mind the main thread will continue to wait for
						// and receive other client connections while the instance thread is working.
{
	TRACE_PRINT1("Client Request String:\"%s\"\n", pchRequest);

	DWORD dwError;
	HANDLE hFile = getDeviceHandleInternal(pchRequest, &dwError);
	TRACE_PRINT1("Driver Handle: %0p\n", hFile);
	if (hFile)
	{
		char buf[BUFSIZE];
		sprintf_s(buf, BUFSIZE, "%p,%d", hFile, dwError);
		strcpy_s(pchReply, BUFSIZE, buf);
		*pchBytes = (DWORD) strlen(buf) * sizeof(char);
	}
	else
	{
		// Check the outgoing message to make sure it's not too long for the buffer.
		if (FAILED(StringCchCopyA( pchReply, BUFSIZE, "default answer from server")))
		{
			*pchBytes = 0;
			pchReply[0] = 0;
			TRACE_PRINT("StringCchCopy failed, no outgoing message.\n");
			return;
		}
		*pchBytes = (DWORD) (strlen(pchReply) + 1) * sizeof(char);
	}
}

int main(int argc, char* argv[])
{
	char *pipeName = NULL;
	if (argc != 3)
	{
		return -1;
	}
	else
	{
		pipeName = argv[1];
		g_sourcePID = atoi(argv[2]);
	}

	createPipe(pipeName);

	getchar();
	return 0;
}

