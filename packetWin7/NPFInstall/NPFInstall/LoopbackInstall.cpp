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
/*++

Module Name:

    LoopbackInstall.cpp

Abstract:

    Device Console
    command-line interface for managing devices

--*/

#include "LoopbackInstall.h"
#include "LoopbackRecord.h"
#include "LoopbackRename2.h"

#include "debug.h"

#include <shlobj.h>
#include <ntddndis.h>

#define BUF_SIZE 255
#define ADAPTER_SIZE 255

#define FIND_DEVICE         0x00000001 // display device
#define FIND_STATUS         0x00000002 // display status of device
#define FIND_RESOURCES      0x00000004 // display resources of device
#define FIND_DRIVERFILES    0x00000008 // display drivers used by device
#define FIND_HWIDS          0x00000010 // display hw/compat id's used by device
#define FIND_DRIVERNODES    0x00000020 // display driver nodes for a device.
#define FIND_CLASS          0x00000040 // display device's setup class
#define FIND_STACK          0x00000080 // display device's driver-stack

#define INSTANCEID_PREFIX_CHAR TEXT('@') // character used to prefix instance ID's
#define CLASS_PREFIX_CHAR      TEXT('=') // character used to prefix class name
#define WILD_CHAR              TEXT('*') // wild character
#define QUOTE_PREFIX_CHAR      TEXT('\'') // prefix character to ignore wild characters
#define SPLIT_COMMAND_SEP      TEXT(":=") // whole word, indicates end of id's

struct GenericContext {
	DWORD count;
	DWORD control;
	BOOL  reboot;
	LPCTSTR strSuccess;
	LPCTSTR strReboot;
	LPCTSTR strFail;
};

struct IdEntry {
	LPCTSTR String;     // string looking for
	LPCTSTR Wild;       // first wild character if any
	BOOL    InstanceId;
};

int g_DevInstanceID = -1;

BOOL g_DevIDPreEnabled = TRUE;

int g_DevIDCount = 0;
int g_DevIDs[ADAPTER_SIZE] = {-1};

int g_DevIDCount_Pre = 0;
int g_DevIDs_Pre[ADAPTER_SIZE] = {-1};

void addDevID(int iDevID)
{
	if (g_DevIDCount < ADAPTER_SIZE - 1)
	{
		g_DevIDs[g_DevIDCount ++] = iDevID;
	}
}

void addDevID(TCHAR strDevID[]) //DevID is in form like: "ROOT\\NET\\0008"
{
	int iDevID;
	_stscanf_s(strDevID, _T("ROOT\\NET\\%04d"), &iDevID);
	addDevID(iDevID);
}

void addDevID_Pre(int iDevID)
{
	if (g_DevIDCount_Pre < ADAPTER_SIZE - 1)
	{
		g_DevIDs_Pre[g_DevIDCount_Pre ++] = iDevID;
	}
}

void addDevID_Pre(TCHAR strDevID[]) //DevID is in form like: "ROOT\\NET\\0008"
{
	int iDevID;
	_stscanf_s(strDevID, _T("ROOT\\NET\\%04d"), &iDevID);
	addDevID_Pre(iDevID);
}

int getNpcapLoopbackAdapterID()
{
	TRACE_ENTER();

	if (g_DevIDCount == g_DevIDCount_Pre)
	{
		TRACE_PRINT1("getNpcapLoopbackAdapterID: error, g_DevIDCount = g_DevIDCount_Pre = 0x%d.", g_DevIDCount);
		TRACE_EXIT();
		return -1;
	}

	for (int i = 0; i < g_DevIDCount; i ++)
	{
		int found = 0;
		for (int j = 0; j < g_DevIDCount_Pre; j ++)
		{
			if (g_DevIDs[i] == g_DevIDs_Pre[j])
			{
				found = 1;
				break;
			}
		}
		if (found == 0)
		{
			TRACE_PRINT1("getNpcapLoopbackAdapterID: succeed, g_DevIDs[i] = 0x%d.", g_DevIDs[i]);
			TRACE_EXIT();
			return g_DevIDs[i];
		}
	}

	TRACE_PRINT2("getNpcapLoopbackAdapterID: error, g_DevIDCount = 0x%d, g_DevIDCount_Pre = 0x%d.", g_DevIDCount, g_DevIDCount_Pre);
	TRACE_EXIT();
	return -1;
}

void FormatToStream(_In_ FILE * stream, _In_ DWORD fmt,...)
/*++

Routine Description:

    Format text to stream using a particular msg-id fmt
    Used for displaying localizable messages

Arguments:

    stream              - file stream to output to, stdout or stderr
    fmt                 - message id
    ...                 - parameters %1...

Return Value:

    none

--*/
{
    va_list arglist;
    LPTSTR locbuffer = NULL;
    DWORD count;

    va_start(arglist, fmt);
    count = FormatMessage(FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_ALLOCATE_BUFFER,
                          NULL,
                          fmt,
                          0,              // LANGID
                          (LPTSTR) &locbuffer,
                          0,              // minimum size of buffer
                          &arglist);

    if(locbuffer) {
        if(count) {
            int c;
            int back = 0;
            //
            // strip any trailing "\r\n"s and replace by a single "\n"
            //
            while(((c = *CharPrev(locbuffer,locbuffer+count)) == TEXT('\r')) ||
                  (c == TEXT('\n'))) {
                count--;
                back++;
            }
            if(back) {
                locbuffer[count++] = TEXT('\n');
                locbuffer[count] = TEXT('\0');
            }
            //
            // now write to apropriate stream
            //
            _fputts(locbuffer,stream);
        }
        LocalFree(locbuffer);
    }
}

IdEntry GetIdType(_In_ LPCTSTR Id)
/*++

Routine Description:

    Determine if this is instance id or hardware id and if there's any wildcards
    instance ID is prefixed by '@'
    wildcards are '*'


Arguments:

    Id - ptr to string to check

Return Value:

    IdEntry

--*/
{
    IdEntry Entry;

    Entry.InstanceId = FALSE;
    Entry.Wild = NULL;
    Entry.String = Id;

    if(Entry.String[0] == INSTANCEID_PREFIX_CHAR) {
        Entry.InstanceId = TRUE;
        Entry.String = CharNext(Entry.String);
    }
    if(Entry.String[0] == QUOTE_PREFIX_CHAR) {
        //
        // prefix to treat rest of string literally
        //
        Entry.String = CharNext(Entry.String);
    } else {
        //
        // see if any wild characters exist
        //
        Entry.Wild = _tcschr(Entry.String,WILD_CHAR);
    }
    return Entry;
}

__drv_allocatesMem(object)
LPTSTR * GetMultiSzIndexArray(_In_ __drv_aliasesMem LPTSTR MultiSz)
/*++

Routine Description:

    Get an index array pointing to the MultiSz passed in

Arguments:

    MultiSz - well formed multi-sz string

Return Value:

    array of strings. last entry+1 of array contains NULL
    returns NULL on failure

--*/
{
    LPTSTR scan;
    LPTSTR * array;
    int elements;

    for(scan = MultiSz, elements = 0; scan[0] ;elements++) {
        scan += lstrlen(scan)+1;
    }
    array = new LPTSTR[elements+2];
    if(!array) {
        return NULL;
    }
    array[0] = MultiSz;
    array++;
    if(elements) {
        for(scan = MultiSz, elements = 0; scan[0]; elements++) {
            array[elements] = scan;
            scan += lstrlen(scan)+1;
        }
    }
    array[elements] = NULL;
    return array;
}

BOOL WildCardMatch(_In_ LPCTSTR Item, _In_ const IdEntry & MatchEntry)
/*++

Routine Description:

    Compare a single item against wildcard
    I'm sure there's better ways of implementing this
    Other than a command-line management tools
    it's a bad idea to use wildcards as it implies
    assumptions about the hardware/instance ID
    eg, it might be tempting to enumerate root\* to
    find all root devices, however there is a CfgMgr
    API to query status and determine if a device is
    root enumerated, which doesn't rely on implementation
    details.

Arguments:

    Item - item to find match for eg a\abcd\c
    MatchEntry - eg *\*bc*\*

Return Value:

    TRUE if any match, otherwise FALSE

--*/
{
    LPCTSTR scanItem;
    LPCTSTR wildMark;
    LPCTSTR nextWild;
    size_t matchlen;

    //
    // before attempting anything else
    // try and compare everything up to first wild
    //
    if(!MatchEntry.Wild) {
        return _tcsicmp(Item,MatchEntry.String) ? FALSE : TRUE;
    }
    if(_tcsnicmp(Item,MatchEntry.String,MatchEntry.Wild-MatchEntry.String) != 0) {
        return FALSE;
    }
    wildMark = MatchEntry.Wild;
    scanItem = Item + (MatchEntry.Wild-MatchEntry.String);

    for(;wildMark[0];) {
        //
        // if we get here, we're either at or past a wildcard
        //
        if(wildMark[0] == WILD_CHAR) {
            //
            // so skip wild chars
            //
            wildMark = CharNext(wildMark);
            continue;
        }
        //
        // find next wild-card
        //
        nextWild = _tcschr(wildMark,WILD_CHAR);
        if(nextWild) {
            //
            // substring
            //
            matchlen = nextWild-wildMark;
        } else {
            //
            // last portion of match
            //
            size_t scanlen = lstrlen(scanItem);
            matchlen = lstrlen(wildMark);
            if(scanlen < matchlen) {
                return FALSE;
            }
            return _tcsicmp(scanItem+scanlen-matchlen,wildMark) ? FALSE : TRUE;
        }
        if(_istalpha(wildMark[0])) {
            //
            // scan for either lower or uppercase version of first character
            //

            //
            // the code suppresses the warning 28193 for the calls to _totupper
            // and _totlower.  This suppression is done because those functions
            // have a check return annotation on them.  However, they don't return
            // error codes and the check return annotation is really being used
            // to indicate that the return value of the function should be looked
            // at and/or assigned to a variable.  The check return annotation means
            // the return value should always be checked in all code paths.
            // We assign the return values to variables but the while loop does not 
            // examine both values in all code paths (e.g. when scanItem[0] == 0, 
            // neither u nor l will be examined) and it doesn't need to examine 
            // the values in all code paths.
            //
#pragma warning( suppress: 28193)
            TCHAR u = _totupper(wildMark[0]);
#pragma warning( suppress: 28193)
            TCHAR l = _totlower(wildMark[0]);
            while(scanItem[0] && scanItem[0]!=u && scanItem[0]!=l) {
                scanItem = CharNext(scanItem);
            }
            if(!scanItem[0]) {
                //
                // ran out of string
                //
                return FALSE;
            }
        } else {
            //
            // scan for first character (no case)
            //
            scanItem = _tcschr(scanItem,wildMark[0]);
            if(!scanItem) {
                //
                // ran out of string
                //
                return FALSE;
            }
        }
        //
        // try and match the sub-string at wildMark against scanItem
        //
        if(_tcsnicmp(scanItem,wildMark,matchlen)!=0) {
            //
            // nope, try again
            //
            scanItem = CharNext(scanItem);
            continue;
        }
        //
        // substring matched
        //
        scanItem += matchlen;
        wildMark += matchlen;
    }
    return (wildMark[0] ? FALSE : TRUE);
}

__drv_allocatesMem(object)
LPTSTR * GetDevMultiSz(_In_ HDEVINFO Devs, _In_ PSP_DEVINFO_DATA DevInfo, _In_ DWORD Prop)
/*++

Routine Description:

    Get a multi-sz device property
    and return as an array of strings

Arguments:

    Devs    - HDEVINFO containing DevInfo
    DevInfo - Specific device
    Prop    - SPDRP_HARDWAREID or SPDRP_COMPATIBLEIDS

Return Value:

    array of strings. last entry+1 of array contains NULL
    returns NULL on failure

--*/
{
    LPTSTR buffer;
    DWORD size;
    DWORD reqSize;
    DWORD dataType;
    LPTSTR * array;
    DWORD szChars;

    size = 8192; // initial guess, nothing magic about this
    buffer = new TCHAR[(size/sizeof(TCHAR))+2];
    if(!buffer) {
        return NULL;
    }
    while(!SetupDiGetDeviceRegistryProperty(Devs,DevInfo,Prop,&dataType,(LPBYTE)buffer,size,&reqSize)) {
        if(GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            goto failed;
        }
        if(dataType != REG_MULTI_SZ) {
            goto failed;
        }
        size = reqSize;
        delete [] buffer;
        buffer = new TCHAR[(size/sizeof(TCHAR))+2];
        if(!buffer) {
            goto failed;
        }
    }
    szChars = reqSize/sizeof(TCHAR);
    buffer[szChars] = TEXT('\0');
    buffer[szChars+1] = TEXT('\0');
    array = GetMultiSzIndexArray(buffer);
    if(array) {
        return array;
    }

failed:
    if(buffer) {
        delete [] buffer;
    }
    return NULL;
}

void DelMultiSz(_In_opt_ __drv_freesMem(object) PZPWSTR Array)
/*++

Routine Description:

    Deletes the string array allocated by GetDevMultiSz/GetRegMultiSz/GetMultiSzIndexArray

Arguments:

    Array - pointer returned by GetMultiSzIndexArray

Return Value:

    None

--*/
{
    if(Array) {
        Array--;
        if(Array[0]) {
            delete [] Array[0];
        }
        delete [] Array;
    }
}

BOOL WildCompareHwIds(_In_ PZPWSTR Array, _In_ const IdEntry & MatchEntry)
/*++

Routine Description:

    Compares all strings in Array against Id
    Use WildCardMatch to do real compare

Arguments:

    Array - pointer returned by GetDevMultiSz
    MatchEntry - string to compare against

Return Value:

    TRUE if any match, otherwise FALSE

--*/
{
    if(Array) {
        while(Array[0]) {
            if(WildCardMatch(Array[0],MatchEntry)) {
                return TRUE;
            }
            Array++;
        }
    }
    return FALSE;
}

int EnumerateDevices(_In_ LPCTSTR BaseName, _In_opt_ LPCTSTR Machine, _In_ DWORD Flags, _In_ int argc, _In_reads_(argc) PWSTR* argv, _In_ CallbackFunc Callback, _In_ LPVOID Context)
/*++

Routine Description:

    Generic enumerator for devices that will be passed the following arguments:
    <id> [<id>...]
    =<class> [<id>...]
    where <id> can either be @instance-id, or hardware-id and may contain wildcards
    <class> is a class name

Arguments:

    BaseName - name of executable
    Machine  - name of machine to enumerate
    Flags    - extra enumeration flags (eg DIGCF_PRESENT)
    argc/argv - remaining arguments on command line
    Callback - function to call for each hit
    Context  - data to pass function for each hit

Return Value:

    EXIT_xxxx

--*/
{
	TRACE_ENTER();

    HDEVINFO devs = INVALID_HANDLE_VALUE;
    IdEntry * templ = NULL;
    int failcode = EXIT_FAIL;
    int retcode;
    int argIndex;
    DWORD devIndex;
    SP_DEVINFO_DATA devInfo;
    SP_DEVINFO_LIST_DETAIL_DATA devInfoListDetail;
    BOOL doSearch = FALSE;
    BOOL match;
    BOOL all = FALSE;
    GUID cls;
    DWORD numClass = 0;
    int skip = 0;

    UNREFERENCED_PARAMETER(BaseName);

    if(!argc) {
		TRACE_EXIT();
        return EXIT_USAGE;
    }

    templ = new IdEntry[argc];
    if(!templ) {
        goto final;
    }

    //
    // determine if a class is specified
    //
    if(argc>skip && argv[skip][0]==CLASS_PREFIX_CHAR && argv[skip][1]) {
        if(!SetupDiClassGuidsFromNameEx(argv[skip]+1,&cls,1,&numClass,Machine,NULL) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            goto final;
        }
        if(!numClass) {
            failcode = EXIT_OK;
            goto final;
        }
        skip++;
    }
    if(argc>skip && argv[skip][0]==WILD_CHAR && !argv[skip][1]) {
        //
        // catch convinient case of specifying a single argument '*'
        //
        all = TRUE;
        skip++;
    } else if(argc<=skip) {
        //
        // at least one parameter, but no <id>'s
        //
        all = TRUE;
    }

    //
    // determine if any instance id's were specified
    //
    // note, if =<class> was specified with no id's
    // we'll mark it as not doSearch
    // but will go ahead and add them all
    //
    for(argIndex=skip;argIndex<argc;argIndex++) {
        templ[argIndex] = GetIdType(argv[argIndex]);
        if(templ[argIndex].Wild || !templ[argIndex].InstanceId) {
            //
            // anything other than simple InstanceId's require a search
            //
            doSearch = TRUE;
        }
    }
    if(doSearch || all) {
        //
        // add all id's to list
        // if there's a class, filter on specified class
        //
        devs = SetupDiGetClassDevsEx(numClass ? &cls : NULL,
                                     NULL,
                                     NULL,
                                     (numClass ? 0 : DIGCF_ALLCLASSES) | Flags,
                                     NULL,
                                     Machine,
                                     NULL);

    } else {
        //
        // blank list, we'll add instance id's by hand
        //
        devs = SetupDiCreateDeviceInfoListEx(numClass ? &cls : NULL,
                                             NULL,
                                             Machine,
                                             NULL);
    }
    if(devs == INVALID_HANDLE_VALUE) {
        goto final;
    }
    for(argIndex=skip;argIndex<argc;argIndex++) {
        //
        // add explicit instances to list (even if enumerated all,
        // this gets around DIGCF_PRESENT)
        // do this even if wildcards appear to be detected since they
        // might actually be part of the instance ID of a non-present device
        //
        if(templ[argIndex].InstanceId) {
            SetupDiOpenDeviceInfo(devs,templ[argIndex].String,NULL,0,NULL);
        }
    }

    devInfoListDetail.cbSize = sizeof(devInfoListDetail);
    if(!SetupDiGetDeviceInfoListDetail(devs,&devInfoListDetail)) {
        goto final;
    }

    //
    // now enumerate them
    //
    if(all) {
        doSearch = FALSE;
    }

    devInfo.cbSize = sizeof(devInfo);
    for(devIndex=0;SetupDiEnumDeviceInfo(devs,devIndex,&devInfo);devIndex++) {

        if(doSearch) {
            for(argIndex=skip,match=FALSE;(argIndex<argc) && !match;argIndex++) {
                TCHAR devID[MAX_DEVICE_ID_LEN];
                LPTSTR *hwIds = NULL;
                LPTSTR *compatIds = NULL;
                //
                // determine instance ID
                //
                if(CM_Get_Device_ID_Ex(devInfo.DevInst,devID,MAX_DEVICE_ID_LEN,0,devInfoListDetail.RemoteMachineHandle)!=CR_SUCCESS) {
                    devID[0] = TEXT('\0');
                }

                if(templ[argIndex].InstanceId) {
                    //
                    // match on the instance ID
                    //
                    if(WildCardMatch(devID,templ[argIndex])) {
                        match = TRUE;
                    }
                } else {
                    //
                    // determine hardware ID's
                    // and search for matches
                    //
                    hwIds = GetDevMultiSz(devs,&devInfo,SPDRP_HARDWAREID);
                    compatIds = GetDevMultiSz(devs,&devInfo,SPDRP_COMPATIBLEIDS);

                    if(WildCompareHwIds(hwIds,templ[argIndex]) ||
                        WildCompareHwIds(compatIds,templ[argIndex])) {
                        match = TRUE;
                    }
                }
                DelMultiSz(hwIds);
                DelMultiSz(compatIds);
            }
        } else {
            match = TRUE;
        }
        if(match) {
            retcode = Callback(devs,&devInfo,devIndex,Context);
            if(retcode) {
                failcode = retcode;
                goto final;
            }
        }
    }

    failcode = EXIT_OK;

final:
    if(templ) {
        delete [] templ;
    }
    if(devs != INVALID_HANDLE_VALUE) {
        SetupDiDestroyDeviceInfoList(devs);
    }

	TRACE_PRINT1("EnumerateDevices: failcode = 0x%d.", failcode);
	TRACE_EXIT();
    return failcode;

}

BOOL DumpDeviceWithInfo(_In_ HDEVINFO Devs, _In_ PSP_DEVINFO_DATA DevInfo, _In_opt_ LPCTSTR Info)
/*++

Routine Description:

    Write device instance & info to stdout

Arguments:

    Devs    )_ uniquely identify device
    DevInfo )

Return Value:

    none

--*/
{
    TCHAR devID[MAX_DEVICE_ID_LEN];
    BOOL b = TRUE;
    SP_DEVINFO_LIST_DETAIL_DATA devInfoListDetail;

    devInfoListDetail.cbSize = sizeof(devInfoListDetail);
    if((!SetupDiGetDeviceInfoListDetail(Devs,&devInfoListDetail)) ||
            (CM_Get_Device_ID_Ex(DevInfo->DevInst,devID,MAX_DEVICE_ID_LEN,0,devInfoListDetail.RemoteMachineHandle)!=CR_SUCCESS)) {
        _tcscpy_s(devID, ARRAYSIZE(devID), TEXT("?"));
        b = FALSE;
    }

	if (g_DevIDPreEnabled)
	{
		addDevID_Pre(devID);
	}
	else
	{
		addDevID(devID);
	}

    if(Info) {
        _tprintf(TEXT("%-60s: %s\n"),devID,Info);
    } else {
        _tprintf(TEXT("%s\n"),devID);
    }
    return b;
}

int FindCallback(_In_ HDEVINFO Devs, _In_ PSP_DEVINFO_DATA DevInfo, _In_ DWORD Index, _In_ LPVOID Context)
/*++

Routine Description:

    Callback for use by Find/FindAll
    just simply display the device

Arguments:

    Devs    )_ uniquely identify the device
    DevInfo )
    Index    - index of device
    Context  - GenericContext

Return Value:

    EXIT_xxxx

--*/
{
    GenericContext *pFindContext = (GenericContext*)Context;

    UNREFERENCED_PARAMETER(Index);

//     if(!pFindContext->control) {
//         DumpDevice(Devs,DevInfo);
//         pFindContext->count++;
//         return EXIT_OK;
//     }
    if(!DumpDeviceWithInfo(Devs,DevInfo,NULL)) {
        return EXIT_OK;
    }
//     if(pFindContext->control&FIND_DEVICE) {
//         DumpDeviceDescr(Devs,DevInfo);
//     }
//     if(pFindContext->control&FIND_CLASS) {
//         DumpDeviceClass(Devs,DevInfo);
//     }
//     if(pFindContext->control&FIND_STATUS) {
//         DumpDeviceStatus(Devs,DevInfo);
//     }
//     if(pFindContext->control&FIND_RESOURCES) {
//         DumpDeviceResources(Devs,DevInfo);
//     }
//     if(pFindContext->control&FIND_DRIVERFILES) {
//         DumpDeviceDriverFiles(Devs,DevInfo);
//     }
//     if(pFindContext->control&FIND_STACK) {
//         DumpDeviceStack(Devs,DevInfo);
//     }
//     if(pFindContext->control&FIND_HWIDS) {
//         DumpDeviceHwIds(Devs,DevInfo);
//     }
//     if (pFindContext->control&FIND_DRIVERNODES) {
//         DumpDeviceDriverNodes(Devs,DevInfo);
//     }
    pFindContext->count++;
    return EXIT_OK;
}

int RemoveCallback(_In_ HDEVINFO Devs, _In_ PSP_DEVINFO_DATA DevInfo, _In_ DWORD Index, _In_ LPVOID Context)
/*++

Routine Description:

    Callback for use by Remove
    Invokes DIF_REMOVE
    uses SetupDiCallClassInstaller so cannot be done for remote devices
    Don't use CM_xxx API's, they bypass class/co-installers and this is bad.

Arguments:

    Devs    )_ uniquely identify the device
    DevInfo )
    Index    - index of device
    Context  - GenericContext

Return Value:

    EXIT_xxxx

--*/
{
    SP_REMOVEDEVICE_PARAMS rmdParams;
    GenericContext *pControlContext = (GenericContext*)Context;
    SP_DEVINSTALL_PARAMS devParams;
    LPCTSTR action = NULL;
    //
    // need hardware ID before trying to remove, as we wont have it after
    //
    TCHAR devID[MAX_DEVICE_ID_LEN];
    SP_DEVINFO_LIST_DETAIL_DATA devInfoListDetail;

    UNREFERENCED_PARAMETER(Index);

    devInfoListDetail.cbSize = sizeof(devInfoListDetail);
    if((!SetupDiGetDeviceInfoListDetail(Devs,&devInfoListDetail)) ||
            (CM_Get_Device_ID_Ex(DevInfo->DevInst,devID,MAX_DEVICE_ID_LEN,0,devInfoListDetail.RemoteMachineHandle)!=CR_SUCCESS)) {
        //
        // skip this
        //
        return EXIT_OK;
    }

    rmdParams.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    rmdParams.ClassInstallHeader.InstallFunction = DIF_REMOVE;
    rmdParams.Scope = DI_REMOVEDEVICE_GLOBAL;
    rmdParams.HwProfile = 0;
    if(!SetupDiSetClassInstallParams(Devs,DevInfo,&rmdParams.ClassInstallHeader,sizeof(rmdParams)) ||
       !SetupDiCallClassInstaller(DIF_REMOVE,Devs,DevInfo)) {
        //
        // failed to invoke DIF_REMOVE
        //
        action = pControlContext->strFail;
    } else {
        //
        // see if device needs reboot
        //
        devParams.cbSize = sizeof(devParams);
        if(SetupDiGetDeviceInstallParams(Devs,DevInfo,&devParams) && (devParams.Flags & (DI_NEEDRESTART|DI_NEEDREBOOT))) {
            //
            // reboot required
            //
            action = pControlContext->strReboot;
            pControlContext->reboot = TRUE;
        } else {
            //
            // appears to have succeeded
            //
            action = pControlContext->strSuccess;
        }
        pControlContext->count++;
    }
    _tprintf(TEXT("%-60s: %s\n"),devID,action);

    return EXIT_OK;
}

// int cmdStatus(_In_ LPCTSTR BaseName, _In_opt_ LPCTSTR Machine, _In_ DWORD Flags, _In_ int argc, _In_reads_(argc) PTSTR argv[])
// /*++
// 
// Routine Description:
// 
//     STATUS <id> ...
//     use EnumerateDevices to do hardwareID matching
//     for each match, dump status to stdout
//     note that we only enumerate present devices
// 
// Arguments:
// 
//     BaseName  - name of executable
//     Machine   - if non-NULL, remote machine
//     argc/argv - remaining parameters - passed into EnumerateDevices
// 
// Return Value:
// 
//     EXIT_xxxx
// 
// --*/
// {
//     GenericContext context;
//     int failcode;
// 
//     UNREFERENCED_PARAMETER(Flags);
// 
//     if(!argc) {
//         return EXIT_USAGE;
//     }
// 
//     context.count = 0;
//     context.control = FIND_DEVICE | FIND_STATUS;
//     failcode = EnumerateDevices(BaseName,Machine,DIGCF_PRESENT,argc,argv,FindCallback,&context);
// 
//     if(failcode == EXIT_OK) {
// 
//         if(!context.count) {
//             FormatToStream(stdout,Machine?MSG_FIND_TAIL_NONE:MSG_FIND_TAIL_NONE_LOCAL,Machine);
//         } else {
//             FormatToStream(stdout,Machine?MSG_FIND_TAIL:MSG_FIND_TAIL_LOCAL,context.count,Machine);
//         }
//     }
//     return failcode;
// }

int cmdUpdate(_In_ LPCTSTR BaseName, _In_opt_ LPCTSTR Machine, _In_ DWORD Flags, _In_ int argc, _In_reads_(argc) PTSTR argv[])
/*++

Routine Description:
    UPDATE
    update driver for existing device(s)

Arguments:

    BaseName  - name of executable
    Machine   - machine name, must be NULL
    argc/argv - remaining parameters

Return Value:

    EXIT_xxxx

--*/
{
	TRACE_ENTER();

    HMODULE newdevMod = NULL;
    int failcode = EXIT_FAIL;
    UpdateDriverForPlugAndPlayDevicesProto UpdateFn;
    BOOL reboot = FALSE;
    LPCTSTR hwid = NULL;
    LPCTSTR inf = NULL;
    DWORD flags = 0;
    DWORD res;
    TCHAR InfPath[MAX_PATH];

    UNREFERENCED_PARAMETER(BaseName);
    UNREFERENCED_PARAMETER(Flags);

    if (Machine)
	{
        //
        // must be local machine
        //
		TRACE_PRINT1("cmdUpdate: error, Machine = %s.", Machine);
		TRACE_EXIT();
        return EXIT_USAGE;
    }
    if (argc < 2)
	{
        //
        // at least HWID required
        //
		TRACE_PRINT1("cmdUpdate: error, argc = %d.", argc);
		TRACE_EXIT();
        return EXIT_USAGE;
    }
    inf = argv[0];
    if (!inf[0])
	{
		TRACE_PRINT1("cmdUpdate: error, argv[0] = %s.", argv[0]);
		TRACE_EXIT();
        return EXIT_USAGE;
    }

    hwid = argv[1];
    if (!hwid[0])
	{
		TRACE_PRINT1("cmdUpdate: error, argv[1] = %s.", argv[1]);
		TRACE_EXIT();
        return EXIT_USAGE;
    }
    //
    // Inf must be a full pathname
    //
    res = GetFullPathName(inf, MAX_PATH, InfPath, NULL);
    if ((res >= MAX_PATH) || (res == 0))
	{
        //
        // inf pathname too long
        //
		TRACE_PRINT1("GetFullPathName: error, res = %d.", res);
		TRACE_EXIT();
        return EXIT_FAIL;
    }
    if (GetFileAttributes(InfPath) == (DWORD) (-1))
	{
        //
        // inf doesn't exist
        //
		TRACE_PRINT1("GetFileAttributes: error, InfPath = %s.", InfPath);
		TRACE_EXIT();
        return EXIT_FAIL;
    }
    inf = InfPath;
    flags |= INSTALLFLAG_FORCE;

    //
    // make use of UpdateDriverForPlugAndPlayDevices
    //
    newdevMod = LoadLibrary(TEXT("newdev.dll"));
    if (!newdevMod)
	{
		TRACE_PRINT1("LoadLibrary failed: %x", GetLastError());
        goto final;
    }
    UpdateFn = (UpdateDriverForPlugAndPlayDevicesProto) GetProcAddress(newdevMod, UPDATEDRIVERFORPLUGANDPLAYDEVICES);
    if (!UpdateFn)
    {
		TRACE_PRINT1("GetProcAddress failed to get UpdateDriverForPlugAndPlayDevices: %x", GetLastError());
        goto final;
    }

    FormatToStream(stdout, inf ? MSG_UPDATE_INF : MSG_UPDATE, hwid, inf);

    if (!UpdateFn(NULL, hwid, inf, flags, &reboot))
	{
		TRACE_PRINT1("UpdateFn failed: %x", GetLastError());
        goto final;
    }

    FormatToStream(stdout, MSG_UPDATE_OK);

    failcode = reboot ? EXIT_REBOOT : EXIT_OK;

final:

    if (newdevMod)
	{
        FreeLibrary(newdevMod);
    }

	TRACE_PRINT1("cmdUpdate: failcode = %d.", failcode);
	TRACE_EXIT();
    return failcode;
}

int cmdInstall(_In_ LPCTSTR BaseName, _In_opt_ LPCTSTR Machine, _In_ DWORD Flags, _In_ int argc, _In_reads_(argc) PTSTR argv[])
/*++

Routine Description:

    CREATE
    Creates a root enumerated devnode and installs drivers on it

Arguments:

    BaseName  - name of executable
    Machine   - machine name, must be NULL
    argc/argv - remaining parameters

Return Value:

    EXIT_xxxx

--*/
{
	TRACE_ENTER();

    HDEVINFO DeviceInfoSet = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA DeviceInfoData;
    GUID ClassGUID;
    TCHAR ClassName[MAX_CLASS_NAME_LEN];
    TCHAR hwIdList[LINE_LEN+4];
    TCHAR InfPath[MAX_PATH];
    int failcode = EXIT_FAIL;
    LPCTSTR hwid = NULL;
	DWORD res;
    LPCTSTR inf = NULL;

    if (Machine)
	{
        //
        // must be local machine
        //
		TRACE_PRINT1("cmdInstall: error, Machine = %s.", Machine);
		TRACE_EXIT();
        return EXIT_USAGE;
    }
    if (argc < 2)
	{
        //
        // at least HWID required
        //
		TRACE_PRINT1("cmdInstall: error, argc = %d.", argc);
		TRACE_EXIT();
        return EXIT_USAGE;
    }
    inf = argv[0];
    if (!inf[0])
	{
		TRACE_PRINT1("cmdUpdate: error, argv[0] = %s.", argv[0]);
		TRACE_EXIT();
        return EXIT_USAGE;
    }

    hwid = argv[1];
    if (!hwid[0])
	{
		TRACE_PRINT1("cmdUpdate: error, argv[1] = %s.", argv[1]);
		TRACE_EXIT();
        return EXIT_USAGE;
    }

    //
    // Inf must be a full pathname
    //
	res = GetFullPathName(inf, MAX_PATH, InfPath, NULL);
	if (res >= MAX_PATH)
	{
        //
        // inf pathname too long
        //
		TRACE_PRINT1("GetFullPathName: error, res = %d.", res);
		TRACE_EXIT();
        return EXIT_FAIL;
    }

    //
    // List of hardware ID's must be double zero-terminated
    //
    ZeroMemory(hwIdList, sizeof(hwIdList));
    if (FAILED(_tcscpy_s(hwIdList, LINE_LEN, hwid)))
	{
        goto final;
    }

    //
    // Use the INF File to extract the Class GUID.
    //
    if (!SetupDiGetINFClass(InfPath, &ClassGUID, ClassName, sizeof(ClassName) / sizeof(ClassName[0]), 0))
    {
        goto final;
    }

    //
    // Create the container for the to-be-created Device Information Element.
    //
    DeviceInfoSet = SetupDiCreateDeviceInfoList(&ClassGUID, 0);
    if (DeviceInfoSet == INVALID_HANDLE_VALUE)
    {
        goto final;
    }

    //
    // Now create the element.
    // Use the Class GUID and Name from the INF file.
    //
    DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    if (!SetupDiCreateDeviceInfo(DeviceInfoSet,
        ClassName,
        &ClassGUID,
        NULL,
        0,
        DICD_GENERATE_ID,
        &DeviceInfoData))
    {
        goto final;
    }

    //
    // Add the HardwareID to the Device's HardwareID property.
    //
    if (!SetupDiSetDeviceRegistryProperty(DeviceInfoSet,
        &DeviceInfoData,
        SPDRP_HARDWAREID,
        (LPBYTE) hwIdList,
        (lstrlen(hwIdList) + 1 + 1) * sizeof(TCHAR)))
    {
        goto final;
    }

	//
	// Get the Device Instance ID for our adapter.
	//
	TCHAR DevInstanceID[BUF_SIZE];
	if (!SetupDiGetDeviceInstanceId(DeviceInfoSet,
		&DeviceInfoData,
		DevInstanceID,
		BUF_SIZE,
		NULL))
	{
		goto final;
	}
	g_DevInstanceID = getIntDevID(DevInstanceID);

    //
    // Transform the registry element into an actual devnode
    // in the PnP HW tree.
    //
    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE,
        DeviceInfoSet,
        &DeviceInfoData))
    {
        goto final;
    }

    FormatToStream(stdout,MSG_INSTALL_UPDATE);
    //
    // update the driver for the device we just created
    //
    failcode = cmdUpdate(BaseName, Machine, Flags, argc, argv);

	// Mark device as an endpoint, not a network
	HKEY DevRegKey = SetupDiCreateDevRegKey(DeviceInfoSet,
		&DeviceInfoData,
		DICS_FLAG_GLOBAL,
		0,
		DIREG_DRV,
		NULL,
		NULL
		);
	if (DevRegKey != INVALID_HANDLE_VALUE)
	{
		DWORD devtype = NDIS_DEVICE_TYPE_ENDPOINT; // 1
		if (ERROR_SUCCESS != RegSetValueEx(DevRegKey,
			TEXT("*NdisDeviceType"), 0, REG_DWORD, (const BYTE *)&devtype, sizeof(devtype))) {
			TRACE_PRINT1("Couldn't set *NdisDeviceType: %x", GetLastError());// Oops. Hope this isn't a problem.
		}
		RegCloseKey(DevRegKey);
	}
	else{ TRACE_PRINT1("Couldn't create/open dev reg key: %x", GetLastError()); }

final:

    if (DeviceInfoSet != INVALID_HANDLE_VALUE)
	{
        SetupDiDestroyDeviceInfoList(DeviceInfoSet);
    }

	TRACE_PRINT1("cmdInstall: failcode = %d.", failcode);
	TRACE_EXIT();
    return failcode;
}

int cmdRemove(_In_ LPCTSTR BaseName, _In_opt_ LPCTSTR Machine, _In_ DWORD Flags, _In_ int argc, _In_reads_(argc) PTSTR argv[])
/*++

Routine Description:

    REMOVE
    remove devices

Arguments:

    BaseName  - name of executable
    Machine   - machine name, must be NULL
    argc/argv - remaining parameters

Return Value:

    EXIT_xxxx

--*/
{
	TRACE_ENTER();

    GenericContext context;
    TCHAR strRemove[80] = _T("Removed");
    TCHAR strReboot[80] = _T("Removed on reboot");
    TCHAR strFail[80] = _T("Remove failed");
    int failcode = EXIT_FAIL;

    UNREFERENCED_PARAMETER(Flags);

    if (!argc)
	{
        //
        // arguments required
        //
		TRACE_PRINT1("cmdRemove: error, argc = %d.", argc);
		TRACE_EXIT();
        return EXIT_USAGE;
    }
    if (Machine)
	{
        //
        // must be local machine as we need to involve class/co installers
        //
		TRACE_PRINT1("cmdRemove: error, Machine = %s.", Machine);
		TRACE_EXIT();
        return EXIT_USAGE;
    }

    context.reboot = FALSE;
    context.count = 0;
    context.strReboot = strReboot;
    context.strSuccess = strRemove;
    context.strFail = strFail;
    failcode = EnumerateDevices(BaseName, Machine, DIGCF_PRESENT, argc, argv, RemoveCallback, &context);

    if (failcode == EXIT_OK)
	{
        if (!context.count)
		{
            FormatToStream(stdout, MSG_REMOVE_TAIL_NONE);
        }
		else if (!context.reboot)
		{
            FormatToStream(stdout, MSG_REMOVE_TAIL, context.count);
        }
		else
		{
            FormatToStream(stdout, MSG_REMOVE_TAIL_REBOOT, context.count);
            failcode = EXIT_REBOOT;
        }
    }

	TRACE_PRINT1("cmdRemove: failcode = %d.", failcode);
	TRACE_EXIT();
    return failcode;
}

// BOOL ListLoopbackAdapters()
// {
// 	TCHAR *strArgVs[1] = {_T("*msloop")}; // Hardware ID: *msloop
// 	if (cmdStatus(_T("devcon.exe"), NULL, 0, 1, strArgVs) == EXIT_OK)
// 	{
// 		return TRUE;
// 	}
// 	else
// 	{
// 		return FALSE;
// 	}
// }

BOOL GetLoopbackINFFilePath(TCHAR strLoopbackInfPath[])
{
	TRACE_ENTER();

	TCHAR tmp[MAX_PATH];
	if (!SHGetSpecialFolderPath(NULL, tmp, CSIDL_WINDOWS, FALSE))
	{
		TRACE_PRINT("SHGetSpecialFolderPath: error.");
		TRACE_EXIT();
		return FALSE;
	}
	_stprintf_s(strLoopbackInfPath, MAX_PATH + 30, _T("%s\\inf\\netloop.inf"), tmp);

	TRACE_PRINT1("SHGetSpecialFolderPath: succeed, strLoopbackInfPath = %s.", strLoopbackInfPath);
	TRACE_EXIT();
	return TRUE;
}

BOOL GetConfigFilePath(TCHAR strConfigPath[])
{
	TRACE_ENTER();

	TCHAR tmp[MAX_PATH];
	TCHAR drive[_MAX_DRIVE];
	TCHAR dir[_MAX_DIR];
	if (!GetModuleFileName(NULL, tmp, MAX_PATH))
	{
		TRACE_PRINT1("GetModuleFileName: error, errCode = 0x%08x.", GetLastError());
		TRACE_EXIT();
		return FALSE;
	}
	_tsplitpath_s(tmp, drive, _MAX_DRIVE, dir, _MAX_DIR, NULL, 0, NULL, 0);
	_stprintf_s(strConfigPath, MAX_PATH + 30, _T("%s%sloopback.ini"), drive, dir);

	TRACE_PRINT1("GetModuleFileName: succeed, strConfigPath = %s.", strConfigPath);
	TRACE_EXIT();
	return TRUE;
}

BOOL InstallLoopbackDeviceInternal()
{
	TRACE_ENTER();

	TCHAR strLoopbackInfPath[MAX_PATH + 30];
	if (!GetLoopbackINFFilePath(strLoopbackInfPath))
	{
		TRACE_PRINT("GetLoopbackINFFilePath: error.");
		TRACE_EXIT();
		return FALSE;
	}

	// devcon.exe install C:\Windows\inf\netloop.inf *msloop
	TCHAR *strArgVs[2] = {strLoopbackInfPath, _T("*msloop")}; // Inf File: netloop.inf, Hardware ID: *msloop
	if (cmdInstall(_T("devcon.exe"), NULL, 0, 2, strArgVs) == EXIT_OK)
	{
		TRACE_EXIT();
		return TRUE;
	}
	else
	{
		TRACE_PRINT("cmdInstall: error.");
		TRACE_EXIT();
		return FALSE;
	}
}

BOOL RemoveLoopbackDeviceInternal(int iDevID)
{
	TRACE_ENTER();

	TCHAR strDevID[BUF_SIZE];
	_stprintf_s(strDevID, BUF_SIZE, _T("@ROOT\\NET\\%04d"), iDevID);

	// devcon.exe remove @ROOT\NET\000X
	TCHAR *strArgVs[1] = {strDevID}; // Device ID: @ROOT\NET\000X
	if (cmdRemove(_T("devcon.exe"), NULL, 0, 1, strArgVs) == EXIT_OK)
	{
		TRACE_EXIT();
		return TRUE;
	}
	else
	{
		TRACE_PRINT("cmdRemove: error.");
		TRACE_EXIT();
		return FALSE;
	}
}

BOOL SaveDevIDToFile(int iDevID)
{
	TRACE_ENTER();

	TCHAR strLoopbackIDFilePath[MAX_PATH + 30];
	if (!GetConfigFilePath(strLoopbackIDFilePath))
	{
		TRACE_PRINT("GetConfigFilePath: error.");
		TRACE_EXIT();
		return FALSE;
	}

	FILE *fp;
	if (_tfopen_s(&fp, strLoopbackIDFilePath, _T("w")) != 0)
	{
		TRACE_PRINT1("_tfopen_s: error, errCode = 0x%08x.", errno);
		TRACE_EXIT();
		return FALSE;
	}
	_ftprintf(fp, _T("%d"), iDevID);
	fclose(fp);

	TRACE_EXIT();
	return TRUE;
}

int LoadDevIDFromFile()
{
	TRACE_ENTER();

	TCHAR strLoopbackIDFilePath[MAX_PATH + 30];
	if (!GetConfigFilePath(strLoopbackIDFilePath))
	{
		TRACE_PRINT("GetConfigFilePath: error.");
		TRACE_EXIT();
		return FALSE;
	}

	FILE *fp;
	int iDevID;
	if (_tfopen_s(&fp, strLoopbackIDFilePath, _T("r")) != 0)
	{
		TRACE_PRINT1("_tfopen_s: error, errCode = 0x%08x.", errno);
		TRACE_EXIT();
		return -1;
	}
	_ftscanf_s(fp, _T("%d"), &iDevID);
	fclose(fp);

	TRACE_EXIT();
	return iDevID;
}

BOOL InstallLoopbackAdapter()
{
	TRACE_ENTER();

	BOOL isWin10 = IsWindowsWin10();

	if (isWin10)
	{
		PrepareRenameLoopbackNetwork2();
	}

	if (!InstallLoopbackDeviceInternal())
	{
		TRACE_PRINT("InstallLoopbackDeviceInternal: error.");
		TRACE_EXIT();
		return FALSE;
	}

	int iNpcapAdapterID = g_DevInstanceID;
	if (iNpcapAdapterID == -1)
	{
		TRACE_PRINT("iNpcapAdapterID == -1: error.");
		TRACE_EXIT();
		return FALSE;
	}

	if (!RecordLoopbackDevice(iNpcapAdapterID))
	{
		if (isWin10)
		{
			if (!DoRenameLoopbackNetwork2())
			{
				TRACE_PRINT("DoRenameLoopbackNetwork2: error.");
				TRACE_EXIT();
				return FALSE;
			}
		}
		else
		{
			TRACE_PRINT("RecordLoopbackDevice: error.");
			TRACE_EXIT();
			return FALSE;
		}
	}

	if (!SaveDevIDToFile(iNpcapAdapterID))
	{
		TRACE_PRINT("SaveDevIDToFile: error.");
		TRACE_EXIT();
		return FALSE;
	}

	TRACE_EXIT();
	return TRUE;
}

BOOL UninstallLoopbackAdapter()
{
	TRACE_ENTER();

	int iNpcapAdapterID = LoadDevIDFromFile();
	if (iNpcapAdapterID == -1)
	{
		TRACE_PRINT("iNpcapAdapterID == -1: error.");
		TRACE_EXIT();
		return FALSE;
	}

	if (!RemoveLoopbackDeviceInternal(iNpcapAdapterID))
	{
		TRACE_PRINT("RemoveLoopbackDeviceInternal: error.");
		TRACE_EXIT();
		return FALSE;
	}

	TRACE_EXIT();
	return TRUE;
}
