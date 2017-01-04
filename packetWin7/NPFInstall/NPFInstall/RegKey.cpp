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

RegKey.cpp

Abstract:

This is used for updating PATH in registry.

--*/

#include "RegKey.h"

const TCHAR szREG_SYSTEM[] = _T("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"); // System Variables (HKEY_LOCAL_MACHINE)
const TCHAR szREG_USER[] = _T("Environment"); // User Variables (HKEY_CURRENT_USER)

const int ERR_SUCCESS = 0;
const int ERR_ERROR = 1;
const int ERR_ACCESS_DENIED = 5;

RegKey::RegKey()
	: iLastErrorCode_(ERROR_SUCCESS)
	, hTheKey_(NULL)
	, hBaseKey_(NULL)
	, bRemote_(false)
	, pszComputerName_(NULL)
{
	memset(&obLastWriteTime_, 0, sizeof(FILETIME));
}

RegKey::~RegKey()
{
	if (hTheKey_)
		RegCloseKey(hTheKey_);

	hTheKey_ = NULL;

	if (bRemote_ || hBaseKey_) // Need to close remote connection ?
	{
		RegCloseKey(hBaseKey_);
		hBaseKey_ = NULL;
	}

	bRemote_ = false;

	if (pszComputerName_ != NULL)
	{
		delete[] pszComputerName_;
		pszComputerName_ = NULL;
	}
}

// Opens/Creates a key and make it the active key
bool RegKey::OpenKey(LPCTSTR pszKeyName, bool bCreateIfNoExist /* = false */, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	if (pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	CloseKey(); // Close current active key and base key if remotely connected

	// If a computer name is specified, then connect to it...
	if (pszMachineName != NULL)
	{		// This will set up the base key to point to the remote machine
		if (ConnectRemote((HKEY)hBaseKey, pszMachineName) == false) // Try to connect
			return false;
	}
	else
		hBaseKey_ = hBaseKey; // Base key is same as the passed parameter

	LONG lRetValue = ERROR_SUCCESS;

	if (bCreateIfNoExist) // Create ?
	{
		DWORD dwDisp; // Disposition

		lRetValue = RegCreateKeyEx(hBaseKey_, pszKeyName, 0, NULL, REG_OPTION_NON_VOLATILE
			, KEY_ALL_ACCESS, NULL, &hTheKey_, &dwDisp);
	}
	else
		lRetValue = RegOpenKeyEx(hBaseKey_, pszKeyName, NULL, KEY_ALL_ACCESS, &hTheKey_);

	if (lRetValue != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		hTheKey_ = NULL;

		return false;
	}

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Creates AND opens a key - key becomes active key 
bool RegKey::CreateKey(LPCTSTR pszKeyName, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	return OpenKey(pszKeyName, true, hBaseKey, pszMachineName);
}

// Close the active key
void RegKey::CloseKey()
{
	if (hTheKey_)
		RegCloseKey(hTheKey_);

	hTheKey_ = NULL;

	if (bRemote_) // Need to close remote connection ?
	{
		RegCloseKey(hBaseKey_);
		hBaseKey_ = NULL;
	}

	bRemote_ = false;

	if (pszComputerName_ != NULL)
	{
		delete[] pszComputerName_;
		pszComputerName_ = NULL;
	}
}

bool RegKey::RecursiveDelete(RegKey* pTheCallingClass, HKEY hTheKey, LPCTSTR pszKeyName)
{
	HKEY hChildHandle = NULL;
	LPTSTR pszTempKeyName = NULL;

	// Open the child
	long lRetValue = RegOpenKeyEx(hTheKey, pszKeyName, NULL, KEY_ALL_ACCESS, &hChildHandle);
	if (lRetValue != ERROR_SUCCESS)
	{
		pTheCallingClass->iLastErrorCode_ = GetLastError();
		return false;
	}

	pszTempKeyName = new TCHAR[_MAX_PATH];
	if (pszTempKeyName == NULL)
	{
		pTheCallingClass->iLastErrorCode_ = GetLastError();
		return false;
	}

	// Get the child's key name
	lRetValue = RegEnumKey(hChildHandle, 0, pszTempKeyName, _MAX_PATH);
	while (lRetValue != ERROR_NO_MORE_ITEMS)
	{
		RecursiveDelete(pTheCallingClass, hChildHandle, pszTempKeyName);
		lRetValue = RegEnumKey(hChildHandle, 0, pszTempKeyName, _MAX_PATH);
	}

	delete[] pszTempKeyName;
	pszTempKeyName = NULL;

	RegCloseKey(hChildHandle);

	lRetValue = RegDeleteKey(hTheKey, pszKeyName);
	if (lRetValue != ERROR_SUCCESS)
	{
		pTheCallingClass->iLastErrorCode_ = GetLastError();
		return false;
	}

	return true;
}

// Deletes a key and all values of that key
bool RegKey::DeleteKey(LPCTSTR pszKeyName)
{
	if (pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	if (hTheKey_ == NULL)
	{
		iLastErrorCode_ = ERROR_INVALID_HANDLE;
		return false;
	}

	bool bRetValue = true;

	// You cannot delete a key if given a full path e.g. "A\\B"
	// We have to go back up a level to "A" and then delete

	// Take a copy of the keyName
	TCHAR* pszCopy = _tcsdup(pszKeyName);
	TCHAR* pBackSlash = _tcsrchr(pszCopy, _T('\\'));

	if (pBackSlash == NULL) // Not found
	{
		// No path, so specified key is just a subkey of active key
		bRetValue = RecursiveDelete(this, hTheKey_, pszKeyName);
	}
	else // Path specified
	{
		LPTSTR pszChildKeyName = pBackSlash + 1;
		*(pBackSlash) = _T('\0'); // Null terminate the parent string

		LPTSTR pszParentKey = (TCHAR*)pszCopy;
		HKEY hTempKey;

		LONG retValue = RegOpenKeyEx(hTheKey_, pszParentKey, NULL, KEY_ALL_ACCESS, &hTempKey);
		if (retValue == ERROR_SUCCESS)
		{
			bRetValue = RecursiveDelete(this, hTempKey, pszChildKeyName);
			RegCloseKey(hTempKey);
		}
		else
		{
			free(pszCopy);
			pszCopy = NULL;

			iLastErrorCode_ = GetLastError();
			return false;
		}
	}

	free(pszCopy);
	pszCopy = NULL;

	if (!bRetValue)
		return false;

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

bool RegKey::EnumerateKeys(LPTSTR pszSubkeyName, const DWORD dwIndex)
{
	if (pszSubkeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	if (hTheKey_ == NULL)
	{
		iLastErrorCode_ = ERROR_INVALID_HANDLE;
		return false;
	}

	// Allocate buffers and zero them
	TCHAR subkeyNameBuffer[2048] = { '\0' };
	TCHAR classNameBuffer[2048] = { '\0' };

	DWORD sizeOfSubkeyName = sizeof(subkeyNameBuffer) - 1;
	DWORD sizeOfClassName = sizeof(classNameBuffer) - 1;

	LONG lRetValue = RegEnumKeyEx(hTheKey_, dwIndex, subkeyNameBuffer
		, &sizeOfSubkeyName, NULL, classNameBuffer, &sizeOfClassName, &obLastWriteTime_);

	if (lRetValue == ERROR_NO_MORE_ITEMS)
	{
		iLastErrorCode_ = ERROR_NO_MORE_ITEMS;
		_tcscpy_s(pszSubkeyName, 2048, subkeyNameBuffer);
		return false;
	}

	if (lRetValue != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	_tcscpy_s(pszSubkeyName, 2048, subkeyNameBuffer);

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Flushes the active key ( Write to hard disk )
bool RegKey::Flush()
{
	if (hTheKey_ == NULL)
		return true;

	if (RegFlushKey(hTheKey_) != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Connect to a remote computer's registry
// Note: WinNT won't allow you to connect to these hives via RegConnectRegistry
bool RegKey::ConnectRemote(HKEY hKeyToOpen, LPCTSTR pszComputerName)
{
	if (pszComputerName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	LONG lRetValue = ERROR_SUCCESS;

	// Try to connect using the remote key
	lRetValue = RegConnectRegistry((TCHAR *)pszComputerName, hKeyToOpen, &hBaseKey_);
	if (lRetValue == ERROR_SUCCESS)
	{
		bRemote_ = true;
		pszComputerName_ = new TCHAR[MAX_COMPUTERNAME_LENGTH + 1];
		memset(pszComputerName_, 0, (MAX_COMPUTERNAME_LENGTH + 1) * sizeof(TCHAR));
		_tcsncpy_s(pszComputerName_, MAX_COMPUTERNAME_LENGTH + 1, pszComputerName, MAX_COMPUTERNAME_LENGTH);
	}
	else
	{
		bRemote_ = false;
		pszComputerName_ = NULL;
		iLastErrorCode_ = GetLastError();

		return false;
	}

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

//////////////////////////
// Various Value Functions

// Retrieves the size and type of a value for the active key
bool RegKey::QueryValue(LPCTSTR pszValueName, DWORD& dwValueLength, DWORD& dwValueType)
{
	if (pszValueName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	if (hTheKey_ == NULL)
	{
		iLastErrorCode_ = ERROR_INVALID_HANDLE;
		return false;
	}

	LONG lRetValue = RegQueryValueEx(hTheKey_, pszValueName, NULL, &dwValueType, NULL, &dwValueLength);
	if (lRetValue != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Deletes a value from the currently open active key
bool RegKey::DeleteValue(LPCTSTR pszValueName)
{
	if (pszValueName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	if (hTheKey_ == NULL)
	{
		iLastErrorCode_ = ERROR_INVALID_HANDLE;
		return false;
	}

	if (RegDeleteValue(hTheKey_, pszValueName) != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Get all the values for the active key, returns XFC_NO_MOREDATA when no more items
bool RegKey::EnumerateValues(LPTSTR pszValueName, LPBYTE lpValue, DWORD& dwValueSize, DWORD& dwValueType, const DWORD dwIndex)
{
	if (pszValueName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	if (hTheKey_ == NULL)
	{
		iLastErrorCode_ = ERROR_INVALID_HANDLE;
		return false;
	}

	TCHAR tmpName[2048] = { '\0' };

	DWORD dwTmpNameSize = sizeof(tmpName);

	LONG lRetValue = RegEnumValue(hTheKey_, dwIndex, tmpName, &dwTmpNameSize, NULL, &dwValueType, lpValue, &dwValueSize);
	if (lRetValue == ERROR_NO_MORE_ITEMS)
	{
		_tcscpy_s(pszValueName, 2048, tmpName);
		iLastErrorCode_ = ERROR_NO_MORE_ITEMS;
		return false;
	}

	if (lRetValue != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	_tcscpy_s(pszValueName, 2048, tmpName);

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Get information on active key
bool RegKey::QueryKey(DWORD& dwNumSubKeys, DWORD& dwMaxSubKeyName, DWORD& dwNumValues, DWORD& dwMaxValueName, DWORD& dwMaxValueDataSize, FILETIME& lastWriteTime)
{
	if (hTheKey_ == NULL)
	{
		iLastErrorCode_ = ERROR_INVALID_HANDLE;
		return false;
	}

	// Not interested in the class name or security in this version, so leave as NULL
	LONG lRetValue = RegQueryInfoKey(hTheKey_, NULL, NULL, NULL
		, &dwNumSubKeys, &dwMaxSubKeyName, NULL, &dwNumValues, &dwMaxValueName
		, &dwMaxValueDataSize, NULL, &lastWriteTime);

	if (lRetValue != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

///////////
// SetValue

// Sets a value for the active key, creates a new value if it doesn't exist
bool RegKey::IntSetValue(LPCTSTR pszValueName, const BYTE* pValue, DWORD dwValueLength, DWORD dwValueType)
{
	if (pszValueName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	if (hTheKey_ == NULL)
	{
		iLastErrorCode_ = ERROR_INVALID_HANDLE;
		return false;
	}

	dwValueLength = dwValueLength * sizeof(TCHAR);
	if (RegSetValueEx(hTheKey_, pszValueName, NULL, dwValueType, pValue, dwValueLength) != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Sets a DWORD value for the active key
bool RegKey::SetValue(LPCTSTR pszValueName, DWORD dwValue)
{
	return IntSetValue(pszValueName, (BYTE*)&dwValue, sizeof(DWORD), REG_DWORD);
}

// Sets a STRING value for the active key
bool RegKey::SetValue(LPCTSTR pszValueName, LPCTSTR pszValue, DWORD dwValueLength)
{
	return IntSetValue(pszValueName, (BYTE*)pszValue, dwValueLength, REG_SZ);
}

bool RegKey::SetValueEx(LPCTSTR pszValueName, LPCTSTR pszValue, DWORD dwValueLength)
{
	return IntSetValue(pszValueName, (BYTE*)pszValue, dwValueLength, REG_EXPAND_SZ);
}

// Sets a BINARY value for the active key
bool RegKey::SetValue(LPCTSTR pszValueName, const BYTE* pValue, DWORD dwValueLength)
{
	return IntSetValue(pszValueName, pValue, dwValueLength, REG_BINARY);
}

///////////
// GetValue

// Gets a value from the active key
bool RegKey::IntGetValue(LPCTSTR pszValueName, BYTE& pValue, DWORD& dwValueLength)
{
	if (pszValueName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	if (hTheKey_ == NULL)
	{
		iLastErrorCode_ = ERROR_INVALID_HANDLE;
		return false;
	}

	DWORD dwType = 0;

	dwValueLength = dwValueLength * sizeof(TCHAR);
	LONG lRetValue = RegQueryValueEx(hTheKey_, pszValueName, NULL, &dwType, (LPBYTE)&pValue, &dwValueLength);
	dwValueLength = dwValueLength / sizeof(TCHAR);
	if (lRetValue != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Gets a DWORD value for the active key
bool RegKey::GetValue(LPCTSTR pszValueName, DWORD& dwValue)
{
	DWORD dwValueLen = sizeof(DWORD);

	if (!IntGetValue(pszValueName, (BYTE&)dwValue, dwValueLen))
		return false;

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Gets a STRING value for the active key
bool RegKey::GetValue(LPCTSTR pszValueName, LPTSTR pszValue, DWORD& dwValueLength)
{
	TCHAR* tmpBuffer = new TCHAR[dwValueLength + 1];
	memset(tmpBuffer, 0, dwValueLength * sizeof(TCHAR));

	if (!IntGetValue(pszValueName, (BYTE&)*tmpBuffer, dwValueLength))
	{
		delete[] tmpBuffer;
		tmpBuffer = NULL;
		return false;
	}

	_tcsncpy_s(pszValue, dwValueLength + 1, tmpBuffer, dwValueLength);
	delete[] tmpBuffer;
	tmpBuffer = NULL;

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Gets a BINARY value for the active key
bool RegKey::GetValue(LPCTSTR pszValueName, BYTE& pValue, DWORD& dwValueLength)
{
	BYTE* tmpBuffer = new BYTE[dwValueLength + 1];
	memset(tmpBuffer, 0, dwValueLength * sizeof(TCHAR));

	if (!IntGetValue(pszValueName, (BYTE&)*tmpBuffer, dwValueLength))
	{
		delete[] tmpBuffer;
		tmpBuffer = NULL;
		return false;
	}

	memcpy(&pValue, tmpBuffer, dwValueLength);
	delete[] tmpBuffer;
	tmpBuffer = NULL;

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

//////////////////////////
// Configuration functions

// Saves a registry tree into the specified file/path from the specified key position
bool RegKey::SaveRegistry(LPCTSTR pszFileName, LPCTSTR pszKeyName, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	if (pszFileName == NULL || pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	CloseKey(); // Close current active key and base key if remote

	// Open the key
	if (!OpenKey(pszKeyName, false, hBaseKey, pszMachineName))
		return false;

	LONG lRetValue = RegSaveKey(hTheKey_, pszFileName, NULL);

	if (lRetValue == ERROR_ALREADY_EXISTS || lRetValue == ERROR_REGISTRY_IO_FAILED) // Win NT / Win 95
	{
		iLastErrorCode_ = ERROR_ALREADY_EXISTS;
		return false;
	}

	if (lRetValue != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Restores a saved registry tree from the specified file to the specified key position
bool RegKey::RestoreRegistry(LPCTSTR pszFileName, LPCTSTR pszKeyName, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	if (pszFileName == NULL || pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	CloseKey(); // Close current active key and base key if remote

	// Open the key
	if (!OpenKey(pszKeyName, true, hBaseKey, pszMachineName))
		return false;

	LONG lRetValue = RegRestoreKey(hTheKey_, pszFileName, REG_OPTION_NON_VOLATILE);
	if (lRetValue == ERROR_CALL_NOT_IMPLEMENTED) // NT ONLY
	{
		iLastErrorCode_ = ERROR_CALL_NOT_IMPLEMENTED;
		return false;
	}

	if (lRetValue != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Notify of a change in the specified registry key/hive
bool RegKey::NotifyChange(LPCTSTR pszKeyName, DWORD dwNotifyfilter, bool bWatchSubKeys /* = false */, HANDLE hEvent /* = NULL */, HKEY hBaseKey /* = HKEY_CURRENT_USER */)
{
	if (pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	if (!OpenKey(pszKeyName, false, hBaseKey, NULL))
		return false;

	LONG lRetValue = ERROR_SUCCESS;

	if (hEvent == NULL)
		lRetValue = RegNotifyChangeKeyValue(hTheKey_, bWatchSubKeys, dwNotifyfilter, hEvent, FALSE);
	else
		lRetValue = RegNotifyChangeKeyValue(hTheKey_, bWatchSubKeys, dwNotifyfilter, hEvent, TRUE);

	if (lRetValue == ERROR_CALL_NOT_IMPLEMENTED) // NT ONLY
	{
		iLastErrorCode_ = ERROR_CALL_NOT_IMPLEMENTED;
		return false;
	}

	if (lRetValue != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

/////////////////////
// Shortcut functions
// These functions perform an open automatically, and close if necessary
// Saves having to do an Open(), Set(), Close() sequence.

DWORD RegKey::GetSizeOfValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	if (pszValueName == NULL || pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	DWORD dwCount = 0;
	if (OpenKey(pszKeyName, false, hBaseKey, pszMachineName))
	{
		DWORD dwType = 0;
		DWORD dwValueLength = 0;

		LONG lRetValue = RegQueryValueEx(hTheKey_, pszValueName, NULL, &dwType, NULL, &dwValueLength);
		if (lRetValue == ERROR_SUCCESS || lRetValue == ERROR_MORE_DATA)
			dwCount = dwValueLength / sizeof(TCHAR);

		CloseKey(); // Close it as we have finnished
	}

	return dwCount;
}

// Opens/Creates a key, sets a value within the key and makes it the active key if active = true, else closes the key
bool RegKey::SetKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, DWORD dwValue
	, bool bCreateIfNoExist /* = false */, bool bActive /* = false */
	, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	if (pszValueName == NULL || pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	CloseKey(); // Close current active key and base key if remote

	// Open / create the key
	if (!OpenKey(pszKeyName, bCreateIfNoExist, hBaseKey, pszMachineName))
		return false;

	if (!SetValue(pszValueName, dwValue))
	{
		if (!bActive)
			CloseKey();
		return false;
	}

	if (!bActive)
		CloseKey(); // Close current active key and base key if remote

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

bool RegKey::SetKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, LPCTSTR pszValue, DWORD dwValueLength
	, bool bCreateIfNoExist /* = false */, bool bActive /* = false */
	, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	if (pszValueName == NULL || pszValue == NULL || pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	CloseKey(); // Close current active key and base key if remote

	// Open / create the key
	if (!OpenKey(pszKeyName, bCreateIfNoExist, hBaseKey, pszMachineName))
		return false;

	if (!SetValue(pszValueName, pszValue, dwValueLength))
	{
		if (!bActive)
			CloseKey();
		return false;
	}

	if (!bActive)
		CloseKey(); // Close current active key and base key if remote

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Set an expanded String Value
bool RegKey::SetKeyValueEx(LPCTSTR pszKeyName, LPCTSTR pszValueName, LPCTSTR pszValue, DWORD dwValueLength
	, bool bCreateIfNoExist /* = false */, bool bActive /* = false */
	, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	if (pszValueName == NULL || pszValue == NULL || pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	CloseKey(); // Close current active key and base key if remote

	// Open / create the key
	if (!OpenKey(pszKeyName, bCreateIfNoExist, hBaseKey, pszMachineName))
		return false;

	if (!SetValueEx(pszValueName, pszValue, dwValueLength))
	{
		if (!bActive)
			CloseKey();
		return false;
	}

	if (!bActive)
		CloseKey(); // Close current active key and base key if remote

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

bool RegKey::SetKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, const BYTE* pValue, DWORD dwValueLength
	, bool bCreateIfNoExist /* = false */, bool bActive /* = false */
	, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	if (pszValueName == NULL || pValue == NULL || pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	CloseKey(); // Close current active key and base key if remote

	// Open / create the key
	if (!OpenKey(pszKeyName, bCreateIfNoExist, hBaseKey, pszMachineName))
		return false;

	if (!SetValue(pszValueName, (BYTE*)pValue, dwValueLength))
	{
		if (!bActive)
			CloseKey();
		return false;
	}

	if (!bActive)
		CloseKey(); // Close current active key and base key if remote

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Opens a key and retrieves A value
// Make it the active key if active = true, else close the key
bool RegKey::GetKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, DWORD& dwValue
	, bool bActive /* = false */, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	if (pszValueName == NULL || pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	CloseKey(); // Close current active key and base key if remote

	// Open the key
	if (!OpenKey(pszKeyName, false, hBaseKey, pszMachineName))
		return false;

	if (!GetValue(pszValueName, dwValue))
	{
		if (!bActive)
			CloseKey();
		return false;
	}

	if (!bActive)
		CloseKey(); // Close current active key and base key if remote

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

bool RegKey::GetKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, LPTSTR pszValue, DWORD dwValueLength
	, bool bActive /* = false */, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	if (pszValueName == NULL || pszValue == NULL || pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	CloseKey(); // Close current active key and base key if remote

	// Open the key
	if (!OpenKey(pszKeyName, false, hBaseKey, pszMachineName))
		return false;

	if (!GetValue(pszValueName, pszValue, dwValueLength))
	{
		if (!bActive)
			CloseKey();
		return false;
	}

	if (!bActive)
		CloseKey(); // Close current active key and base key if remote

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

/*lint -e774 */
bool RegKey::GetKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, BYTE& pValue, DWORD dwValueLength
	, bool bActive /* = false */, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	if ((pszKeyName == NULL) || (pszValueName == NULL) || (&pValue == NULL))
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	CloseKey(); // Close current active key and base key if remote

	// Open the key
	if (!OpenKey(pszKeyName, false, hBaseKey, pszMachineName))
		return false;

	if (!GetValue(pszValueName, pValue, dwValueLength))
	{
		if (!bActive)
			CloseKey();
		return false;
	}

	if (!bActive)
		CloseKey(); // Close current active key and base key if remote

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}
/*lint +e774 */

// Opens a key, deletes a value from the key and makes key active if required
bool RegKey::DeleteKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, bool bActive /* = false */, HKEY hBaseKey /* = HKEY_CURRENT_USER */, LPCTSTR pszMachineName /* = NULL */)
{
	if (pszValueName == NULL || pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	CloseKey(); // Close current active key and base key if remote

	// Open the key
	if (!OpenKey(pszKeyName, false, hBaseKey, pszMachineName))
		return false;

	if (!DeleteValue(pszValueName))
	{
		if (!bActive)
			CloseKey();
		return false;
	}

	if (!bActive)
		CloseKey(); // Close current active key and base key if remote

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Move a key, it's subkeys and all values
bool RegKey::MoveKey(LPCTSTR pszSourceKey, LPCTSTR pszDestKey, HKEY hBaseKey /* = HKEY_CURRENT_USER */)
{
	if (pszSourceKey == NULL || pszDestKey == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	HKEY hSource = NULL;
	HKEY hDest = NULL;

	// Open the source key
	LONG lRetValue = RegOpenKeyEx(hBaseKey, pszSourceKey, NULL, KEY_ALL_ACCESS, &hSource);

	if (lRetValue != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	// Open/Create the destination key
	DWORD dwDisp; // Disposition

	lRetValue = RegCreateKeyEx(hBaseKey, pszDestKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hDest, &dwDisp);
	if (lRetValue != ERROR_SUCCESS)
	{
		iLastErrorCode_ = GetLastError();
		return false;
	}

	// We have opened and created all appropriate keys
	// Enumerate all values in hSource, and recreate in hDest
	TCHAR szValueName[_MAX_PATH];
	DWORD dwValueBuffer = _MAX_PATH;
	DWORD dwIndex = 0;
	DWORD dwValueType;
	DWORD dwValueLength = 0;
	bool bContinue = true;

	// Deal with the values first
	while (bContinue)
	{
		dwValueBuffer = _MAX_PATH;
		dwValueLength = 1;

		if (RegEnumValue(hSource, dwIndex, szValueName, &dwValueBuffer, NULL, &dwValueType, NULL, &dwValueLength) == ERROR_SUCCESS)
		{
			LPBYTE pValue = (LPBYTE) new TCHAR[dwValueLength + 1]; // Allocate memory for the data

			if (pValue)
			{
				DWORD dwRealDataLen = dwValueLength + 1;

				if (RegQueryValueEx(hSource, szValueName, NULL, NULL, pValue, &dwRealDataLen) == ERROR_SUCCESS)
				{
					if (RegSetValueEx(hDest, szValueName, NULL, dwValueType, pValue, dwValueLength) != ERROR_SUCCESS)
					{
						delete[] pValue;
						pValue = NULL;

						iLastErrorCode_ = GetLastError();
						return false;
					}
				}
				else
				{
					delete[] pValue;
					pValue = NULL;

					iLastErrorCode_ = GetLastError();
					return false;
				}

				delete[] pValue;
				pValue = NULL;

				dwIndex++;
			}
		}
		else
			bContinue = false;
	}

	// Enumerate all subkeys in hSource, and recreate in hDest
	bContinue = true;
	dwIndex = 0;

	while (bContinue)
	{
		if (RegEnumKey(hSource, dwIndex, szValueName, _MAX_PATH) == ERROR_SUCCESS)
		{
			TCHAR szSourceKey[_MAX_PATH] = { '\0' };
			TCHAR szDestKey[_MAX_PATH] = { '\0' };

			_tcscpy_s(szSourceKey, _MAX_PATH, pszSourceKey);
			_tcscpy_s(szDestKey, _MAX_PATH, pszDestKey);

			_tcscat_s(szSourceKey, _MAX_PATH, _T("\\"));
			_tcscat_s(szSourceKey, _MAX_PATH, szValueName);

			_tcscat_s(szDestKey, _MAX_PATH, _T("\\"));
			_tcscat_s(szDestKey, _MAX_PATH, szValueName);

			if (!MoveKey(szSourceKey, szDestKey, hBaseKey))
				dwIndex++;
		}
		else
			bContinue = false;
	}

	// Now delete the original key and it's values and subkeys
	RegCloseKey(hSource);
	RegCloseKey(hDest);
	QuickDeleteKey(pszSourceKey, hBaseKey);

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

// Delete a Key
bool RegKey::QuickDeleteKey(LPCTSTR pszKeyName, HKEY hBaseKey /* = HKEY_CURRENT_USER */)
{
	if (pszKeyName == NULL)
	{
		iLastErrorCode_ = ERROR_BAD_ARGUMENTS;
		return false;
	}

	CloseKey(); // Close current active key and base key if remote

	TCHAR* pBackSlash;
	bool bRetValue = true;

	// You cannot delete a key if given a full path e.g. "A\\B"
	// We have to go back up a level to "A" and then delete

	// Take a copy of the keyName
	TCHAR* pszCopy = _tcsdup(pszKeyName);

	pBackSlash = _tcsrchr(pszCopy, _T('\\'));
	if (pBackSlash == NULL) // Not found
	{
		// No path, so specified key is just a subkey of active key
		bRetValue = RecursiveDelete(this, hBaseKey, pszKeyName);
	}
	else // Path specified
	{
		LPTSTR pszChildKeyName = pBackSlash + 1;
		*(pBackSlash) = _T('\0'); // Null terminate the parent string

		LPTSTR pszParentKey = (TCHAR*)pszCopy;
		HKEY hTempKey;

		LONG retValue = RegOpenKeyEx(hBaseKey, pszParentKey, NULL, KEY_ALL_ACCESS, &hTempKey);

		if (retValue == ERROR_SUCCESS)
		{
			bRetValue = RecursiveDelete(this, hTempKey, pszChildKeyName);
			RegCloseKey(hTempKey);
		}
		else
		{
			free(pszCopy);
			pszCopy = NULL;

			iLastErrorCode_ = GetLastError();
			return false;
		}
	}

	free(pszCopy);

	if (!bRetValue)
		return false;

	CloseKey(); // Close current active key and base key if remote

	iLastErrorCode_ = ERROR_SUCCESS;
	return true;
}

void OutputErr(LPCTSTR pBuff)
{
	if (!pBuff) return;

	OutputDebugString(pBuff);
	_tprintf(_T("%s"), pBuff);
}

// Display a system error message to the console window
void DisplaySysError(LPCTSTR pszBuff, DWORD dwErr)
{
	OutputErr((LPCTSTR)pszBuff);
}

// Find a string value within an expanded string, returns the offset if found, else string::npos
// We need to match the entire string, so that we can match '3' in the following
// 1,2,33,3 and not match the 33
tstring::size_type FindValueInExpandedString(const tstring& szData, const tstring& szSearch, tstring::size_type iValueIndex)
{
	if (szData.empty())
		return tstring::npos;

	bool bCompleted = false;
	size_t iValueOffset = 0;
	tstring szTmpVal;

	if (iValueIndex > 0)
		iValueOffset = iValueIndex;
	else
		iValueIndex = tstring::npos;

	while (!bCompleted)
	{
		if (iValueOffset >= szData.length())
		{
			bCompleted = true;
			continue;
		}

		tstring::size_type iTmpIndex = szData.find(_T(";"), iValueOffset);

		if (iTmpIndex != tstring::npos)
			szTmpVal = szData.substr(iValueOffset, iTmpIndex - iValueOffset); // Grab up to the next seperator
		else
			szTmpVal = szData.substr(iValueOffset, szData.length()); // Grab up to the end of the line

		if (szTmpVal == szSearch) // Found it so stop searching
		{
			iValueIndex = iValueOffset;
			bCompleted = true;
			continue;
		}

		iValueOffset += szTmpVal.length() + 1; // Move to the next entry
	}

	return iValueIndex;
}

// Replace ALL '~' chars with '%')
tstring DynamicCheckAndReplace(const tstring& szValue, bool& expand)
{
	tstring tmpVal = szValue;

	tstring::size_type index = tmpVal.find(_T("~"));

	if (index != tstring::npos)
		expand = true;

	while (index != tstring::npos)
	{
		tmpVal.replace(index, 1, _T("%"));
		index = tmpVal.find(_T("~"));
	}

	return tmpVal;
}

// Sets either a USER or a SYSTEM enviroment variable (Win 2000 and above)
// And the value can be a normal string or an expanded string, e.g. PATH
bool SetRegistryKey(RegKey& obKey, bool bSystem, bool bExpandedStr, const tstring& szName, const tstring& szValue)
{
	bool bRetVal = false;

	if (bExpandedStr)
		bRetVal = obKey.SetKeyValueEx(((bSystem) ? szREG_SYSTEM : szREG_USER), szName.c_str(), szValue.c_str(), (DWORD)szValue.length(), true, false, ((bSystem) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER));
	else
		bRetVal = obKey.SetKeyValue(((bSystem) ? szREG_SYSTEM : szREG_USER), szName.c_str(), szValue.c_str(), (DWORD)szValue.length(), true, false, ((bSystem) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER));

	return bRetVal;
}

// Sets either a USER or a SYSTEM enviroment variable (Win 2000 and above)
// And the value can be a normal string or an expanded string, e.g. PATH
bool DeleteRegistryKey(RegKey& obKey, bool bSystem, const tstring& szName)
{
	return obKey.DeleteKeyValue(((bSystem) ? szREG_SYSTEM : szREG_USER), szName.c_str(), false, ((bSystem) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER));
}

// Process registry task
int ProcessRegistryTask(tstring szName, tstring szValue, bool bAddValue, bool bSystemValue, bool bPrepend)
{
	// Get the size of the current registry value
	RegKey obKey;
	DWORD dwSize = obKey.GetSizeOfValue(((bSystemValue) ? szREG_SYSTEM : szREG_USER), szName.c_str(), ((bSystemValue) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER));

	DWORD iTotalLength = dwSize + (DWORD) szValue.size() + 1;
	TCHAR* pszRegkey = new TCHAR[iTotalLength];
	memset(pszRegkey, 0, iTotalLength * sizeof(TCHAR));

	bool bExpandedString = false;

	// Pre-process the string (i.e. is it expanded or dynamic)
	// Is this an expanded string ?
	if (szValue[0] == '%')
	{
		szValue = szValue.substr(1, szValue.length() - 1); // Remove the % character
		bExpandedString = true;
	}

	// If this is a dynamic string, i.e. contains "~PATH~", then replace ALL '~' chars with '%')
	szValue = DynamicCheckAndReplace(szValue, bExpandedString);

	// Does the value already exist ?
	bool bExists = obKey.GetKeyValue(((bSystemValue) ? szREG_SYSTEM : szREG_USER), szName.c_str(), pszRegkey, iTotalLength, false, ((bSystemValue) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER));
	if (bExists)
	{
		// Already exists, so we need to modify it or delete it
		// First, check the type of value, i.e. REG_SZ or REG_EXPAND_SZ as we need to process them differently
		if (obKey.OpenKey(((bSystemValue) ? szREG_SYSTEM : szREG_USER), false, ((bSystemValue) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER)))
		{
			DWORD dwLen = 0;
			DWORD dwType = REG_SZ;
			if (obKey.QueryValue(szName.c_str(), dwLen, dwType))
			{
				if (dwType == REG_EXPAND_SZ)
					bExpandedString = true;
			}

			obKey.CloseKey();
		}

		if (bAddValue) // Add the value to the registry
		{
			if (bExpandedString)
			{
				tstring szOriginalValue = pszRegkey;

				// Does it already contain our new value ?
				size_t iValueIndex = 0;
				tstring::size_type index = FindValueInExpandedString(szOriginalValue, szValue, iValueIndex);
				if (index == tstring::npos) // Did we find it ?
				{
					tstring szNewValue; // No, so add it

					if (szOriginalValue.length() > 0)
					{
						// We may need to add a semi colon seperator if the last character of the original value is not a semi colon
						if (bPrepend)
							szNewValue = szValue + _T(";") + szOriginalValue; // Add semi colon
						else
						{
							if (szOriginalValue[szOriginalValue.length() - 1] != _T(';'))
								szNewValue = szOriginalValue + _T(";") + szValue; // Add semi colon
							else
								szNewValue = szOriginalValue + szValue; // Do not add the semi colon
						}
					}
					else
						szNewValue = szValue;

					if (!SetRegistryKey(obKey, bSystemValue, true, szName, szNewValue))
					{
						DisplaySysError(_T("Set Value"), obKey.GetLastErrorCode()); // Failed
						delete[] pszRegkey; pszRegkey = NULL;
						return (obKey.GetLastErrorCode() == 0x05) ? ERR_ACCESS_DENIED : ERR_ERROR;
					}
				}
			}
			else // Just overwrite it
			{
				if (!SetRegistryKey(obKey, bSystemValue, bExpandedString, szName, szValue))
				{
					DisplaySysError(_T("Set Value"), obKey.GetLastErrorCode()); // Failed
					delete[] pszRegkey; pszRegkey = NULL;
					return (obKey.GetLastErrorCode() == 0x05) ? ERR_ACCESS_DENIED : ERR_ERROR;
				}
			}
		}
		else // Delete the entry
		{
			if (szValue.length() == 0 || !bExpandedString) // Delete the whole key
			{
				if (!obKey.DeleteKeyValue(((bSystemValue) ? szREG_SYSTEM : szREG_USER), szName.c_str(), false, ((bSystemValue) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER)))
				{
					DisplaySysError(_T("Delete Value"), obKey.GetLastErrorCode()); // Failed
					delete[] pszRegkey; pszRegkey = NULL;
					return (obKey.GetLastErrorCode() == 0x05) ? ERR_ACCESS_DENIED : ERR_ERROR;
				}
			}
			else
				if (bExpandedString) // We need to delete our bit only and leave the rest of the value alone
				{
					tstring szOriginalValue = pszRegkey;

					size_t iValueIndex = 0;
					tstring::size_type index = FindValueInExpandedString(szOriginalValue, szValue, iValueIndex);
					if (index != tstring::npos) // Did we find it ?
					{
						// We should only delete our value if it actually exists in the environment variable
						tstring szNewValue;

						if (szOriginalValue[index + szValue.length()] == _T(';')) // Any terminating ; to remove ?
							szNewValue = szOriginalValue.replace(index, szValue.length() + 1, _T(""));
						else
							szNewValue = szOriginalValue.replace(index, szValue.length(), _T(""));

						if (szNewValue[szNewValue.length() - 1] == _T(';'))
							szNewValue.replace(szNewValue.length() - 1, 1, _T(""));

						if (szNewValue.empty())
							DeleteRegistryKey(obKey, bSystemValue, szName);
						else
							if (!SetRegistryKey(obKey, bSystemValue, true, szName, szNewValue))
							{
								DisplaySysError(_T("Delete Value"), obKey.GetLastErrorCode()); // Failed
								delete[] pszRegkey; pszRegkey = NULL;
								return (obKey.GetLastErrorCode() == 0x05) ? ERR_ACCESS_DENIED : ERR_ERROR;
							}
					}
				}
		}
	}
	else // Value does NOT exist yet so create it
	{
		if (bAddValue)
		{
			bool bOK = SetRegistryKey(obKey, bSystemValue, bExpandedString, szName, szValue);

			if (!bOK)
			{
				DisplaySysError(_T("Set Value"), obKey.GetLastErrorCode()); // Failed
				delete[] pszRegkey; pszRegkey = NULL;
				return (obKey.GetLastErrorCode() == 0x05) ? ERR_ACCESS_DENIED : ERR_ERROR;
			}
		}
	}

	// Tell the system that we have changed a setting (can take 0.5 second to return)
	SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM) _T("Environment"), SMTO_ABORTIFHUNG, 500, 0);

	delete[] pszRegkey; pszRegkey = NULL;
	return ERR_SUCCESS;
}
