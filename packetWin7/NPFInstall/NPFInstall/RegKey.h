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

RegKey.h

Abstract:

This is used for updating PATH in registry.

--*/

#ifndef HDR_REGKEY_INCLUDE
#define HDR_REGKEY_INCLUDE

// Support for the Windows Registry

#if	!defined(STRICT)
#define STRICT 1
#endif

// Includes
#if !defined(_WINDOWS_)
#include <windows.h>
#endif

#include <vector>
using namespace std;

typedef std::basic_string<TCHAR> tstring;

#include <tchar.h>

class RegKey
{
private:
	DWORD iLastErrorCode_; // The error code for the last error that occurred

	HKEY hTheKey_; // The active key
	HKEY hBaseKey_; // The base key, either HKEY_LOCAL... or another machine

	bool bRemote_; // Connected to a remote machine ?
	TCHAR* pszComputerName_;	// Which computer to connect to, NULL means local

	FILETIME obLastWriteTime_; // Last write time ( Used for Enumerate() functions )

	bool IntSetValue(LPCTSTR pszValueName, const BYTE* pValue, DWORD dwValueLength, DWORD dwValueType); // Generic SetValue()
	bool IntGetValue(LPCTSTR pszValueName, BYTE& pValue, DWORD& dwValueLength); // Generic GetValue()

	bool ConnectRemote(HKEY hKeyToOpen, LPCTSTR pszComputerName); // Connect to a remote computer's registry

	static bool RecursiveDelete(RegKey* pTheCallingClass, HKEY hTheKey, LPCTSTR pszKeyName);

public:
	RegKey();
	~RegKey();

	// Can either use these (for more detailed control) or the Shortcut functions 
	// In most cases, the shortcut functions will be enough

	// Opens/Creates a key and make it the active key
	bool OpenKey(LPCTSTR pszKeyName, bool bCreateIfNoExist = false, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL);

	// Creates and opens a new key - key becomes active key 
	bool CreateKey(LPCTSTR pszKeyName, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL);

	void CloseKey(); // Close the active key, and remote key if necessary
	bool DeleteKey(LPCTSTR pszKeyName); // Deletes a key and all values and subkeys

	// Get all the subkeys for the active key, returns REG_NO_MORE_ITEMS when no more items
	bool EnumerateKeys(LPTSTR pszSubkeyName, const DWORD dwIndex);

	// Get information on active key
	bool QueryKey(DWORD& dwNumSubKeys, DWORD& dwMaxSubKeyName, DWORD& dwNumValues, DWORD& dwMaxValueName, DWORD& dwMaxValueDataSize, FILETIME& lastWriteTime);

	bool Flush(); // Flushes the active key ( Write to hard disk )

	// Various Value functions
	bool QueryValue(LPCTSTR pszValueName, DWORD& dwValueLength, DWORD& dwValueType); // Retrieves the size and type of a value for the active key
	bool DeleteValue(LPCTSTR pszValueName); // Deletes a value from the currently open active key

	// Get all the values for the active key, returns REG_NO_MORE_ITEMS when no more items
	bool EnumerateValues(LPTSTR pszValueName, LPBYTE lpValue, DWORD& dwValueSize, DWORD& dwValueType, const DWORD dwIndex);

	// Set Value
	bool SetValue(LPCTSTR pszValueName, DWORD dwValue); // Sets a DWORD value for the active key
	bool SetValue(LPCTSTR pszValueName, LPCTSTR pszValue, DWORD dwValueLength); // Sets a STRING value for the active key
	bool SetValue(LPCTSTR pszValueName, const BYTE* pValue, DWORD dwValueLength); // Sets a BINARY value for the active key
	bool SetValueEx(LPCTSTR pszValueName, LPCTSTR pszValue, DWORD dwValueLength); // Sets an EXPANDED STRING value for the active key

	// Get Value
	bool GetValue(LPCTSTR pszValueName, DWORD& dwValue); // Gets a DWORD value for the active key
	bool GetValue(LPCTSTR pszValueName, LPTSTR pszValue, DWORD& dwValueLength); // Gets a STRING value for the active key
	bool GetValue(LPCTSTR pszValueName, BYTE& pValue, DWORD& dwValueLength); // Gets a BINARY value for the active key

	//////////////////////////
	// Configuration functions

	// Saves a registry tree into the specified file/path from the specified key position
	bool SaveRegistry(LPCTSTR pszFileName, LPCTSTR pszKeyName, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL);

	// Restores a saved registry tree from the specified file to the specified key position
	bool RestoreRegistry(LPCTSTR pszFileName, LPCTSTR pszKeyName, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL);

	/////////////////
	// Misc Functions

	// Notify user of a change in the registry ( Local computer only )
	// The notification flags can be or'd together
	bool NotifyChange(LPCTSTR pszKeyName, DWORD dwNotifyfilter, bool bWatchSubKeys = false, HANDLE hEvent = NULL, HKEY hBaseKey = HKEY_CURRENT_USER);

	/////////////////////
	// Shortcut functions
	// These functions perform an open automatically, and close if necessary
	// Saves having to do an Open(), Set(), Close() sequence.

	// Returns the size of the specified registry value (in bytes)
	DWORD GetSizeOfValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL);

	// Opens/Creates a key, sets a value within the key and makes it the active key if active = true, else closes the key
	bool SetKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, DWORD dwValue
		, bool bCreateIfNoExist = false, bool bActive = false
		, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL);

	bool SetKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, LPCTSTR pszValue, DWORD dwValueLength
		, bool bCreateIfNoExist = false, bool bActive = false
		, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL);

	bool SetKeyValueEx(LPCTSTR pszKeyName, LPCTSTR pszValueName, LPCTSTR pszValue, DWORD dwValueLength
		, bool bCreateIfNoExist = false, bool bActive = false
		, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL); // Expanded String

	bool SetKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, const BYTE* pValue, DWORD dwValueLength
		, bool bCreateIfNoExist = false, bool bActive = false
		, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL);

	// Opens a key and retrieves a value
	// Make it the active key if active = true, else close the key
	bool GetKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, DWORD& dwValue
		, bool bActive = false, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL);

	bool GetKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, LPTSTR pszValue, DWORD dwValueLength
		, bool bActive = false, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL);

	bool GetKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, BYTE& pValue, DWORD dwValueLength
		, bool bActive = false, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL);

	// Opens a key, deletes a value from the key and makes key active if required
	bool DeleteKeyValue(LPCTSTR pszKeyName, LPCTSTR pszValueName, bool bActive = false, HKEY hBaseKey = HKEY_CURRENT_USER, LPCTSTR pszMachineName = NULL);

	bool MoveKey(LPCTSTR pszSourceKey, LPCTSTR pszDestKey, HKEY hBaseKey = HKEY_CURRENT_USER); // Move a key, it's subkeys and all values

	// Delete a Key and all of the values and subkeys
	bool QuickDeleteKey(LPCTSTR pszKeyName, HKEY hBaseKey = HKEY_CURRENT_USER);

	// Support functions
	DWORD GetLastErrorCode() const { return iLastErrorCode_; };
};

#endif	// HDR_REGKEY_INCLUDE

int ProcessRegistryTask(tstring szName, tstring szValue, bool bAddValue, bool bSystemValue, bool bPrepend);
