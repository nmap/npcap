
#include <windows.h>
#include <windowsx.h>
#include <vector>
using namespace std;

typedef std::basic_string<TCHAR> tstring;

tstring OperationMode2String(ULONG OperationMode);
ULONG String2OperationMode(tstring strOperationMode);

tstring PhyType2String(ULONG PhyType);

tstring printArray(vector<tstring> nstr);

tstring executeCommand(TCHAR* cmd);

void initAdapterList();

tstring getGuidFromAdapterName(tstring strAdapterName);

BOOL makeOIDRequest(tstring strAdapterGUID, ULONG iOid, BOOL bSet, PVOID pData, ULONG ulDataSize);

BOOL GetCurrentOperationMode(tstring strGUID, tstring &strMode);
BOOL SetCurrentOperationMode(tstring strGUID, tstring strMode);

BOOL GetOperationModeCapability(tstring strGUID, tstring &strModes);

BOOL GetSupportedPhyTypes(tstring strGUID, vector<tstring> &strPhyTypes);

BOOL GetCurrentChannel(tstring strGUID, ULONG &ulChannel);
BOOL SetCurrentChannel(tstring strGUID, ULONG ulChannel);

BOOL GetCurrentFrequency(tstring strGUID, ULONG &ulFrequency);
BOOL SetCurrentFrequency(tstring strGUID, ULONG ulFrequency);
