
#include <windows.h>
#include <windowsx.h>
#include <vector>
using namespace std;

typedef std::basic_string<TCHAR> tstring;

tstring OperationMode2String(ULONG OperationMode);
ULONG String2OperationMode(tstring strOperationMode);

tstring executeCommand(TCHAR* cmd);

void initAdapterList();

tstring getGuidFromAdapterName(tstring strAdapterName);

BOOL makeOIDRequest_ULONG(tstring strAdapterGUID, ULONG iOid, BOOL bSet, ULONG *pFlag);
BOOL makeOIDRequest_DOT11_CURRENT_OPERATION_MODE(tstring strAdapterGUID, ULONG iOid, BOOL bSet, DOT11_CURRENT_OPERATION_MODE *pFlag);
BOOL makeOIDRequest_DOT11_OPERATION_MODE_CAPABILITY(tstring strAdapterGUID, ULONG iOid, BOOL bSet, DOT11_OPERATION_MODE_CAPABILITY *pFlag);

BOOL GetCurrentOperationMode(tstring strGUID, tstring &strMode);
BOOL SetCurrentOperationMode(tstring strGUID, tstring strMode);

BOOL GetOperationModeCapability(tstring strGUID, tstring &strModes);

BOOL GetCurrentChannel(tstring strGUID, ULONG &ulChannel);
BOOL SetCurrentChannel(tstring strGUID, ULONG ulChannel);

BOOL GetCurrentFrequency(tstring strGUID, ULONG &ulFrequency);
BOOL SetCurrentFrequency(tstring strGUID, ULONG ulFrequency);
