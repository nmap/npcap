
#include <windows.h>
#include <windowsx.h>
#include <vector>
using namespace std;

typedef std::basic_string<TCHAR> tstring;

tstring executeCommand(TCHAR* cmd);

void initAdapterList();

tstring getGuidFromAdapterName(tstring strAdapterName);

BOOL makeOIDRequest_ULONG(tstring strAdapterGUID, ULONG iOid, BOOL bSet, ULONG *pFlag);

BOOL makeOIDRequest_DOT11_CURRENT_OPERATION_MODE(tstring strAdapterGUID, ULONG iOid, BOOL bSet, DOT11_CURRENT_OPERATION_MODE *pFlag);
