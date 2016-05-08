
#include <windows.h>
#include <windowsx.h>
#include <vector>
using namespace std;

typedef std::basic_string<TCHAR> tstring;

tstring executeCommand(TCHAR* cmd);

void initAdapterList();

tstring getGuidFromAdapterName(TCHAR *pszAdapterName);

BOOL makeOIDRequest(TCHAR *pszAdapterGUID, BOOL bSet, ULONG *pFlag);
