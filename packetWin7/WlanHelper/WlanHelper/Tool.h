
#include <windows.h>
#include <vector>
using namespace std;

typedef std::basic_string<TCHAR> tstring;

tstring executeCommand(TCHAR* cmd);

void initAdapterList();

tstring getGuidFromAdapterName(TCHAR *pszAdapterName);
