
#include <windows.h>
#include <vector>
using namespace std;

typedef std::basic_string<TCHAR> tstring;

wstring executeCommand(wchar_t* cmd);

void initAdapterList();

tstring getGuidFromAdapterName(TCHAR *pszAdapterName);
