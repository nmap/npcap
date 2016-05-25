// WlanRecord.h
//

#include <vector>
using namespace std;

typedef std::basic_string<TCHAR> tstring;

#ifdef UNICODE
#define RPC_TSTR RPC_WSTR
#else
#define RPC_TSTR RPC_CSTR
#endif

tstring printArray(vector<tstring> nstr);

vector<tstring> getWlanAdapterGuids();