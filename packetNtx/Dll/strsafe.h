#ifndef __STRSAFE_GCC__383773443
#define __STRSAFE_GCC__383773443

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#ifdef _MSC_VER
#error Trying to use strsafe.h for GCC within Visual Studio
#endif

static int vsnprintf(char *buffer,size_t count, const char *format, va_list argptr )
{
	return vsprintf(buffer, format, argptr);
}


static void StringCchPrintfA(char *pszDest,size_t cbDest, char *pszFormat, ...)
 {
	va_list marker;
	va_start( marker, pszFormat );     /* Initialize variable arguments. */

	if (cbDest == 0 || pszDest == NULL || pszFormat == NULL)
		return;

	
	pszDest[cbDest - 1] = '\0';
	vsnprintf(pszDest, cbDest - 1, pszFormat,  marker);

	va_end(marker);
}

static void StringCchPrintfW( WCHAR *pszDest,size_t cbDest, WCHAR *pszFormat, ...)
 {
	va_list marker;
	va_start( marker, pszFormat );     /* Initialize variable arguments. */

	if (cbDest == 0 || pszDest == NULL || pszFormat == NULL)
		return;

	
	pszDest[cbDest - 1] = L'\0';
	_vsnwprintf(pszDest, cbDest - 1, pszFormat,  marker);

	va_end(marker);
}


static void StringCchCopyA(char *pszDest,size_t cbDest, const char* pszSrc)
{
	if (cbDest == 0 || pszDest == NULL || pszSrc == NULL)
		return;

	pszDest[cbDest - 1] = '\0';
	
	strncpy(pszDest, pszSrc, cbDest - 1);

}

static void StringCchCatA(char* pszDest, size_t cbDest,const char* pszSrc)
{
	if (cbDest == 0 || pszDest == NULL || pszSrc == NULL)
		return;

	pszDest[cbDest - 1] = '\0';

	strncat(pszDest, pszSrc, cbDest - 1);

}

#ifdef UNICODE
#define StringCchPrintf StringCchPrintfW
#else
#define StringCchPrintf StringCchPrintfA
#endif


#endif
