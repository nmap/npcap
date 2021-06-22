/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2021 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and the free version may not be redistributed  *
 * or incorporated into other software without special permission from     *
 * the Nmap Project. It also has certain usage limitations described in    *
 * the LICENSE file included with Npcap and also available at              *
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header          *
 * summarizes a few important aspects of the Npcap license, but is not a   *
 * substitute for that full Npcap license agreement.                       *
 *                                                                         *
 * We fund the Npcap project by selling two commercial licenses:           *
 *                                                                         *
 * The Npcap OEM Redistribution License allows companies distribute Npcap  *
 * OEM within their products. Licensees generally use the Npcap OEM        *
 * silent installer, ensuring a seamless experience for end                *
 * users. Licensees may choose between a perpetual unlimited license or    *
 * an annual term license, along with options for commercial support and   *
 * updates. Prices and details: https://nmap.org/npcap/oem/redist.html     *
 *                                                                         *
 * The Npcap OEM Internal-Use License is for organizations that wish to    *
 * use Npcap OEM internally, without redistribution outside their          *
 * organization. This allows them to bypass the 5-system usage cap of the  *
 * Npcap free edition. It includes commercial support and update options,  *
 * and provides the extra Npcap OEM features such as the silent installer  *
 * for automated deployment. Prices and details:                           *
 * https://nmap.org/npcap/oem/internal.html                                *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests, but we normally recommend that such        *
 * authors instead ask their users to download and install Npcap           *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  You are encouraged to submit such patches as Github pull     *
 * requests or by email to fyodor@nmap.org.  If you wish to specify        *
 * special license conditions or restrictions on your contributions, just  *
 * say so when you send them. Otherwise, it is understood that you are     *
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,  *
 * modify, and relicence your code contributions so that we may (but are   *
 * not obligated to) incorporate them into Npcap.                          *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranty rights    *
 * and commercial support are available for the OEM Edition described      *
 * above.                                                                  *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
 ***************************************************************************/
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
