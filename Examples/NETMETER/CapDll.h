/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#if !defined(AFX_CapDll_H__03FA9206_C8EA_11D2_B729_0048540133F7__INCLUDED_)
#define AFX_CapDll_H__03FA9206_C8EA_11D2_B729_0048540133F7__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif // _MSC_VER >= 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols
#define MaxCapPars 10

/////////////////////////////////////////////////////////////////////////////
// CCapDll:
// See CapDll.cpp for the implementation of this class
//
#ifdef _EXPORTING   
#define CLASS_DECLSPEC __declspec(dllexport)
#else
#define CLASS_DECLSPEC __declspec(dllimport)
#endif

void CLASS_DECLSPEC InitCapDll(const char* INI);

class CLASS_DECLSPEC CCapDll
{
public:
	CCapDll();
	const char* GetFileName();
	char* SetFileName(const char* fn);
	const char* GetAdapter();
	const char* GetPath();
	const char* GetFilter();
	char* SetPath(const char * p);
	char* SetAdapter(const char* ad);
	char* SetFilter(const char* ad);
	int CaptureDialog(const char* Adapter,const char* P, CWnd* mw);
	int ChooseAdapter(const char* Adapter, CWnd* mw);
	const char* Capture(const char* file, CWnd* mw);
	~CCapDll();
private:
	char* Path;
	char* Adapter;
	char* FileName;
	char* Filter;
	int bufdim;
	int ncapture;
	int snaplen;	
	int promisquous;
	void LoadCmds();
	CString RetrieveValue(CString keyval);
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Developer Studio will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_CapDll_H__03FA9206_C8EA_11D2_B729_0048540133F7__INCLUDED_)
