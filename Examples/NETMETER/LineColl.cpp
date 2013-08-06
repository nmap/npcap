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

#include "LineColl.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

LineCollection::LineCollection(CString *s,int skip)
{
	m_Skip=skip;
	if(s==NULL) return;
	*this=*s;
}

LineCollection::LineCollection(CArchive &ar,int skip)
{
	if (ar.IsStoring())
	{
		return;
	}
	else
	{
		m_Skip=skip;
		CString s;
		int i,j;
		vect.SetSize(0);
		for(i=0,j=0;ar.ReadString(s);i++)
		{
			if(m_Skip && s=="") continue;
			vect.SetSize(j+1);
			vect[j]=s;
			j++;
		}
	}
}

LineCollection::~LineCollection()
{
}

int LineCollection::GetSize()
{
	return vect.GetSize();
}

CString & LineCollection::operator =(CString &s)
{
	int i,l,n,t=0;
	l=s.GetLength();
	vect.SetSize(0);
	for(i=0,n=0;i<l;i++)
	{
		if ((s)[i]=='\n')
		{
			if(m_Skip && i>0 && (s)[i-1]=='\n') continue;
			vect.SetSize(t+1);
			vect[t]=(s).Mid(n,i-n-1);
			t++;
			n=i+1;
		}
	}
	return s;
}

void LineCollection::clear()
{
	vect.SetSize(0);
}

