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

#include "stdafx.h"
#include "CapDll.h"
#include "SelectAdapter.h"
#include "LineColl.h"
#include "..\..\include\pcap.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define SA_ERR "Unable to choose Adaptors"
#define SA_ADS "Network Cards"
#define MFR_TCPDUMPERR "Unable to Capture on this operating system"

/////////////////////////////////////////////////////////////////////////////
// CSelectAdapter dialog


CSelectAdapter::CSelectAdapter(CWnd* pParent /*=NULL*/)
	: CDialog(CSelectAdapter::IDD, pParent)
{
	//{{AFX_DATA_INIT(CSelectAdapter)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
}


void CSelectAdapter::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CSelectAdapter)
	DDX_Control(pDX, IDC_ADAPTER, m_CAdapter);
	DDX_Control(pDX, IDC_LIST1, m_ListCtrl);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CSelectAdapter, CDialog)
	//{{AFX_MSG_MAP(CSelectAdapter)
	ON_NOTIFY(HDN_ITEMCLICK, IDC_LIST1, OnSelectItem)
	ON_NOTIFY(HDN_ITEMDBLCLICK, IDC_LIST1, Ondblclickitem)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CSelectAdapter message handlers

BOOL CSelectAdapter::OnInitDialog() 
{
char ebuf[PCAP_ERRBUF_SIZE];
char devicelist[65000];
pcap_if_t *alldevs, *d;
char *devicelistptr;


	CDialog::OnInitDialog();

	/* Retrieve the device list on the local machine */
	/* Don't check for errors */
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, ebuf);

	devicelistptr= devicelist;
	devicelist[0]= 0;

	for(d=alldevs; d; d=d->next)
	{

		strcat(devicelistptr, d->name);
		devicelistptr+= strlen(d->name);

		strcat(devicelistptr, "\r\n");
		devicelistptr+= strlen("\r\n");
	}

	m_Cmd= devicelist;

	pcap_freealldevs(alldevs);

	LineCollection lc(&m_Cmd);	
    m_ListCtrl.InsertColumn(0,SA_ADS /*Adapters*/, LVCFMT_LEFT,200);
	m_ctlImage.Create(IDB_CAP_WIZ,16,0,RGB(255,0,255));
	m_ListCtrl.SetImageList(&m_ctlImage,LVSIL_SMALL);
	Update(lc);
	m_ListCtrl.SetFocus();
	m_CAdapter.SetWindowText(m_Adapter);
	return FALSE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

void CSelectAdapter::AddItem(int nItem,int nSubItem,LPCTSTR strItem,int nImageIndex)
{
	LV_ITEM lvItem;
	lvItem.mask = LVIF_TEXT;
	lvItem.iItem = nItem;
	lvItem.iSubItem = nSubItem;
	lvItem.pszText = (LPTSTR) strItem;
	if(nImageIndex != -1){
		lvItem.mask |= LVIF_IMAGE;
		lvItem.iImage = nImageIndex;
	}
	if(nSubItem == 0)
		m_ListCtrl.InsertItem(&lvItem);
	else m_ListCtrl.SetItem(&lvItem);
}

void CSelectAdapter::SelectItem(int i)
{
	LV_FINDINFO it;
	
	it.flags=LVFI_PARAM;
	it.lParam=i;
	i=m_ListCtrl.FindItem(&it);
	m_ListCtrl.SetItemState(i,0xFFFFFFFF,LVIS_SELECTED);
}

void CSelectAdapter::Update(LineCollection &lc)
{
        m_ListCtrl.DeleteAllItems();
	    int n=lc.getLineCount();
		CString t;
        for(n--;n>=0;n--)
         {
			t=lc.line(n);
			t.TrimLeft();
			t.TrimRight();
			if (strlen(t)>0)
	        AddItem(0,0,t,3);
         }
		m_ListCtrl.UpdateWindow();
		n=m_ListCtrl.GetItemCount();
		for (n--;n>=0;n--)
		{
			if (m_Adapter.CompareNoCase(m_ListCtrl.GetItemText(n,0))==0)
				{
					SelectItem(n);
					return;
				}
		}
		m_Adapter=m_ListCtrl.GetItemText(0,0);
}


void CSelectAdapter::OnOK() 
{
	int i,n=m_ListCtrl.GetItemCount();
	for(i=0;i<n;i++)
	{
		if (m_ListCtrl.GetItemState(i,LVIS_SELECTED))
		{
			m_Adapter=m_ListCtrl.GetItemText(i,0);
			break;
		}
	}
	if(i==n) 
	{
		if (n!=0) m_Adapter=m_ListCtrl.GetItemText(0,0);
		else m_Adapter="";
	}
	
	CDialog::OnOK();
}

void CSelectAdapter::OnSelectItem(NMHDR* pNMHDR, LRESULT* pResult) 
{
	HD_NOTIFY *phdn = (HD_NOTIFY *) pNMHDR;

	int i,n=m_ListCtrl.GetItemCount();
	for(i=0;i<n;i++)
	{
		if (m_ListCtrl.GetItemState(i,LVIS_SELECTED))
		{
			m_Adapter=m_ListCtrl.GetItemText(i,0);
			break;
		}
	}
	if(i==n) 
	{
		if (n!=0) m_Adapter=m_ListCtrl.GetItemText(0,0);
		else m_Adapter="";
	}
	m_CAdapter.SetWindowText(m_Adapter);
	
	*pResult = 0;
}

void CSelectAdapter::Ondblclickitem(NMHDR* pNMHDR, LRESULT* pResult) 
{
	HD_NOTIFY *phdn = (HD_NOTIFY *) pNMHDR;

	AfxMessageBox("Error setting the filter");

	int i,n=m_ListCtrl.GetItemCount();
	for(i=0;i<n;i++)
	{
		if (m_ListCtrl.GetItemState(i,LVIS_SELECTED))
		{
			m_Adapter=m_ListCtrl.GetItemText(i,0);
			break;
		}
	}
	if(i==n) 
	{
		if (n!=0) m_Adapter=m_ListCtrl.GetItemText(0,0);
		else m_Adapter="";
	}

	*pResult = 0;
	SendMessage(WM_CLOSE,0,0);

}
