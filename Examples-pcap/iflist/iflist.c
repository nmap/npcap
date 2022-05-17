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

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>

#ifndef _WIN32
	#include <sys/socket.h>
	#include <netinet/in.h>
#else
	#include <winsock2.h>
#endif

#ifdef _WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}

#endif


// Function prototypes
void ifprint(pcap_if_t *d);
const char* iptos(struct sockaddr *sockaddr);


int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE+1];
	
#ifdef _WIN32
	WSADATA wsadata;
	int err = WSAStartup(MAKEWORD(2,2), &wsadata);

	if (err != 0) {
		fprintf(stderr, "WSAStartup failed: %d\n", err);
		exit(1);
	}
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		WSACleanup();
		exit(1);
	}
#endif
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		WSACleanup();
		exit(1);
	}
	
	/* Scan the list printing every entry */
	for(d=alldevs;d;d=d->next)
	{
		ifprint(d);
	}

	/* Free the device list */
	pcap_freealldevs(alldevs);

	WSACleanup();
	return 0;
}



/* Print all the available information on the given interface */
void ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;

  /* Name */
  printf("%s\n",d->name);

  /* Description */
  if (d->description)
    printf("\tDescription: %s\n",d->description);

  /* Loopback Address*/
  printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

  /* IP addresses */
  for(a=d->addresses;a;a=a->next) {
    printf("\tAddress Family: #%d\n",a->addr->sa_family);

    switch(a->addr->sa_family)
    {
      case AF_INET:
        printf("\tAddress Family Name: AF_INET\n");
        break;

      case AF_INET6:
        printf("\tAddress Family Name: AF_INET6\n");
        break;

      default:
        printf("\tAddress Family Name: Unknown\n");
        break;
    }
    if (a->addr && a->addr->sa_family > 0)
      printf("\tAddress: %s\n",iptos(a->addr));
    if (a->netmask && a->netmask->sa_family > 0)
      printf("\tNetmask: %s\n",iptos(a->netmask));
    if (a->broadaddr && a->broadaddr->sa_family > 0)
      printf("\tBroadcast Address: %s\n",iptos(a->broadaddr));
    if (a->dstaddr && a->dstaddr->sa_family > 0)
      printf("\tDestination Address: %s\n",iptos(a->dstaddr));
  }
  printf("\n");
}

#define ADDR_STR_MAX 128
const char* iptos(struct sockaddr *sockaddr)
{
  static char address[ADDR_STR_MAX] = {0};
  int gni_error = 0;

  gni_error = getnameinfo(sockaddr,
      sizeof(struct sockaddr_storage),
      address,
      ADDR_STR_MAX,
      NULL,
      0,
      NI_NUMERICHOST);
  if (gni_error != 0)
  {
    fprintf(stderr, "getnameinfo: %s\n", gai_strerror(gni_error));
    return "ERROR!";
  }

  return address;
}
