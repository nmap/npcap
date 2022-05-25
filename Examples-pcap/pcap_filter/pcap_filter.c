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


#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#define MAX_PRINT 80
#define MAX_LINE 16

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


int usage(int ret);


int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	char *source = NULL;
	char *ofilename = NULL;
	char *filter = NULL;
	int i;
	pcap_dumper_t *dumpfile;
	struct bpf_program fcode;
	bpf_u_int32 NetMask;
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int snaplen = 65536;
	
#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	if (argc <= 1)
	{
		return usage(-1);
	}

	/* Parse parameters */
	for(i=1;i < argc - 1; i+= 2)
	{
		if (argv[i][0] != '-') {
			fprintf(stderr, "Invalid option '%s'\n", argv[i]);
			return usage(1);
		}
		switch (argv[i] [1])
		{
			case 's':
				source=argv[i+1];
				break;
			
			case 'o':
				ofilename=argv[i+1];
				break;

			case 'f':
				filter=argv[i+1];
				break;
			case 'l':
				snaplen = atoi(argv[i+1]);
				if (snaplen <= 0 || snaplen == INT_MAX) {
					fprintf(stderr, "Invalid snaplen; must be positive integer smaller than INT_MAX\n");
					return usage(1);
				}
				break;
			default:
				fprintf(stderr, "Invalid option '%s'\n", argv[i]);
				return usage(1);
		}
	}
	
	// open a capture from the network
	if (source != NULL)
	{
		fp = pcap_create(source, errbuf);
		if (fp == NULL) {
			fprintf(stderr, "pcap_create error: %s\n", errbuf);
			return -2;
		}
		res = pcap_set_snaplen(fp, snaplen);
		if (res < 0) {
			fprintf(stderr, "pcap_set_snaplen error: %s\n", pcap_statustostr(res));
			return -2;
		}
		res = pcap_set_promisc(fp, 1);
		if (res < 0) {
			fprintf(stderr, "pcap_set_promisc error: %s\n", pcap_statustostr(res));
			return -2;
		}
		res = pcap_set_timeout(fp, 1000);
		if (res < 0) {
			fprintf(stderr, "pcap_set_timeout error: %s\n", pcap_statustostr(res));
			return -2;
		}
		res = pcap_activate(fp);
		if (res < 0) {
			fprintf(stderr, "pcap_activate error: %s\n", pcap_statustostr(res));
			return -2;
		}
	}
	else return usage(1);

	if (filter != NULL)
	{
		// We should loop through the adapters returned by the pcap_findalldevs_ex()
		// in order to locate the correct one.
		//
		// Let's do things simpler: we suppose to be in a C class network ;-)
		NetMask=0xffffff;

		//compile the filter
		if((res = pcap_compile(fp, &fcode, filter, 1, NetMask)) < 0)
		{
			fprintf(stderr,"\nError compiling filter: %s\n", pcap_statustostr(res));

			pcap_close(fp);
			return -3;
		}

		//set the filter
		if((res = pcap_setfilter(fp, &fcode))<0)
		{
			fprintf(stderr,"\nError setting the filter: %s\n", pcap_statustostr(res));

			pcap_close(fp);
			return -4;
		}

	}

	//open the dump file
	if (ofilename != NULL)
	{
		dumpfile= pcap_dump_open(fp, ofilename);

		if (dumpfile == NULL)
		{
			fprintf(stderr,"\nError opening output file: %s\n", pcap_geterr(fp));

			pcap_close(fp);
			return -5;
		}
	}
	else return usage(1);

	//start the capture
 	while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
	{

		if(res == 0)
		/* Timeout elapsed */
		continue;

		//save the packet on the dump file
		pcap_dump((unsigned char *) dumpfile, header, pkt_data);

	}

	pcap_close(fp);
	pcap_dump_close(dumpfile);

	return 0;
}


int usage(int ret)
{

	printf("\npf - Generic Packet Filter.\n");
	printf("\nUsage:\npf -s source -o output_file_name [-f filter_string] [-l snaplen]\n\n");
	return ret;
}
