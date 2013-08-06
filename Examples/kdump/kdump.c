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

#error At the moment the kernel dump feature is not supported in the driver

main(int argc, char **argv) {
	
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, i=0;
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("kdump: saves the network traffic to file using WinPcap kernel-level dump faeature.\n");
	printf("\t Usage: %s [adapter] | dump_file_name max_size max_packs\n", argv[0]);
	printf("\t Where: max_size is the maximum size that the dump file will reach (0 means no limit)\n");
	printf("\t Where: max_packs is the maximum number of packets that will be saved (0 means no limit)\n\n");


	if(argc < 5){

		/* The user didn't provide a packet source: Retrieve the device list */
		if (pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
			exit(1);
		}
		
		/* Print the list */
		for(d=alldevs; d; d=d->next)
		{
			printf("%d. %s", ++i, d->name);
			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}
		
		if(i==0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
		}
		
		printf("Enter the interface number (1-%d):",i);
		scanf("%d", &inum);
		
		if(inum < 1 || inum > i)
		{
			printf("\nInterface number out of range.\n");
			/* Free the device list */
			return -1;
		}
		
		/* Jump to the selected adapter */
		for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
		
		/* Open the device */
		if ( (fp = pcap_open_live(d->name, 100, 1, 20, errbuf) ) == NULL)
		{
			fprintf(stderr,"\nError opening adapter\n");
			return -1;
		}

		/* Free the device list */
		pcap_freealldevs(alldevs);

		/* Start the dump */
		if(pcap_live_dump(fp, argv[1], atoi(argv[2]), atoi(argv[3]))==-1){
			printf("Unable to start the dump, %s\n", pcap_geterr(fp));
			return -1;
		}
	}
	else{
		
		/* Open the device */
		if ( (fp= pcap_open_live(argv[1], 100, 1, 20, errbuf) ) == NULL)
		{
			fprintf(stderr,"\nError opening adapter\n");
			return -1;
		}

		/* Start the dump */
		if(pcap_live_dump(fp, argv[0], atoi(argv[1]), atoi(argv[2]))==-1){
			printf("Unable to start the dump, %s\n", pcap_geterr(fp));
			return -1;
		}
	}

	/* Wait until the dump finishes, i.e. when  max_size or max_packs is reached*/
	pcap_live_dump_ended(fp, TRUE);
	
	/* Close the adapter, so that the file is correctly flushed */
	pcap_close(fp);

	return 0;
}
