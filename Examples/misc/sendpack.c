#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>
#include "misc.h"


void main(int argc, char **argv)
{
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
u_char packet[100];
int i;

    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }

	/* Check the validity of the command line */
	if (argc != 2)
	{
		printf("usage: %s interface (e.g. 'rpcap://eth0')", argv[0]);
		return;
	}
    
	/* Open the output device */
	if ( (fp= pcap_open(argv[1],			// name of the device
						100,				// portion of the packet to capture (only the first 100 bytes)
						PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
						1000,				// read timeout
						NULL,				// authentication on the remote machine
						errbuf				// error buffer
						) ) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", argv[1]);
		return;
	}

	i = 0;
	switch(pcap_datalink(fp))
	{
		case DLT_NULL:
			// Pretend IPv4
			packet[i++] = 2;
			packet[i++] = 0;
			packet[i++] = 0;
			packet[i++] = 0;
			break;
		case DLT_EN10MB:
			/* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
			while (i < 6)
				packet[i++]=1;

			/* set mac source to 2:2:2:2:2:2 */
			while (i < 12)
				packet[i++]=2;
			break;
		default:
			fprintf(stderr, "\nError, unknown data-link type %u\n", pcap_datalink(fp));
			return 4;
	}
	
	/* Fill the rest of the packet */
	for(;i<100;i++)
	{
		packet[i]=(u_char)i;
	}

	/* Send down the packet */
	if (pcap_sendpacket(fp, packet, 100 /* size */) != 0)
	{
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
		return;
	}

	return;
}
