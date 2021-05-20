#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

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


int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[100];
	int i;
	
#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	/* Check the validity of the command line */
	if (argc != 2)
	{
		printf("usage: %s interface", argv[0]);
		return 1;
	}
    
	/* Open the adapter */
	if ((fp = pcap_open_live(argv[1],		// name of the device
							 65536,			// portion of the packet to capture. It doesn't matter in this case 
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", argv[1]);
		return 2;
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
		packet[i]= (u_char)i;
	}

	/* Send down the packet */
	if (pcap_sendpacket(fp,	// Adapter
		packet,				// buffer with the packet
		100					// size
		) != 0)
	{
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
		return 3;
	}

	pcap_close(fp);	
	return 0;
}

