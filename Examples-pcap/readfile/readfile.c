#include <stdio.h>
#include <pcap.h>

#define LINE_LEN 16
#define TIMEVAL_AFTER(a, b) (((a).tv_sec > (b).tv_sec) || ((a).tv_sec == (b).tv_sec && (a).tv_usec > (b).tv_usec))
#define TIMEVAL_BEFORE(a, b) (((a).tv_sec < (b).tv_sec) || ((a).tv_sec == (b).tv_sec && (a).tv_usec < (b).tv_usec))

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

void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

struct state {
	int verify;
	const struct pcap_pkthdr *first;
	const struct pcap_pkthdr *prev;
	pcap_t *p;
};

int main(int argc, char **argv)
{
	pcap_t *fp;
	char *filename = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct state st;
	st.verify = 0;
	st.first = NULL;
	st.prev = NULL;
	
#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	if (argc == 3 && strcmp(argv[1], "-v") == 0) {
		filename = argv[2];
		st.verify = 1;
	}
	else if(argc != 2)
	{	
		printf("usage: %s [-v] filename", argv[0]);
		return -1;

	}
	else
		filename = argv[1];
	
	/* Open the capture file */
	if ((fp = pcap_open_offline(filename, // name of the device
					errbuf // error buffer
				   )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s: %s\n", filename, errbuf);
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	st.p = fp;
	if (0 != pcap_loop(fp, 0, dispatcher_handler, (u_char *) &st)) {
		fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(fp));
		pcap_close(fp);
		return -1;
	}

	if (st.prev == NULL || st.first == NULL) {
		fprintf(stderr, "No packets processed!\n");
		pcap_close(fp);
		return -1;
	}

	if (!TIMEVAL_AFTER(st.prev->ts, st.first->ts)) {
		fprintf(stderr, "Timestamps do not increase: %lu.%06lu\n", st.prev->ts.tv_sec, st.prev->ts.tv_usec);
		pcap_close(fp);
		return -1;
	}
	pcap_close(fp);
	return 0;
}



void dispatcher_handler(u_char *temp1, 
						const struct pcap_pkthdr *header, 
						const u_char *pkt_data)
{
	u_int i=0;
	
	struct state *st = (struct state *) temp1;
	if (st->first == NULL) {
		st->first = header;
	}

	if (st->verify && st->prev != NULL) {
		/* Default timestamp mode is monotonically increasing */
		if (TIMEVAL_BEFORE(header->ts, st->prev->ts)) {
			fprintf(stderr, "Backwards timestamp!\n");
			pcap_breakloop(st->p);
		}
	}

	/* print pkt timestamp and pkt len */
	printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);			
	
	/* Print the packet */
	for (i=1; (i < header->caplen + 1 ) ; i++)
	{
		printf("%.2x ", pkt_data[i-1]);
		if ( (i % LINE_LEN) == 0) printf("\n");
	}
	
	printf("\n\n");		
	st->prev = header;
}
