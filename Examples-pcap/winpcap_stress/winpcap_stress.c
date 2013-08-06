/*============================================================================*
 * FILE: winpcap_stress.c
 *============================================================================*
 *
 * COPYRIGHT (C) 2006 BY
 *          CACE TECHNOLOGIES, INC., DAVIS, CALIFORNIA
 *          ALL RIGHTS RESERVED.
 *
 *          THIS SOFTWARE IS FURNISHED UNDER A LICENSE AND MAY BE USED AND
 *          COPIED ONLY IN ACCORDANCE WITH THE TERMS OF SUCH LICENSE AND WITH
 *          THE INCLUSION OF THE ABOVE COPYRIGHT NOTICE.  THIS SOFTWARE OR ANY
 *          OTHER COPIES THEREOF MAY NOT BE PROVIDED OR OTHERWISE MADE
 *          AVAILABLE TO ANY OTHER PERSON.  NO TITLE TO AND OWNERSHIP OF THE
 *          SOFTWARE IS HEREBY TRANSFERRED.
 *
 *          THE INFORMATION IN THIS SOFTWARE IS SUBJECT TO CHANGE WITHOUT
 *          NOTICE AND SHOULD NOT BE CONSTRUED AS A COMMITMENT BY CACE TECNOLOGIES
 *
 *===========================================================================*
 *
 * This program is a generic "stress test" for winpcap. It creates several threads
 * each of which opens an adapter, captures some packets and then closes it.
 * The user can specify:
 *
 *  - the number of threads
 *  - the number of read operations that every thread performs before exiting
 *
 * The program prints statistics before exiting.
 *
 *===========================================================================*/

/////////////////////////////////////////////////////////////////////
// Program parameters
/////////////////////////////////////////////////////////////////////
#undef STRESS_AIRPCAP_TRANSMISSION
#define NUM_THREADS 16
#define MAX_NUM_READS 500
#define MAX_NUM_WRITES 10000
#define READ_TIMEOUT	100

#define WRITES_FREQUENCY 2	// This constant specifies how often a thread will transmit instead of receiving
							// packets. 
							//   - 0 means no Tx threads 
							//   - 1 means all threads are Tx
							//   - 2 means that 1 thread every 2 is Tx
							//   - 3 means that 1 thread every 3 is Tx 
							//   ...and so on

#undef INJECT_FILTERS

/////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include <pcap.h>

#ifdef STRESS_AIRPCAP_TRANSMISSION
#include <airpcap.h>
#endif

#define LINE_LEN 16


#define FILTER "ether[80:1] < 128 || ether[81:1] > 127 || ether[82:1] < 180 || ether[83:1] > 181" \
			"|| ether[84:1] < 128 || ether[85:1] > 127 || ether[86:1] < 180 || ether[87:1] > 181" \
			"|| ether[88:1] < 128 || ether[89:1] > 127 || ether[90:1] < 180 || ether[91:1] > 181" \
			"|| ether[92:1] < 128 || ether[93:1] > 127 || ether[94:1] < 180 || ether[95:1] > 181" \
			"|| ether[96:1] < 128 || ether[97:1] > 127 || ether[98:1] < 180 || ether[99:1] > 181" \
			"|| ether[100:1] < 128 || ether[101:1] > 127 || ether[102:1] < 180 || ether[103:1] > 181" \
			"|| ether[104:1] < 128 || ether[105:1] > 127 || ether[106:1] < 180 || ether[107:1] > 181" \
			"|| ether[108:1] < 128 || ether[109:1] > 127 || ether[110:1] < 180 || ether[111:1] > 181" \


u_int n_iterations = 0;
u_int n_packets = 0;
u_int n_timeouts = 0;
u_int n_open_errors = 0;
u_int n_read_errors = 0;
u_int n_write_errors = 0;
u_int n_findalldevs_errors = 0;
u_int n_setfilters = 0;
u_int thread_id = 0;

CRITICAL_SECTION print_cs;

#define MAX_TX_PACKET_SIZE 1604
u_char pkt_to_send[MAX_TX_PACKET_SIZE];


/////////////////////////////////////////////////////////////////////
// Radiotap header. Used for 802.11 transmission
/////////////////////////////////////////////////////////////////////

#ifndef __MINGW32__
#pragma pack(push)
#pragma pack(1)
#endif // __MINGW32__
typedef struct _tx_ieee80211_radiotap_header 
{
	u_int8_t it_version;
	u_int8_t it_pad;
	u_int16_t it_len;
	u_int32_t it_present;
	u_int8_t it_rate;
}
#ifdef __MINGW32__
__attribute__((__packed__))
#endif // __MINGW32__
tx_ieee80211_radiotap_header;
#ifndef __MINGW32__
#pragma pack(pop)
#endif // __MINGW32__

/////////////////////////////////////////////////////////////////////
// Table of legal radiotap Tx rates
/////////////////////////////////////////////////////////////////////
UCHAR TxRateInfoTable[] =
{
	2,	
	4,	
	11,
	12,
	18,
	22,
	24,
	36,
	48,
	72,
	96,
	108
};

/////////////////////////////////////////////////////////////////////

void usage()
{
	printf("winpcap_stress: utility that stresses winpcap by opening and capturing from multiple adapters at the same time.\n");
	printf("   Usage: winpcap_stress <nthreads> <adapter_substring_to_match>\n\n"
		"   Examples:\n"
		"      winpcap_stress\n"
		"      winpcap_stress 10\n\n"
		"      winpcap_stress 10 \\Device\\NPF_{ \n");	
}

/////////////////////////////////////////////////////////////////////

void sigh(int val)
{
	EnterCriticalSection(&print_cs);

	printf("\nNumber of iterations:\t\t%u\n", n_iterations);
	printf("Number of packets captured:\t\t%u\n", n_packets);
	printf("Number of read timeouts:\t\t%u\n", n_timeouts);
	printf("Number of open errors:\t\t%u\n", n_open_errors);
	printf("Number of read errors:\t\t%u\n", n_read_errors);
	printf("Number of setfilters:\t\t%u\n", n_setfilters);

	//
	// Note: we don't release the critical section on purpose, so the user doesn't 
	// get crappy input when he presses CTRL+C 
	//
	exit(0);
}



/////////////////////////////////////////////////////////////////////

DWORD WINAPI pcap_thread(LPVOID arg)
{
	pcap_t *fp;
	char* AdName = (char*)arg;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i;
	u_int n_reads, n_writes;
#ifdef INJECT_FILTERS
	struct bpf_program fcode;
	int compile_result;
#endif
#ifdef STRESS_AIRPCAP_TRANSMISSION
	PAirpcapHandle airpcap_handle;
	tx_ieee80211_radiotap_header *radio_header;
#endif
	u_int rate_index;

	srand( (unsigned)time( NULL ) );

	//
	// Open the adapter
	//
	if((fp = pcap_open_live(AdName,
		65535,
		0,								// promiscuous mode
		READ_TIMEOUT,								// read timeout
		errbuf)) == NULL)
	{
		EnterCriticalSection(&print_cs);
		fprintf(stderr,"\nError opening adapter (%s)\n", errbuf);
		LeaveCriticalSection(&print_cs);
		n_open_errors++;
		return -1;
	}

	//
	// Decide if this is going to be a read or write thread
	//

	if((WRITES_FREQUENCY != 0) && ((thread_id++) % WRITES_FREQUENCY == 0))
	{
		//
		// Write thread
		//
		if(MAX_NUM_WRITES)
		{
			n_writes = rand() % MAX_NUM_READS;
		}
		else
		{
			n_writes = 0;
		}
		
		//
		// Get the airpcap handle so we can change wireless-specific settings
		//
#ifdef STRESS_AIRPCAP_TRANSMISSION
		airpcap_handle = pcap_get_airpcap_handle(fp);
		
		if(airpcap_handle != NULL)
		{
			//
			// Configure the AirPcap adapter
			//
			
			// Tell the adapter that the packets we'll send don't include the FCS
			if(!AirpcapSetFcsPresence(airpcap_handle, FALSE))
			{
				printf("Error setting the Fcs presence: %s\n", AirpcapGetLastError(airpcap_handle));
				pcap_close(fp);
				return -1;
			}
			
			//
			// Set the link layer to 802.11 + radiotap
			//
			if(!AirpcapSetLinkType(airpcap_handle, AIRPCAP_LT_802_11_PLUS_RADIO))
			{
				printf("Error setting the link layer: %s\n", AirpcapGetLastError(airpcap_handle));
				pcap_close(fp);
				return -1;
			}
			
			//
			// Create the radiotap header
			//
			radio_header = (tx_ieee80211_radiotap_header*)pkt_to_send;
			radio_header->it_version = 0;
			radio_header->it_pad = 0;
			radio_header->it_len = sizeof(tx_ieee80211_radiotap_header);
			radio_header->it_present = 1 << 2;	// bit 2 is the rate
			rate_index = 18/*rand() % (sizeof(TxRateInfoTable) / sizeof(TxRateInfoTable[0]))*/;
			radio_header->it_rate = 18/*TxRateInfoTable[rate_index]*/;
		}
#endif
		for(i = 0; i < n_writes; i++)
		{
			if(pcap_sendpacket(fp, pkt_to_send, (rand() % MAX_TX_PACKET_SIZE) + 10) != 0)
			{
//				EnterCriticalSection(&print_cs);
//				printf("Write Error: %s\n", pcap_geterr(fp));
//				LeaveCriticalSection(&print_cs);
				n_write_errors++;
			}
		}
	}
	else
	{
		
		//
		// Read Thread
		//
		if(MAX_NUM_READS)
		{
			n_reads = rand() % MAX_NUM_READS;
		}
		else
		{
			n_reads = 0;
		}
		
		for(i = 0; i < n_reads; i++)
		{
			res = pcap_next_ex(fp, &header, &pkt_data);
			
			if(res < 0)
			{
				break;
			}
			
#ifdef INJECT_FILTERS

			EnterCriticalSection(&print_cs);
			compile_result = pcap_compile(fp, &fcode, FILTER, 1, 0xFFFFFFFF);
			LeaveCriticalSection(&print_cs);
			
			
			
			//compile the filter
			if( compile_result < 0)
			{
				fprintf(stderr,"Error compiling filter: wrong syntax.\n");
			}
			else
			{
				//set the filterf
				if(pcap_setfilter(fp, &fcode)<0)
				{
					fprintf(stderr,"Error setting the filter\n");
				}
				else
				{
					InterlockedIncrement(&n_setfilters);
				}
				pcap_freecode(&fcode);
			}
#endif
			
			if(res == 0)
			{
				// Timeout elapsed
				n_timeouts++;
				continue;
			}
			
			
			// print pkt timestamp and pkt len
			n_packets++;
		}
		
		if(res == -1)
		{
			EnterCriticalSection(&print_cs);
			printf("Read error: %s\n", pcap_geterr(fp));
			LeaveCriticalSection(&print_cs);
			n_read_errors++;
		}
	}
	
	pcap_close(fp);
	
	return 1;
}

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

int main(int argc, char **argv)
{	
	pcap_if_t *alldevs, *d;
	u_int i;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int n_threads;
	HANDLE* hThreads;
	char* string_to_match;
	DWORD WaitRes;

	//
	// Parse input
	//
	if(argc == 1)
	{
		n_threads = NUM_THREADS;
		string_to_match = NULL;
	}
	else
	if(argc == 2)
	{
		n_threads = atoi(argv[1]);
		string_to_match = NULL;
	}
	else
	if(argc == 3)
	{
		n_threads = atoi(argv[1]);
		string_to_match = argv[2];
	}
	else
	{
		usage();
		return 1;
	}

	//
	// Init the Tx packet
	//
	for(i = 0; i < MAX_TX_PACKET_SIZE; i++)
	{
		pkt_to_send[i] = i & 0xff; 
	}

	//
	// Allocate storage for the threads list
	//
	hThreads = (HANDLE*)malloc(n_threads * sizeof(HANDLE));
	if(!hThreads)
	{
		printf("Memeory allocation failure\n");
		return -1;
	}
	
	memset(hThreads, 0, n_threads * sizeof(HANDLE));

	signal(SIGINT, sigh);
	InitializeCriticalSection(&print_cs);

	// 
	// Scan the device list
	//
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		EnterCriticalSection(&print_cs);
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		LeaveCriticalSection(&print_cs);
		n_findalldevs_errors++;
//		continue;
		return -1;
	}
	
	//
	// Jump to the selected adapter
	//
	for(i = 0;;)
	{		
		//
		// Go through the list, feeding a thread with each adapter that contains our substring
		//
		for(d = alldevs; d; d = d->next)
		{
			if(string_to_match)
			{
				if(!strstr(d->name, string_to_match))
				{
					continue;
				}
			}

			if(i == n_threads)
			{
				i= 0;
			}
			
			//
			// Check if the thread is done
			//
			WaitRes = WaitForSingleObject(hThreads[i], 1);

			if(WaitRes == WAIT_TIMEOUT)
			{
				//
				// In case of timeout, we switch to the following thread
				//
				i++;
				continue;
			}
			
			//
			// Create the child thread
			//
			printf("Thread %u, %s 0x%x\n", i, d->name, WaitRes);
			
			//
			// Close the thread handle 
			//
			if(hThreads[i])
			{
				CloseHandle(hThreads[i]);
			}

			hThreads[i] = CreateThread(NULL, 0, pcap_thread, d->name, 0, NULL);
			
			if(hThreads[i] == NULL)
			{
				printf("error creating thread. Quitting\n");
				sigh(42);
			}

			n_iterations++;
			i++;
		}
	}
	
	free(hThreads);
	
	return 0;
}
