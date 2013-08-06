/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2010 CACE Technologies, Davis (California)
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


#include "pcap-int.h"
#include <Packet32.h>

#ifdef HAVE_REMOTE
#include <pcap-remote.h>
#endif


HANDLE
pcap_getevent(pcap_t *p)
{
	if (p->TcInstance != NULL)
	{
		return TcGetReceiveWaitHandle(p);
	}
	else
	if (p->adapter==NULL)
	{
		sprintf(p->errbuf, "The read event cannot be retrieved while reading from a file");
		return NULL;
	}	

	return PacketGetReadEvent(p->adapter);
}



/*
This way is definitely safer than passing the pcap_stat * from the userland. In fact, there could
happen than the user allocates a variable which is not big enough for the new structure, and the
library will write in a zone which is not allocated to this variable.
In this way, we're pretty sure we are writing on memory allocated to this variable.
*/
struct pcap_stat *
pcap_stats_ex(pcap_t *p, int *pcap_stat_size)
{
	*pcap_stat_size= sizeof (struct pcap_stat);

#ifdef HAVE_REMOTE
	if (p->rmt_clientside)
	{
		/* We are on an remote capture */
		return pcap_stats_ex_remote(p);
	}
#endif

	if (p->adapter == NULL)
	{
		sprintf(p->errbuf, "Cannot retrieve the extended statistics from a file or a TurboCap port");
		return NULL;
	}

	if(PacketGetStatsEx(p->adapter, (struct bpf_stat*) (&p->md.stat) ) != TRUE){
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "PacketGetStatsEx error: %s", pcap_win32strerror());
		return NULL;
	}
	return (&p->md.stat);
}


pcap_send_queue* 
pcap_sendqueue_alloc(u_int memsize)
{

	pcap_send_queue *tqueue;

	/* Allocate the queue */
	tqueue = (pcap_send_queue*)malloc(sizeof(pcap_send_queue));
	if(tqueue == NULL){
		return NULL;
	}

	/* Allocate the buffer */
	tqueue->buffer = (char*)malloc(memsize);
	if(tqueue->buffer == NULL){
		free(tqueue);
		return NULL;
	}

	tqueue->maxlen = memsize;
	tqueue->len = 0;

	return tqueue;
}

void 
pcap_sendqueue_destroy(pcap_send_queue* queue)
{
	free(queue->buffer);
	free(queue);
}

int 
pcap_sendqueue_queue(pcap_send_queue* queue, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{

	if(queue->len + sizeof(struct pcap_pkthdr) + pkt_header->caplen > queue->maxlen){
		return -1;
	}

	/* Copy the pcap_pkthdr header*/
	memcpy(queue->buffer + queue->len, pkt_header, sizeof(struct pcap_pkthdr));
	queue->len += sizeof(struct pcap_pkthdr);

	/* copy the packet */
	memcpy(queue->buffer + queue->len, pkt_data, pkt_header->caplen);
	queue->len += pkt_header->caplen;

	return 0;
}

u_int 
pcap_sendqueue_transmit(pcap_t *p, pcap_send_queue* queue, int sync){

	u_int res;
	DWORD error;
	int errlen;

	if (p->adapter==NULL)
	{
		sprintf(p->errbuf, "Cannot transmit a queue to an offline capture or to a TurboCap port");
		return 0;
	}	

	res = PacketSendPackets(p->adapter,
		queue->buffer,
		queue->len,
		(BOOLEAN)sync);

	if(res != queue->len){
		error = GetLastError();
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,NULL,error,0,p->errbuf,PCAP_ERRBUF_SIZE,NULL);
		/*
		* "FormatMessage()" "helpfully" sticks CR/LF at the end of
		* the message.  Get rid of it.
		*/
		errlen = strlen(p->errbuf);
		if (errlen >= 2) {
			p->errbuf[errlen - 1] = '\0';
			p->errbuf[errlen - 2] = '\0';
		}
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "Error opening adapter: %s", p->errbuf);
	}

	return res;
}


#ifdef WE_HAVE_TO_DELETE_IT_ASAP
int 
pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, u_char **pkt_data)
{
	/* Check the capture type */

#ifdef HAVE_REMOTE
	if (p->rmt_clientside)
	{
		/* We are on an remote capture */
		if (!p->rmt_capstarted)
		{
			// if the capture has not started yet, please start it
			if (pcap_startcapture_remote(p) )
				return -1;
			p->rmt_capstarted= 1;
		}
		return pcap_next_ex_remote(p, pkt_header, pkt_data);
	}
#endif

	if (p->adapter!=NULL)
	{
		/* We are on a live capture */
		int cc;
		int n = 0;
		register u_char *bp, *ep;
		
		cc = p->cc;
		if (p->cc == 0) 
		{
			/* capture the packets */
			if(PacketReceivePacket(p->adapter, p->Packet, TRUE) == FALSE)
			{
				sprintf(p->errbuf, "read error: PacketReceivePacket failed");
				return (-1);
			}
			
			cc = p->Packet->ulBytesReceived;
			
			bp = p->Packet->Buffer;
		} 
		else
			bp = p->bp;
		
		/*
		 * Loop through each packet.
		 */
		ep = bp + cc;
		if (bp < ep) 
		{
			register int caplen, hdrlen;
			caplen = ((struct bpf_hdr *)bp)->bh_caplen;
			hdrlen = ((struct bpf_hdr *)bp)->bh_hdrlen;
			
			/*
			 * XXX A bpf_hdr matches a pcap_pkthdr.
			 */
			*pkt_header = (struct pcap_pkthdr*)bp;
			*pkt_data = bp + hdrlen;
			bp += BPF_WORDALIGN(caplen + hdrlen);
			
			p->bp = bp;
			p->cc = ep - bp;
			return (1);
		}
		else{
			p->cc = 0;
			return (0);
		}
	}	
	else
	{
		/* We are on an offline capture */
		struct bpf_insn *fcode = p->fcode.bf_insns;
		int status;
		int n = 0;
		
		struct pcap_pkthdr *h=(struct pcap_pkthdr*)(p->buffer+p->bufsize-sizeof(struct pcap_pkthdr));
		
		while (1)
		{
			status = sf_next_packet(p, h, p->buffer, p->bufsize);
			if (status==1)
				/* EOF */
				return (-2);
			if (status==-1)
				/* Error */
				return (-1);
			
			if (fcode == NULL ||
				bpf_filter(fcode, p->buffer, h->len, h->caplen)) 
			{
				*pkt_header = h;
				*pkt_data = p->buffer;
				return (1);
			}			
			
		}
	}
}
#endif


int
pcap_setuserbuffer(pcap_t *p, int size)

{
	unsigned char *new_buff;

	if (!p->adapter) {
		sprintf(p->errbuf,"Impossible to set user buffer while reading from a file or on a TurboCap port");
		return -1;
	}

	if (size<=0) {
		/* Bogus parameter */
		sprintf(p->errbuf,"Error: invalid size %d",size);
		return -1;
	}

	/* Allocate the buffer */
	new_buff=(unsigned char*)malloc(sizeof(char)*size);

	if (!new_buff) {
		sprintf(p->errbuf,"Error: not enough memory");
		return -1;
	}

	free(p->buffer);
	
	p->buffer=new_buff;
	p->bufsize=size;

	/* Associate the buffer with the capture packet */
	PacketInitPacket(p->Packet,(BYTE*)p->buffer,p->bufsize);

	return 0;

}

int
pcap_live_dump(pcap_t *p, char *filename, int maxsize, int maxpacks){

	BOOLEAN res;

	if (p->adapter==NULL)
	{
		sprintf(p->errbuf, "live dump needs a physical interface supported by the NPF driver");
		return -1;
	}	

	/* Set the packet driver in dump mode */
	res = PacketSetMode(p->adapter, PACKET_MODE_DUMP);
	if(res == FALSE){
		sprintf(p->errbuf, "Error setting dump mode");
		return -1;
	}

	/* Set the name of the dump file */
	res = PacketSetDumpName(p->adapter, filename, strlen(filename));
	if(res == FALSE){
		sprintf(p->errbuf, "Error setting kernel dump file name");
		return -1;
	}

	/* Set the limits of the dump file */
	res = PacketSetDumpLimits(p->adapter, maxsize, maxpacks);

	return 0;
}

int 
pcap_live_dump_ended(pcap_t *p, int sync){

	if (p->adapter == NULL)
	{
		sprintf(p->errbuf, "wrong interface type. A physical interface supported by the NPF driver is needed");
		return -1;
	}	

	return PacketIsDumpEnded(p->adapter, (BOOLEAN)sync);

}

PAirpcapHandle pcap_get_airpcap_handle(pcap_t *p)
{
#ifdef HAVE_AIRPCAP_API
	if (p->adapter == NULL)
	{
		sprintf(p->errbuf, "wrong interface type. A physical interface is needed");
		return NULL;
	}

	return PacketGetAirPcapHandle(p->adapter);
#else
	return NULL;
#endif /* HAVE_AIRPCAP_API */
}