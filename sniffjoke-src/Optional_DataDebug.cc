#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include <sys/signal.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include <arpa/inet.h>

#include "Optional_DataDebug.h"
#include "sniffjoke.h"

DataDebug::DataDebug()
{
	Session_f = fopen(SESSION_FILE_DEBUG, "a+");
	Packet_f = fopen(PACKET_FILE_DEBUG, "a+");
	TTL_f = fopen(TTL_FILE_DEBUG, "a+");

	if(Session_f == NULL || Packet_f == NULL || TTL_f == NULL) {
		fprintf(stderr, "unable to open file(s) %s %s %s - check your system or remove #define DATADEBUG\n",
			SESSION_FILE_DEBUG, PACKET_FILE_DEBUG, TTL_FILE_DEBUG
		);
		raise(SIGTERM);
	}

	Session = NULL;
	Packet = NULL;
	TTL = NULL;

	return;
}

void DataDebug::Dump_Session( int session_elements )
{
	if(Session == NULL) {
		fprintf(Session_f, "wrong !?");
		return;
	}

	int i, accumulo_start = 0, accumulo_end = 0;
	for(i = 0; i < session_elements; i++) 
	{
		if(accumulo_start && Session[i].daddr) {
			accumulo_end = (i - 1);
			fprintf(Session_f, "[%d - %d]/%d empty\n", accumulo_start, accumulo_end, session_elements);
			accumulo_start = accumulo_end = 0;
		}

		if(!Session[i].daddr && !Session[i].sport && !accumulo_start) {
			accumulo_start = i;
		}

		if(Session[i].daddr && Session[i].sport) 
		{
			fprintf( Session_f,
				"[%d]/%d %s %d:%d isn %8x packet number %d shutdown %d\n", 
				i, session_elements,
				inet_ntoa( *((struct in_addr *)&(Session[i].daddr)) ),
                                ntohs(Session[i].sport),
                                ntohs(Session[i].dport),
				Session[i].isn,
				Session[i].packet_number,
				Session[i].shutdown
			);
		}
	}

	if(accumulo_start) 
		fprintf(Session_f, "[%d - %d]/%d empty\n", accumulo_start, session_elements, session_elements);
}

void DataDebug::Dump_Packet( int pblock_elements)
{
	if(Packet == NULL) {
		fprintf(Packet_f, "wrong !?");
		return;
	}

	int accumulo_start = 0, accumulo_end = 0;
	for(int i = 0; i < pblock_elements; i++) 
	{
		if(accumulo_start && Packet[i].pbuf_size) {
			accumulo_end = (i - 1);
			fprintf(Packet_f, "[%d - %d]/%d empty\n", accumulo_start, accumulo_end, pblock_elements);
			accumulo_start = accumulo_end = 0;
		}

		if(!accumulo_start && !Packet[i].pbuf_size) {
			accumulo_start = i;
		}

		if(Packet[i].pbuf_size) 
		{
			const char *source;

			if(Packet[i].source == ANY_SOURCE)
				source = "ANY SOURCE";
			else if(Packet[i].source == TUNNEL)
				source = "TUNNEL";
			else if(Packet[i].source == LOCAL)
				source = "LOCAL";
			else if(Packet[i].source == TTLBFORCE)
				source = "TTL BRUTAL FORCE";
			else
				source = "WRONG SOURCE CODE";

			if(Packet[i].proto == TCP) 
			{
				fprintf( Packet_f, "[%d]/%d %s:%d-", i, pblock_elements,
					inet_ntoa( *((struct in_addr *)&(Packet[i].ip->saddr)) ),
					ntohs(Packet[i].tcp->source)
				);
				fprintf( Packet_f, "%s:%d id %8x orig_pktlen %d bufsize %d\n",
					inet_ntoa( *((struct in_addr *)&(Packet[i].ip->daddr)) ),
					ntohs(Packet[i].tcp->dest),
					Packet[i].packet_id,
					Packet[i].orig_pktlen,
					Packet[i].pbuf_size
				);
			} 
			else if (Packet[i].proto == ICMP) 
			{
				fprintf( Packet_f, "[%d]/%d %s ICMP origlen %d bufsize %d packet_id %8x\n", 
					i, pblock_elements,
					inet_ntoa( *((struct in_addr *)&(Packet[i].ip->saddr)) ),
					Packet[i].orig_pktlen,
					Packet[i].pbuf_size,
					Packet[i].packet_id
				);
			} 
			else if ( Packet[i].proto == OTHER_IP)
			{
				fprintf( Packet_f, "[%d]/%d %s OTHER PROTOCOL (%d) origlen %d bufsize %d packet_id %8x\n", 
					i, pblock_elements,
					inet_ntoa( *((struct in_addr *)&(Packet[i].ip->saddr)) ),
					Packet[i].ip->protocol,
					Packet[i].orig_pktlen,
					Packet[i].pbuf_size,
					Packet[i].packet_id
				);
			}
		}
	}

	if(accumulo_start) 
		fprintf(Packet_f, "[%d - %d]/%d empty\n", accumulo_start, pblock_elements, pblock_elements);
}

void DataDebug::Dump_TTL ( int ttl_elements )
{
	if(TTL== NULL) {
		fprintf(TTL_f, "wrong !?");
		return;
	}

	int i, accumulo_start = 0, accumulo_end = 0;
	for(i = 0; i < ttl_elements; i++) 
	{
		if(accumulo_start && TTL[i].daddr) {
			accumulo_end = (i - 1);
			fprintf(Session_f, "[%d - %d]/%d empty\n", accumulo_start, accumulo_end, ttl_elements);
			accumulo_start = accumulo_end = 0;
		}

		if(!TTL[i].daddr && !accumulo_start) {
			accumulo_start = i;
		}

		if(TTL[i].daddr) 
		{
			const char *ttl_status;

			if(TTL[i].status == TTL_KNOW ) { 
				ttl_status = "KNOW/DETECTED";
			} else if(TTL[i].status == TTL_BRUTALFORCE ) { 
				ttl_status = "BRUTEFORCE RUNNING";
			} else if(TTL[i].status == TTL_UNKNOW ) {
				ttl_status = "UNKNOW/UNABLE TO DETECT";
			} else { 
				ttl_status = "TTL-ERROR-STATUS";
			}

			fprintf( TTL_f,
				"[%d]/%d %s expiring %d min working %d sent probe %d received %d status %s\n",
					i, ttl_elements,
					inet_ntoa( *((struct in_addr *)&(TTL[i].daddr)) ),
					TTL[i].expiring_ttl,
					TTL[i].min_working_ttl,
					TTL[i].sent_probe,
					TTL[i].received_probe,
					ttl_status
			);
		}
	}

	if(accumulo_start) 
		fprintf(TTL_f, "[%d - %d]/%d empty\n", accumulo_start, ttl_elements, ttl_elements);
}

void DataDebug::InfoMsg( const char *where, const char *msg, ...)
{
	time_t now = time(NULL);
	va_list arguments;
	FILE *dest = NULL;
	char *time = strdup(asctime(localtime(&now)));

	if(!strcmp(where, "Session"))
		dest = Session_f;
	else if(!strcmp(where, "Packet"))
		dest = Packet_f;
	else
		dest = TTL_f;

	time[strlen(time) -1] = ' ';
	va_start(arguments, msg);
	fprintf(dest, "%s ", time);
	vfprintf(dest, msg, arguments);
	fprintf(dest, "\n");
	fflush(dest);
	free(time);
	va_end(arguments);
}

DataDebug::~DataDebug()
{
	fclose(Session_f);
	fclose(Packet_f);
	fclose(TTL_f);
}
