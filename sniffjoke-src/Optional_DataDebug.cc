#include <stdio.h>
#include <stdarg.h>
#include <netinet/ip.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "Optional_DataDebug.h"
#include "sniffjoke.h"

DataDebug::DataDebug()
{
	Session_f = fopen(SESSION_FILE_DEBUG, "a+");
	Packet_f = fopen(PACKET_FILE_DEBUG, "a+");
	TTL_f = fopen(TTL_FILE_DEBUG, "a+");

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
	for(i =0; i < session_elements; i++) 
	{
		if(accumulo_start && Session[i].daddr) {
			accumulo_end = (i - 1);
			fprintf(Session_f, "[%d - %d]/%d empty\n", accumulo_start, accumulo_end, session_elements);
			accumulo_start = accumulo_end = 0;
		}

		if(!Session[i].daddr && !Session[i].sport) {
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
	fprintf(Packet_f, "to be implemented\n");
}

void DataDebug::Dump_TTL ( int ttl_elements )
{
	fprintf(TTL_f, "to be implemented\n");
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

