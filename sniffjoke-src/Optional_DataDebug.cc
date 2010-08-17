#include "Optional_DataDebug.h"
#include <cstdarg>
#include <ctime>
#include <cstring>
#include <cstdlib>

#include <csignal>
#include <sys/stat.h>

#include <arpa/inet.h>

DataDebug::DataDebug()
{
	mkdir("/tmp/datadump", 777);
	Session_f = fopen(SESSION_FILE_DEBUG, "a+");
	Packet_f = fopen(PACKET_FILE_DEBUG, "a+");
	TTL_f = fopen(TTL_FILE_DEBUG, "a+");

	if (Session_f == NULL || Packet_f == NULL || TTL_f == NULL) {
		fprintf(stderr, "unable to open file(s) %s %s %s - check your system or remove #define DATADEBUG\n",
			SESSION_FILE_DEBUG, PACKET_FILE_DEBUG, TTL_FILE_DEBUG
		);
		raise(SIGTERM);
	}

	return;
}

void DataDebug::Dump_Packet(PacketQueue& list)
{
	int i = 0;
	const char *source;
	Packet *tmp = list.get(false);
	while (tmp != NULL) {
		i++;

		switch(tmp->source) {
			case ANY_SOURCE:
				source = "ANY SOURCE";
				break;
			case TUNNEL:
				source = "TUNNEL";
				break;
			case LOCAL:
				source = "LOCAL";
				break;
			case TTLBFORCE:
				source = "TTL BRUTAL FORCE";
				break;
			case SOURCEUNASSIGNED:
				source = "SOURCE UNASSIGNED (this wouldn't be happen)";
				break;
			default:
				source = "WRONG SOURCE CODE";
		}

		switch(tmp->proto) {
			case TCP:
				fprintf(Packet_f, "Packet [%d] %s:%d",
						i,
						inet_ntoa(*((struct in_addr *)&(tmp->ip->saddr))),
						ntohs(tmp->tcp->source)
				);
				fprintf(Packet_f, "Packet [%d] %s:%d id %8x orig_pktlen %d bufsize %d\n",
						i,
						inet_ntoa(*((struct in_addr *)&(tmp->ip->daddr))),
						ntohs(tmp->tcp->dest),
						tmp->packet_id,
						tmp->orig_pktlen,
						tmp->pbuf_size
				);
				break;
			case ICMP:
				fprintf(Packet_f, "Packet [%d] %s ICMP origlen %d bufsize %d packet_id %8x\n",
						i,
						inet_ntoa(*((struct in_addr *)&(tmp->ip->saddr))),
						tmp->orig_pktlen,
						tmp->pbuf_size,
						tmp->packet_id
				);
				break;
			case OTHER_IP:
				fprintf(Packet_f, "Packet [%d] %s OTHER PROTOCOL (%d) origlen %d bufsize %d packet_id %8x\n",
						i,
						inet_ntoa(*((struct in_addr *)&(tmp->ip->saddr))),
						tmp->ip->protocol,
						tmp->orig_pktlen,
						tmp->pbuf_size,
						tmp->packet_id
				);
				break;
		}

		tmp = list.get(true);
	}
}


void DataDebug::Dump_Session(SessionTrackMap &sex_map)
{
	int i = 0;
	SessionTrack *tmp;
	for ( SessionTrackMap::iterator it = sex_map.begin() ; it != sex_map.end(); it++ ) {
		i++;

		tmp = &(it->second);
		fprintf(Session_f,
				"SessionTrack [%d] %s %d:%d isn %8x packet number %d shutdown %d\n",
				i,
				inet_ntoa(*((struct in_addr *)&(tmp->daddr))),
				ntohs(tmp->sport),
				ntohs(tmp->dport),
				tmp->isn,
				tmp->packet_number,
				tmp->shutdown
		);
	}
}

void DataDebug::Dump_TTL (TTLFocusMap &ttlfocus_map)
{
	int i = 0;
	TTLFocus *tmp;
	const char *ttl_status;
	for ( TTLFocusMap::iterator it = ttlfocus_map.begin() ; it != ttlfocus_map.end(); it++ ) {
		i++;

		tmp = &(it->second);
		switch(tmp->status) {
			case TTL_KNOW:
				ttl_status = "KNOW/DETECTED";
				break;
			case TTL_BRUTALFORCE:
				ttl_status = "BRUTEFORCE RUNNING";
				break;
			case TTL_UNKNOW:
				ttl_status = "UNKNOW/UNABLE TO DETECT";
				break;
			default:
				ttl_status = "TTL-ERROR-STATUS";
		}

		fprintf(TTL_f,
				"TTLFocus [%d] %s expiring %d min working %d sent probe %d received %d status %s\n",
				i,
				inet_ntoa(*((struct in_addr *)&(tmp->daddr))),
				tmp->expiring_ttl,
				tmp->min_working_ttl,
				tmp->sent_probe,
				tmp->received_probe,
				ttl_status
		);

	}
}

void DataDebug::InfoMsg(const char *where, const char *msg, ...)
{
	time_t now = time(NULL);
	va_list arguments;
	FILE *dest = NULL;
	char *time = strdup(asctime(localtime(&now)));

	if (!strcmp(where, "Session"))
		dest = Session_f;
	else if (!strcmp(where, "Packet"))
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
