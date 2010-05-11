#define SESSION_FILE_DEBUG	"/tmp/datadump/session.log"
#define PACKET_FILE_DEBUG	"/tmp/datadump/packet.log"
#define TTL_FILE_DEBUG		"/tmp/datadump/ttl.log"

class DataDebug 
{
	private:
		FILE *Session_f, *Packet_f, *TTL_f;
	public:
		DataDebug();
		~DataDebug();
		int session_tracked, packet_queue, tracked_ttl;

		struct sniffjoke_track *Session;
		void Dump_Session( int );

		struct packetblock *Packet;
		void Dump_Packet( int );

		struct ttlfocus *TTL;
		void Dump_TTL( int );

		/* "Session", "Packet", "TTL" */
		void InfoMsg( const char *, const char *, ... );
};
