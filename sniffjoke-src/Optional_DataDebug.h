class DataDebug 
{
	private:
		FILE *Session_f, *Packet_f, *TTL_f;
	public:
		int session_tracked, packet_queue, tracked_ttl;
		DataDebug( );
		~DataDebug();

		struct sniffjoke_track *Session;
		Dump_Session( int );

		struct packetblock *Packet;
		Dump_Packet( int );

		struct ttlfocus *TTL;
		Dump_TTL( int );

		/* "Session", "Packet", "TTL" */
		InfoMsg( const char *, const char * );
};
