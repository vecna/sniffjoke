#ifndef SJ_TCPTRACK_H
#define SJ_TCPTRACK_H

#include <netinet/tcp.h>

#include "SjConf.h"
#include "Packet.h"
#include "PacketQueue.h"
#include "SessionTrack.h"
#include "SessionTrackList.h"
#include "TTLFocus.h"
#include "TTLFocusList.h"


class TCPTrack {
private:
    int maxttlprobe;    /* max probe for discern ttl */

    SessionTrackList *sex_list;
    TTLFocusList *ttlfocus_list;

    /* as usually in those classes */
    struct sj_config *runcopy;

    /* main function of packet analysis, called by analyze_packets_queue */
    Packet* analyze_incoming_icmp( Packet * );
    Packet* analyze_incoming_synack( Packet * );
    Packet* analyze_incoming_rstfin( Packet * );
    void manage_outgoing_packets( Packet * );

    /* functions forging/mangling packets que, ttl analysis */
    bool check_evil_packet( const unsigned char * buff, int nbyte );
    void inject_hack_in_queue( const Packet *, SessionTrack * );
    void enque_ttl_probe( Packet *, SessionTrack * );
    bool analyze_ttl_stats( SessionTrack * );
    void mark_real_syn_packets_SEND( unsigned int );

    /* functions for decrete which, and if, inject hacks */
    bool check_uncommon_tcpopt( const struct tcphdr * );
    Packet *packet_orphanotrophy( const Packet *, int );
    bool percentage( float, int );
    float logarithm( int );

    /* the sniffjoke hack apply on the packets */
    void SjH__fake_data( Packet * );
    void SjH__fake_seq( Packet * );
    void SjH__fake_syn( Packet * );
    void SjH__fake_close( Packet * );
    void SjH__zero_window( Packet * );

    /* sadly, those hacks require some analysis */
    void SjH__shift_ack( Packet * );
    void SjH__valid_rst_fake_seq( Packet * );

    /* void SjH__half_fake_syn( Packet * ); NOT IMPLEMENTED */
    /* void SjH__half_fake_ack( Packet * ); NOT IMPLEMENTED */

    /* size of header to fill with wild IP/TCP options */
    void SjH__inject_ipopt( Packet * );
    void SjH__inject_tcpopt( Packet * );

    /* functions for working on queues and lists */
    struct SessionTrack* init_session( const Packet * );

public:
    PacketQueue *p_queue;
    TCPTrack( SjConf* );
    ~TCPTrack();

    bool add_packet_queue( const source_t, const unsigned char *, int );
    void analyze_packets_queue();
    void last_pkt_fix( Packet * );

    /* force all packets sendable, used from NetIO for avoid Sn mangling */
    void force_send( void );
};

#endif /* SJ_TCPTRACK_H */
