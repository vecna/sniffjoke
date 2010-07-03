#ifndef SJ_TCPTRACK_H
#define SJ_TCPTRACK_H

#include <netinet/tcp.h>

#include "SjConf.h"

/* Maximum Transfert Unit */
#define MTU		1500

/* Max Number of options injectable */
#define MAXOPTINJ       12
#define MAXHACKS	7

enum status_t { ANY_STATUS = 16, SEND = 5, KEEP = 10, YOUNG = 82, DROP = 83 };
enum source_t { ANY_SOURCE = 3, TUNNEL = 80, LOCAL = 5, NETWORK = 13, TTLBFORCE = 28 };
enum proto_t { ANY_PROTO = 11, TCP = 6, ICMP = 9, OTHER_IP = 7 };
enum judge_t { PRESCRIPTION = 10, GUILTY = 315, INNOCENT = 1 };

struct packetblock {
        int orig_pktlen;
        int pbuf_size;
        /* 
         * this packet_id are useful for avoid packet duplication
         * due to sniffjoke queue, I don't want avoid packet 
         * retrasmission (one of TCP best feature :) 
         */
        unsigned int packet_id;

        proto_t proto;
        source_t source;
        status_t status;
        judge_t wtf;

        unsigned char pbuf[MTU];
        struct iphdr *ip;
        struct tcphdr *tcp;
        struct icmphdr *icmp;
        unsigned char *payload;

        struct ttlfocus *tf;
};

struct sniffjoke_track {
        unsigned int daddr;
        unsigned short sport;
        unsigned short dport;
        unsigned int isn;
        unsigned int packet_number;
        bool shutdown;

        struct ttlfocus *tf;
};

enum ttlsearch_t { TTL_KNOW = 1, TTL_BRUTALFORCE = 3, TTL_UNKNOW = 9 };
struct ttlfocus {
        unsigned int daddr;
        unsigned char expiring_ttl;
        unsigned char min_working_ttl;
        unsigned char sent_probe;
        unsigned char received_probe;
        unsigned short puppet_port;
        unsigned int rand_key;

        ttlsearch_t status;
};

enum priority_t { HIGH = 188, LOW = 169 };

class TCPTrack {
private:
        int paxmax;             /* max packet tracked */
        int sextraxmax;         /* max tcp session tracked */
        int maxttlfocus;        /* max destination ip tracked */
        int maxttlprobe;        /* max probe for discern ttl */

        struct sniffjoke_track *sex_list;
        struct packetblock *pblock_list;
        struct ttlfocus *ttlfocus_list;
        int sex_list_count[2];
        int pblock_list_count[2];

        /* as usually in those classess */
        struct sj_config *runcopy;

        /* main function of packet analysis, called by analyze_packets_queue */
        void update_pblock_pointers( struct packetblock * );
        void analyze_incoming_icmp( struct packetblock * );
        void analyze_incoming_synack( struct packetblock * );
        void analyze_incoming_rstfin( struct packetblock * );
        void manage_outgoing_packets( struct packetblock * );

        /* functions forging/mangling packets que, ttl analysis */
        void inject_hack_in_queue( struct packetblock *, struct sniffjoke_track * );
        void enque_ttl_probe( struct packetblock *, struct sniffjoke_track * );
        unsigned int make_pkt_id( const unsigned char* );
        bool analyze_ttl_stats( struct sniffjoke_track * );
        void mark_real_syn_packets_SEND( unsigned int );

        /* functions for decrete which, and if, inject hacks */
        bool check_uncommon_tcpopt( const struct tcphdr * );
        struct packetblock *packet_orphanotrophy( const struct packetblock *, int );
        bool percentage( float, int );
        float logarithm( int );

        /* the sniffjoke hack apply on the packets */
        void SjH__fake_data( struct packetblock * );
        void SjH__fake_seq( struct packetblock * );
        void SjH__fake_syn( struct packetblock * );
        void SjH__fake_close( struct packetblock * );
        void SjH__zero_window( struct packetblock * );

        /* sadly, those hacks require some analysis */
	void SjH__shift_ack( struct packetblock * );
        void SjH__valid_rst_fake_seq( struct packetblock * );
        
        /* void SjH__half_fake_syn( struct packetblock * ); NOT IMPLEMENTED */
        /* void SjH__half_fake_ack( struct packetblock * ); NOT IMPLEMENTED */

        /* size of header to fill with wild IP/TCP options */
        void SjH__inject_ipopt( struct packetblock * );
        void SjH__inject_tcpopt( struct packetblock * );

        /* functions required in TCP/IP packets forging */
        unsigned int half_cksum( const void *, int );
        unsigned short compute_sum( unsigned int );
        void fix_iptcp_sum( struct iphdr *, struct tcphdr * );

        /* functions for working on queues and lists */
        struct packetblock *get_free_pblock( int, priority_t, unsigned int );
        void recompact_pblock_list( int );
        struct sniffjoke_track *init_sexion( const struct packetblock * );
        struct sniffjoke_track *get_sexion( unsigned int, unsigned short, unsigned short );
        struct sniffjoke_track *find_sexion( const struct packetblock * );
        void clear_sexion( struct sniffjoke_track * );
        void recompact_sex_list( int );
        struct ttlfocus *init_ttl_focus( int, unsigned int );
        struct ttlfocus *find_ttl_focus( unsigned int, int );

public:
        TCPTrack( SjConf* );
        ~TCPTrack();
        
        bool check_evil_packet( const unsigned char * buff, int nbyte);
        void add_packet_queue( const source_t, const unsigned char *, int );
        void analyze_packets_queue();
        struct packetblock *get_pblock( status_t, source_t, proto_t, bool);
        void clear_dropped_pblocks();
        void last_pkt_fix( struct packetblock * );

        /* force all packets sendable, used from NetIO for avoid Sn mangling */
        void force_send(void);
};

#endif /* SJ_TCPTRACK_H */
