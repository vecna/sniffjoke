/*
 * sniffjoke.hh, October 2008: 
 * 
 * "does public key and web of trust could create a trustable peer to peer network ?"
 * "yes."
 *
 * how much sniffjoke had to do with p2p/wot ? nothing, but until this kind of 
 * network don't exist, confuse sniffer should be helpfullest!
 */

#ifndef SNIFFJOKE_H
#define SNIFFJOKE_H

#include <net/ethernet.h>

#define STRERRLEN	1024
int check_call_ret(const char *, int, int, char **em =NULL, int *el =NULL);

struct port_range {
	unsigned short start;
	unsigned short end;
};

enum size_buf_t { 
	SMALLBUF = 64, 
	MEDIUMBUF = 256, 
	LARGEBUF = 1024, 
	HUGEBUF = 4096, 
	GARGANTUABUF = 4096 * 4 
};

#define MAGICVAL	0xADECADDE
struct sj_config {
	char gw_ip_addr[SMALLBUF]; 	/* default: autodetect */
	char local_ip_addr[SMALLBUF];	/* default: autodetect */
	char gw_mac_str[SMALLBUF]; 	/* default: autodetect */
	unsigned char gw_mac_addr[ETH_ALEN];	/* the conversion of _str */
	float MAGIC; /* integrity check for saved binary configuration */
	unsigned char sj_run; 		/* default: 0 = NO RUNNING */
	unsigned short web_bind_port; 	/* default: 8844 */
	unsigned short max_ttl_probe;	/* default: 26 */
	unsigned short max_session_tracked; /* default: 20 */
	unsigned short max_packet_que; 	/* default: 60 */
	unsigned short max_tracked_ttl; /* default: 1024 */
	unsigned char interface[SMALLBUF]; /* default: autodetect */
	int tun_number;			/* tunnel interface number */
	int port_range_n; 		/* default: 0 */

	bool reload_conf;
	char *error;
};


class SjConf {
private:
public:
	struct sj_config *running;
	struct port_range *pr;

	void dump_config(const char *);
	void dump_error(char *, int);
	SjConf(const char *);
	~SjConf();
};

#include <swill/swill.h>
class WebIO {
private:
	/* static struct sj_config *runcopy, and the other member, due to
 	 * swill integration */
public:
	WebIO( SjConf * );
	~WebIO();
	int web_poll();
};

/* 
 * the class before had err value, below this isn't 
 * present because thats objects had not an "initialization"
 * and are not called on init section.
 */

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netpacket/packet.h>

/* Maximum Transfert Unit */
#define MTU	1500
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
	struct packetblock *refsyn;

	ttlsearch_t status;
};

enum priority_t { HIGH = 188, LOW = 169 };
class TCPTrack {
private:
	/* main function of packet analysis, called by analyze_packets_queue */
	void update_pblock_pointers( struct packetblock *); 
	void analyze_incoming_icmp(struct packetblock *);
	void analyze_incoming_synack(struct packetblock *);
	void analyze_incoming_rstfin(struct packetblock *);
	void manage_outgoing_packets(struct packetblock *);

	/* functions forging/mangling packets que, ttl analysis */
	void inject_hack_in_queue(struct packetblock *, struct sniffjoke_track *);
	void enque_ttl_probe( struct packetblock *, struct sniffjoke_track *);
	void discern_working_ttl( struct packetblock *, struct sniffjoke_track *);
	unsigned int make_pkt_id( struct iphdr *);
	bool analyze_ttl_stats(struct sniffjoke_track *);

	/* functions for decrete which, and if, inject hacks */
	bool check_uncommon_tcpopt(struct tcphdr *);
	struct packetblock *packet_orphanotrophy( struct iphdr *, struct tcphdr *, int);
	void packets_court( struct iphdr *, struct tcphdr *, struct ttlfocus *, judge_t);
	bool percentage(float, int);
	float logarithm(int);

	/* the sniffjoke hack apply on the packets */
	void SjH__fake_data( struct packetblock *);
	void SjH__fake_seq( struct packetblock *);
	void SjH__fake_syn( struct packetblock *);
	void SjH__fake_close( struct packetblock *);
	void SjH__zero_window( struct packetblock *);

#if 1	/* sadly, those hacks require some analysis */
	void SjH__valid_rst_fake_seq( struct packetblock *);
	void SjH__half_fake_syn( struct packetblock *);
	void SjH__half_fake_ack( struct packetblock *);
	void SjH__shift_ack( struct packetblock *);
#endif

	/* size of header to fill with wild IP/TCP options */
#define MAXOPTINJ	12
	void SjH__inject_ipopt( struct packetblock *);
	void SjH__inject_tcpopt( struct packetblock *);

	/* functions required in TCP/IP packets forging */
	unsigned int half_cksum(void *, int);
	unsigned short compute_sum(unsigned int);
	void fix_iptcp_sum(struct iphdr *, struct tcphdr *);

	/* functions for work in queue and lists */
	struct packetblock *get_free_pblock(int, priority_t, unsigned int);
    struct sniffjoke_track *init_sexion(int, struct packetblock *);    
	struct sniffjoke_track *find_sexion(struct packetblock *);
	struct sniffjoke_track *get_sexion(unsigned int, unsigned short, unsigned short);
	void clear_sexion(struct sniffjoke_track *);
    struct ttlfocus *init_ttl_focus(int, unsigned int, struct packetblock *);
	struct ttlfocus *find_ttl_focus(unsigned int, struct packetblock *);

	int paxmax; 		/* max packet tracked */
	int sextraxmax; 	/* max tcp session tracked */
	int maxttlfocus;	/* max destination ip tracked */
	int maxttlprobe;	/* max probe for discern ttl */

	struct sniffjoke_track *sex_list;
	struct packetblock *pblock_list;
	struct ttlfocus *ttlfocus_list;

	/* as usually in those classess */
	struct sj_config *runcopy;
public:
	TCPTrack(SjConf *);
	~TCPTrack();
	void add_packet_queue(source_t, unsigned char *, int);
	void analyze_packets_queue();
	struct packetblock *get_pblock(status_t, source_t, proto_t, unsigned int);
	void clear_pblock(struct packetblock *);
	void last_pkt_fix(struct packetblock *);
};

class NetIO {
private:
	/* 
 	 * these data are required for handle 
 	 * tunnel/ethernet man in the middle
	 */
	struct sockaddr_ll send_ll;
	struct sj_config *runcopy;
public:
	/* tunfd/netfd: file descriptor for I/O purpose */
	int tunfd;
	int netfd;

	/* error msg */
	int error_len;
	char *error_msg;

	NetIO(SjConf *);
	~NetIO();
	void network_io(source_t, TCPTrack *);
	void queue_flush( TCPTrack *);
};

#endif /* SNIFFJOKE_H */
