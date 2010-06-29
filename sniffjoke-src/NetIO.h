#ifndef SJ_NETIO_H
#define SJ_NETIO_H

#include <poll.h>
#include <netpacket/packet.h>

#include "TCPTrack.h"
#include "SjConf.h"

class NetIO {
private:
        /* 
         * these data are required for handle 
         * tunnel/ethernet man in the middle
         */
        struct sockaddr_ll send_ll;
        struct sj_config *runcopy;
        TCPTrack *conntrack;
public:

        /* tunfd/netfd: file descriptor for I/O purpose */
        int tunfd;
        int netfd;

        /* poll variables, two file descriptors */
        struct pollfd fds[2];

	/* networkdown_condition express if the network is down and sniffjoke must be interrupted 
	 *       --- but not killed!
	*/

        bool networkdown_condition;

        NetIO( SjConf * );
        ~NetIO();
        void network_io();
        void queue_flush();
};

#endif /* SJ_NETIO_H */
