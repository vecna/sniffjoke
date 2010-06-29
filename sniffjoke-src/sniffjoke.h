/*
 * sniffjoke.h, October 2008: 
 * 
 * "does public key and web of trust could create a trustable peer to peer network ?"
 * "yes."
 *
 * how much sniffjoke had to do with p2p/wot ? nothing, but until this kind of 
 * network don't exist, confuse sniffer should be helpfullest!
 */

#ifndef SNIFFJOKE_H
#define SNIFFJOKE_H

#define SJ_PROCESS_TYPE_UNASSIGNED (-1)
#define SJ_PROCESS_TYPE_SRV_FATHER (0)
#define SJ_PROCESS_TYPE_SRV_CHILD (1)
#define SJ_PROCESS_TYPE_CLI (2)
#define SJ_SRV_LOCK "/var/run/sniffjoke/srv.lock"
#define SJ_CLI_LOCK "/var/run/sniffjoke/cli.lock"
#define SJ_SRV_TMPDIR "/var/run/sniffjoke/srv"
#define SJ_SRV_FATHER_PID_FILE SJ_SRV_TMPDIR"/father.pid"
#define SJ_SRV_CHILD_PID_FILE SJ_SRV_TMPDIR"/child.pid"
#define SJ_SRV_US "sniffjoke_srv" // relative to the jail
#define SJ_CLI_US "sniffjoke_cli" // relative to the jail

#define STRERRLEN       1024

#include "SjUtils.h"
#include "SjConf.h"
#include "NetIO.h"
#include "TCPTrack.h"

#endif /* SNIFFJOKE_H */
