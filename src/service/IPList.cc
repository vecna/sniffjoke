/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2011 vecna <vecna@delirandom.net>
 *                      evilaliv3 <giovanni.pellerano@evilaliv3.org>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "IPList.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

IPList::IPList(uint32_t ip, uint8_t a, uint8_t b, uint8_t c) :
ip(ip),
a(a),
b(b),
c(c)
{
    SELFLOG("");
}

IPList::~IPList(void)
{
    SELFLOG("");
}

void IPList::selflog(const char *func, const char *format, ...) const
{
    if (debug.level() == SUPPRESS_LEVEL)
        return;

    char loginfo[LARGEBUF];
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(loginfo, sizeof (loginfo), format, arguments);
    va_end(arguments);

    LOG_SESSION("%s: IP %s attribute a(%02x) b(%02x) c(%02x) %s",
                func, inet_ntoa(*((struct in_addr *) &(this->ip))), this->a, this->b, this->c, loginfo);
}

IPListMap::IPListMap(const char* ipConfFile)
{
    LOG_ALL("loading ipList from %s", ipConfFile);
    dumpfname = ipConfFile;
    load();
}

IPListMap::~IPListMap(void)
{
    dump();
    for (IPListMap::iterator it = begin(); it != end();)
    {
        delete &(*it->second);
        erase(it++);
    }
}

IPList& IPListMap::add(uint32_t ip, uint8_t a, uint8_t b, uint8_t c)
{
    IPList *ipcnf;

    /* check if the key it's already present */
    IPListMap::iterator it = find(ip);
    if (it != end()) /* on hit: update the IPConfig object. */
    {
        ipcnf = &(*it->second);
        ipcnf->a = a;
        ipcnf->b = b;
        ipcnf->c = c;
    }
    else /* on miss: create a new IPConfig and insert it into the map */
        ipcnf = &(*insert(pair<uint32_t, IPList*>(ip, new IPList(ip, a, b, c))).first->second);

    return *ipcnf;
}

bool IPListMap::isPresent(uint32_t ip) const
{
    return (find(ip) != end());
}

void IPListMap::load(void)
{
    char record[MEDIUMBUF];
    char tmp_ip[17];
    uint32_t tmp_a, tmp_b, tmp_c;

    FILE *IPfileP = fopen(dumpfname, "r");
    if (IPfileP == NULL)
    {
        LOG_ALL("unable to open %s: %s", dumpfname, strerror(errno));
        return;
    }

    uint32_t records_num = 0;
    do
    {
        tmp_a = tmp_b = tmp_c = 0;
        memset(record, 0x00, MEDIUMBUF);

        if ( fgets(record, sizeof (record), IPfileP) == NULL )
            break;

        if (record[0] == '#' || record[0] == '\n' || record[0] == ' ' || strlen(record) < 7)
            continue;

        /* C's chop() */
        if (record[strlen(record) - 1] == '\n')
            record[strlen(record) - 1] = 0x00;

        sscanf(record, "%s %u,%u,%u", tmp_ip, &tmp_a, &tmp_b, &tmp_c);
        LOG_VERBOSE("importing record %d: %s %u,%u,%u", records_num, tmp_ip, tmp_a, tmp_b, tmp_c);

        /* the value in tmp_* are not used at the moment */
        add(inet_addr(tmp_ip), (uint8_t) tmp_a, (uint8_t) tmp_b, (uint8_t) tmp_c);
        records_num++;
    }
    while (!feof(IPfileP));

    fclose(IPfileP);

    LOG_ALL("from %s completed: %u records loaded", dumpfname, records_num);
}

/* Implemented but not used until the client sniffjokectl supports the updating of whitelist/blacklist */
void IPListMap::dump(void)
{
    FILE *IPfileP = fopen(dumpfname, "w");
    if (IPfileP == NULL)
        LOG_ALL("unable to open %s: %s", dumpfname, strerror(errno));

    uint32_t records_num = 0;
    for (IPListMap::iterator it = begin(); it != end(); ++it)
    {
        IPList *tmp = &(*it->second);

        char record[MEDIUMBUF];
        snprintf(record, sizeof (record), "%s %u,%u,%u\n", inet_ntoa(*((struct in_addr *) &(tmp->ip))), tmp->a, tmp->b, tmp->c);

        if (fwrite(&record, strlen(record), 1, IPfileP) != 1)
        {
            LOG_ALL("unable to dump ipconfig: %s", strerror(errno));
            return;
        }

        ++records_num;
    }
    fclose(IPfileP);

    LOG_ALL("completed with %u records dumped", records_num);
}
