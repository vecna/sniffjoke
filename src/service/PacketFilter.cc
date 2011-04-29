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

#include "PacketFilter.h"

FilterEntry::FilterEntry(uint16_t id, uint16_t totallen, uint32_t saddr, uint32_t daddr) :
ip_id(id),
ip_totallen(totallen),
ip_saddr(saddr),
ip_daddr(daddr)
{
}

FilterEntry::FilterEntry(const Packet &pkt) :
ip_id(pkt.ip->id),
ip_totallen(pkt.ip->tot_len),
ip_saddr(pkt.ip->saddr),
ip_daddr(pkt.ip->daddr)
{
}

bool FilterEntry::operator<(FilterEntry comp) const
{
    if (ip_id < comp.ip_id)
        return true;
    else if (ip_id > comp.ip_id)
        return false;
    else
    {
        if (ip_totallen < comp.ip_totallen)
            return true;
        else if (ip_totallen > comp.ip_totallen)
            return false;
        else
        {
            if (ip_saddr < comp.ip_saddr)
                return true;
            else if (ip_saddr > comp.ip_saddr)
                return false;
            else
            {
                if (ip_daddr < comp.ip_daddr)
                    return true;
                else
                    return false;
            }
        }
    }
}

FilterMultiset::FilterMultiset(void) :
timeout_len(PLUGINHASH_EXPIRYTIME),
manage_timeout(sj_clock + timeout_len),
first(&fm[0]),
second(&fm[1])
{
}

FilterMultiset::~FilterMultiset(void)
{
    first->clear();
    second->clear();
}

/*
 * tests the existance of the entry;
 * returns:
 *      - true:  if found, and automatically does remove the entry;
 *               due to the multiset entry can be duplicated, this is
 *               a feature much important that permit a fine count
 *               during packet filtering.
 * 
 *      - false: if not found.
 */
bool FilterMultiset::check(const FilterEntry &hash)
{
    manage();

    if (first->erase(hash) || second->erase(hash))
        return true;

    return false;
}

/*
 * inserts a new entry; due to the use of multiset entry can be
 * duplicate; this is particular important to permit multiple
 * packet to define multiple filters.
 * so repeated filters works as a fine counter during packet filtering.
 *
 */
void FilterMultiset::add(const FilterEntry &hash)
{
    second->insert(hash);
}

void FilterMultiset::manage(void)
{
    if (manage_timeout > sj_clock - timeout_len)
        return;

    multiset<FilterEntry> *tmp = first;
    first = second;
    second = tmp;
    second->clear();

    manage_timeout = sj_clock + timeout_len;
}

bool PacketFilter::filterICMPErrors(const Packet &pkt)
{
    if (pkt.icmppayloadlen > sizeof (struct iphdr))
    {
        const struct iphdr *ip = (struct iphdr*) pkt.icmppayload;
        FilterEntry filter(ip->id, ip->tot_len, ip->saddr, ip->daddr);
        return filter_multiset.check(filter);
    }

    return false;
}

void PacketFilter::add(const Packet& pkt)
{
    FilterEntry hash(pkt);
    filter_multiset.add(hash);
}

bool PacketFilter::match(const Packet& pkt)
{
    if (pkt.proto == ICMP)
        return filterICMPErrors(pkt);

    return false;
}

