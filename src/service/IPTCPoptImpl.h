/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *
 *  Copyright (C) 2010, 2011 vecna <vecna@delirandom.net>
 *                           evilaliv3 <giovanni.pellerano@evilaliv3.org>
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

#ifndef SJ_IPTCPOPTIMPL_H
#define SJ_IPTCPOPTIMPL_H

#include "Utils.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "IPTCPopt.h"
#include "TTLFocus.h"

#define IPOPT_NOOP_SIZE     1
#define IPOPT_CIPSO         (6 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_CIPSO_SIZE    10
#define IPOPT_SID_SIZE      4

#define TCPOPT_NOP_SIZE     1
#define TCPOPT_MD5SIG       19
#define TCPOPT_MD5SIG_SIZE  18
#define TCPOPT_MSS          2
#define TCPOPT_MSS_SIZE     4

#define DUMMY_OPCODE        255

class Io_NOOP : public IPTCPopt
{
public:
    Io_NOOP(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_EOL : public IPTCPopt
{
public:
    Io_EOL(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_TIMESTAMP : public IPTCPopt
{
public:
    Io_TIMESTAMP(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_TIMESTOVERFLOW : public IPTCPopt
{
private:
    TTLFocus *ttlfocus;
public:
    Io_TIMESTOVERFLOW(bool);
    void setupTTLFocus(TTLFocus *);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_LSRR : public IPTCPopt
{
public:
    Io_LSRR(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_RR : public IPTCPopt
{
public:
    Io_RR(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_RA : public IPTCPopt
{
public:
    Io_RA(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_CIPSO : public IPTCPopt
{
public:
    Io_CIPSO(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_SEC : public IPTCPopt
{
public:
    Io_SEC(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_SID : public IPTCPopt
{
public:
    Io_SID(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class To_NOP : public IPTCPopt
{
public:
    To_NOP(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class To_EOL : public IPTCPopt
{
public:
    To_EOL(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class To_MD5SIG : public IPTCPopt
{
public:
    To_MD5SIG(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class To_PAWSCORRUPT : public IPTCPopt
{
public:
    To_PAWSCORRUPT(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class To_TIMESTAMP : public IPTCPopt
{
public:
    To_TIMESTAMP(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class To_MSS : public IPTCPopt
{
public:
    To_MSS(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class To_SACK : public IPTCPopt
{
public:
    To_SACK(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class To_SACKPERM : public IPTCPopt
{
public:
    To_SACKPERM(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

class To_WINDOW : public IPTCPopt
{
public:
    To_WINDOW(bool);
protected:
    uint8_t optApply(struct optHdrData *);
};

#endif /* SJ_IPTCPOPTIMPL_H */

