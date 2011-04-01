/*
 * SniffJoke is a software able to confuse the Internet traffic analysis,
 * developed with the aim to improve digital privacy in communications and
 * to show and test some securiy weakness in traffic analysis software.
 *    
 *  Copyright (C) 2010, 2011 vecna <vecna@delirandom.net>
 *                           evilaliv3 <giovanni.pellerano@evilaliv3.org>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http:www.gnu.org/licenses/>.
 */

#ifndef IPTCPOPTAPPLY_H
#define IPTCPOPTAPPLY_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "HDRoptions.h"

class Io_NOOP : public optionImplement
{
public:
    Io_NOOP(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
    uint8_t optApply(struct optHdrData *);
};

class Io_TIMESTAMP : public optionImplement
{
public:
    Io_TIMESTAMP(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_TIMESTOVERFLOW: public optionImplement
{
private:
    TTLFocus *ttlfocus;
public:
    Io_TIMESTOVERFLOW(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
    void setupTTLFocus(TTLFocus *);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_LSRR : public optionImplement
{
public:
    Io_LSRR(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_RR : public optionImplement
{
public:
    Io_RR(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_RA : public optionImplement
{ 
public:
    Io_RA(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_CIPSO : public optionImplement
{ 
public:
    Io_CIPSO(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_SEC : public optionImplement
{
public:
    Io_SEC(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
protected:
    uint8_t optApply(struct optHdrData *);
};

class Io_SID : public optionImplement
{
public:
    Io_SID(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
protected:
    uint8_t optApply(struct optHdrData *);
};

class To_NOP : public optionImplement
{
public:
    To_NOP(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
protected:
    uint8_t optApply(struct optHdrData *);
};

class To_MD5SIG : public optionImplement
{
public:
    To_MD5SIG(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
protected:
    uint8_t optApply(struct optHdrData *);
};

class To_PAWSCORRUPT : public optionImplement
{
public:
    To_PAWSCORRUPT(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
protected:
    uint8_t optApply(struct optHdrData *);
};

#endif /* HDROPTIONS_H */
