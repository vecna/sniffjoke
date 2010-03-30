#######################################################################
# $Header: /cvsroot/swill/SWILL/Source/SWILL/Makefile.in,v 1.5 2006/12/21 21:07:03 gonzalodiethelm Exp $
#######################################################################

srcdir = .


#.KEEP_STATE:

CC      = gcc
CCSHARED= -fpic
prefix  = /usr/local
RANLIB  = ranlib
AR      = ar
SO      = .so
LDSHARED= gcc -shared
NETLIBS = 

########################################################################
# Normally, you shouldn't have to change anything below this point     #
########################################################################

LIBOBJS = log.o io.o encoding.o handlers.o mime.o parse.o web.o security.o sock.o ssl.o
LIBSRCS = log.c io.c encoding.c handlers.c mime.c parse.c web.c security.c sock.c ssl.c

DOHOBJS = ../Objects/*.o
LIBHEADERS = $(srcdir)/../Include/swill.h
LIB        = libswill$(SO)
SLIB       = libswill.a
INCLUDE    = -I$(srcdir)/../../Include -I$(srcdir)/../Objects 
CFLAGS     = 
SHELL      = /bin/sh

#
# Rules for creation of a .o file from .cxx
.SUFFIXES: .c
.c.o:
	$(CC) $(CCSHARED) $(INCLUDE) $(CFLAGS) -c -o $*.o $<

first: all

../../$(SLIB): $(LIBOBJS)
	@echo "Building static library"
	$(AR) cr $(SLIB) $(LIBOBJS) $(DOHOBJS)
	cp -f $(SLIB) ../..

../../$(LIB): $(LIBOBJS)
	@echo "Building shared library"
	$(LDSHARED) $(LIBOBJS) $(DOHOBJS) -o $(LIB) $(NETLIBS)
	cp -f $(LIB) ../..

static: ../../$(SLIB)

shared: ../../$(LIB)

all: static shared

clean::
	rm -f *.o a.out core $(LIB) ../../$(LIB) $(SLIB) ../../$(SLIB)

nuke:: clean
	rm -f Makefile *~ #*
