#######################################################################
# $Header: /cvsroot/swill/SWILL/Examples/Makefile.in,v 1.3 2005/05/25 21:24:49 gonzalodiethelm Exp $
#######################################################################

srcdir = .


prefix     = /usr/local
exec_prefix= ${prefix}

INCLUDE_DIR = $(prefix)/include 
LIB_DIR = $(exec_prefix)/lib
LIBS    = 

#.KEEP_STATE:

CC      = gcc
MPICC   = 

BINARIES = simple sg mandel mpi talk

#
# Rules for creation of a .o file from .c
.SUFFIXES: .c
.c.o:
	$(CC) -I $(INCLUDE_DIR) $(CFLAGS) -c -o $*.o $<

first:	simple

simple: simple.o
	$(CC) simple.o -L$(LIB_DIR) -lswill $(LIBS) -o simple

sg: sg.o
	$(CC) sg.o -L$(LIB_DIR) -lswill -lgifplot -lm $(LIBS) -o sg

mandel: mandel.o
	$(CC) mandel.o -L$(LIB_DIR) -lswill -lgd -lpng -ljpeg -lz -lm $(LIBS) -o mandel

mpi: mpi.o
	$(MPICC) mpi.o -L$(LIB_DIR) -lswillmpi $(LIBS) -o mpi

talk: talk.o
	$(CC) talk.o  -L$(LIB_DIR) -lswill -lgd -lpng -ljpeg -lz -lm $(LIBS) -o talk


all: $(BINARIES)

clean::
	rm -f *.o a.out core $(BINARIES)

nuke:: clean
	rm -f Makefile *~ #*
