# SniffJoke: transparent TCP connection scrambler

SniffJoke is an application for Linux that handle transparently your
TCP connection, delaying, modifyng and inject fake packets inside your
transmission, make it almost impossible to be wiretapped.

# Installation
    ./configure && make && make install

# Simple immediate execution
   root@linux# sniffjoke --debug 6 --start --foreground

# What's is this project

SniffJoke 0.4 beta 4, last update: Mon Feb 7 01:30:26 CET 2011

# REQUIREMENTS:

Linux OS (>=2.6.19) with tun kernel module;
wifi/eth as default gateway (no other interface supported).

## Installed files (paths may vary in your system), becuase configure supports --prefix:


The service binary
 /usr/local/bin/sniffjoke

The client, required for manage remotely the configuration of Sj
 /usr/local/bin/sniffjokectl

The "generic location" configuration, contains every default configuration files
 /usr/local/var/sniffjoke/generic/

SniffJoke plugins
 /usr/local/lib/sniffjoke/*.so

# REFERENCE LINKS:

the files:
  doc/*

official sniffjoke page:
  http://www.delirandom.net/sniffjoke

binary installed:
  sniffjoke
  sniffjokectl

script included
  sniffjoke-autotest

(old) academic researchs:
  http://www.delirandom.net/sniffjoke/Insertion%20Evasion%20and%20denial%20of%20service%20on%20IDS.pdf

hacker's bread:
  http://www.phrack.org/issues.html?issue=54&id=10#article

MacOSx ports as kernel module:
  http://en.roolz.org/trafscrambler.html

Wireshark thread about Sj 0.3:
  http://www.mail-archive.com/wireshark-dev@wireshark.org/msg13465.html

## music compāniōn-, Italian text only:

  http://www.youtube.com/watch?v=y2pZ8C7ODSs Uochi Toki - Il ladro
  http://www.youtube.com/watch?v=Hv4PchuPrGc Uochi Toki - i gesti di cattiveria
  http://www.youtube.com/watch?v=T1-3q-vFsBY Uochi Toki - L'estetica
