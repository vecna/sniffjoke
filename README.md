# SniffJoke: transparent TCP connection scrambler

SniffJoke is an application for Linux that handle transparently your TCP connection, delaying, modifyng and inject fake packets inside your transmission, make them almost impossible to be correctly readed by a passive wiretapping technology (IDS or sniffer)

# Installation
    ./configure && make && make install

# Simple immediate execution
    root@linux# sniffjoke --debug 6 --start --foreground

# Requirements

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

Betatesting 
-----------

The file **BETATESTING** is provided in the root directory of the package: every betatester has a good point to start

# How does it work + Documentation

Sniffjoke is an userspace software able to delay, block and modify the packets sent from the kernel. For obtain this, use a fake default gateway make with a tunnel device. run in background, read some configuration files, and related to which place is started will support a different *location*.

The doc/ directory include some usuful files:

This file contains know bugs and weird situation derived from the network/kernel use/misuse:
    bugs-and-warning.txt

This explain the *location* concept, the generation of new location with *sniffjoke-autotest*:
    config-location.txt

This was the older README file, contain some generic info, syntetized and better explained in the other files:
    generic-infos-README.txt

Explanation of the networking hacks for make the userspace service act after the kernel:
    networking.txt

SniffJoke supports plugin (implementing the IDS/sniffers evasion techniques), this is the related howto:
    plugin-development.txt

SniffJoke use an internal protocol for comunication between the service (that will be start/stopped/logged/etc...) and the client: a binary that would run in another box (eg: your Linux gateway run sniffjoke, and from your client you manage it). This file explain the protocol, just in case other client will support it:
    SJ-PROTOCOL.txt

Explanation about the script *sniffjoke-autotest* that check every plugin+scramble combination, searching for eventually couple that in your network environment will not work (thus generating coherent configuration files)
    sniffjoke-autotest.txt

Explanation of the plugin work and the scrambling concept: the technique that confuse the sniffers and the software that inject in the confused flow the unexpected data.
    tcp-hacks-and-scrambling.txt

Example of usage, configuration etc..
    usage.txt

TODO, and if you will help, we are glad:
    TODO.txt

# Internal & external links

the files:
    doc/*

official sniffjoke page:
    http://www.delirandom.net/sniffjoke

binary installed:
    sniffjoke
    sniffjokectl

script installed:
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
