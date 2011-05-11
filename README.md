# SniffJoke: transparent TCP connection scrambler

SniffJoke is an application for Linux that handle transparently your TCP connection, delaying, modifyng and inject fake packets inside your transmission, make them almost impossible to be correctly readed by a passive wiretapping technology (IDS or sniffer)

# Requirement

    cmake, gcc, iptables, tcpdump

# or, if you're makin some code modify
    mkdir build
    cd build
    cmake ..
    make 
    sudo -s
    make install

and you could check the exaclty installed file by
    cat install_manifest.txt

# Simple immediate verbose execution
    root@linux# sniffjoke --debug 6 --start --foreground

# Correct setup, check your network capabilities
    sniffjoke-autotest -l name_of_your_location -d /usr/local/var/sniffjoke -n 2

since you have runned the "autotest" in this network location (office, home, lab, etc...) you will invoke sniffjoke with
    sniffjoke --location name_of_your_location
    sniffjokectl --stat
    sniffjokectl --start
    sniffjokectl --help
    [...]

# CONFIG FILES installed in the 'generic' location
    ipblacklist.conf
    iptcp-options.conf
    ipwhitelist.conf
    plugins-enabled.conf
    port-aggressivity.conf
    sniffjoke-service.conf

# CACHE and LOGs that should be generated in a location
    plugin.fake_close_fin.log
    plugin.fragmentation.log
    plugin.segmentation.log
    ttlfocusmap.bin

# CONFIG FILES generated as location specific by sniffjoke-autotest
    iptcp-options.conf
    plugins-enabled.conf

# Requirements

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

# Internal & external links

Official sniffjoke page:
    http://www.delirandom.net/sniffjoke

Binary installed:
    sniffjoke
    sniffjokectl

Script installed:
    sniffjoke-autotest
    sj-iptcp-probe (not intended to be called directly by an user, useful for developer)

(old) academic researchs:
    http://www.delirandom.net/sniffjoke/Insertion%20Evasion%20and%20denial%20of%20service%20on%20IDS.pdf

Hacker's old bread:
    http://www.phrack.org/issues.html?issue=54&id=10#article

MacOSx ports as kernel module:
    http://en.roolz.org/trafscrambler.html

Wireshark thread about Sj 0.3:
    http://www.mail-archive.com/wireshark-dev@wireshark.org/msg13465.html

# Italian music support
    http://www.youtube.com/watch?v=y2pZ8C7ODSs Uochi Toki - Il ladro
    http://www.youtube.com/watch?v=T1-3q-vFsBY Uochi Toki - L'estetica

# GPG public keys
    X-2:~ X$ gpg --keyserver pgp.mit.edu --recv-key C6765430
    X-2:~ X$ gpg --fingerprint --list-keys C6765430
    pub   1024D/C6765430 2009-08-25 [expires: 2011-08-25]
          Key fingerprint = 341F 1A8C E2B4 F4F4 174D  7C21 B842 093D C676 5430
    uid                  vecna <vecna@s0ftpj.org>
    uid                  vecna <vecna@delirandom.net>
    sub   3072g/E8157737 2009-08-25 [expires: 2011-08-25]

    X-2:~ X$ gpg --keyserver pgp.mit.edu --recv-key D9A950DE
    X-2:~ X$ gpg --fingerprint --list-keys D9A950DE
    pub   1024D/D9A950DE 2009-05-10 [expires: 2014-05-09]
          Key fingerprint = C1ED 5C8F DB6A 1C74 A807  5695 91EC 9BB8 D9A9 50DE
    uid                  Giovanni Pellerano <giovanni.pellerano@evilaliv3.org>
    sub   4096g/50A7F150 2009-05-10 [expires: 2014-05-09]
    
