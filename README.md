# SniffJoke: transparent TCP connection scrambler 0.4.1

SniffJoke is an application for Linux that handle transparently your TCP connection, delaying, modifyng and inject fake packets inside your transmission, make them almost impossible to be correctly readed by a passive wiretapping technology (IDS or sniffer)

# Requirements

    cmake, gcc, iptables, tcpdump

Suggested

    gnupg

# How to compile/install
    mkdir build
    cd build
    cmake ..
    make 
    sudo -s
    make install

and you could check the exactly installed file by

    cat install_manifest.txt

# Suggested setup, for configure your network capabilities
    sniffjoke-autotest -l name_of_your_location -d /usr/local/var/sniffjoke -n 2

since you have runned the "autotest" in this network location (office, home, lab, etc...) you will invoke sniffjoke with:

    sniffjoke --location name_of_your_location
    sniffjokectl --stat
    sniffjokectl --start
    sniffjokectl --help
    [...]

# Link and info

SniffJoke man page: http://www.delirandom.net/sniffjoke/

SniffJoke location requirement: http://www.delirandom.net/sniffjoke/sniffjoke-locations

SniffJoke concepts, goals: http://www.delirandom.net/sniffjoke/sniffjoke-how-does-work

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

Linux OS (>=2.6.19) with tun support;

wifi/eth as default gateway (no other interface supported).

## Installed files 

The service binary

    /usr/local/bin/sniffjoke

The client, required to manage remotely the configuration of Sj

    /usr/local/bin/sniffjokectl

The "generic location" configuration, containing every default configuration files

    /usr/local/var/sniffjoke/generic/

SniffJoke plugins:

    /usr/local/lib/sniffjoke/*.so

Scripts:

    /usr/local/bin/sniffjoke-autotest
    /usr/local/bin/sj-iptcpopt-probe
    /usr/local/bin/sj-commit-results

Sniffjoke Man pages

    /usr/local/man/man1/sniffjoke.1
    /usr/local/man/man1/sniffjokectl.1
    /usr/local/man/man1/sniffjoke-autotest.1

# External service

Sniffjoke in autotesting required to contact http://www.delirandom.net/sjA, this is not striclty required
and if an user want to perform himself the test, will install the "pe.php" script, present in this package
here

    conf/sjA/pe.php

and using the semi-secret options -s and -a in sniffjoke-autotest (you will avoid every contact w/ delirandom)

# Official sniffjoke page:

http://www.delirandom.net/sniffjoke

(old) academic researchs:

http://www.delirandom.net/sniffjoke/Insertion%20Evasion%20and%20denial%20of%20service%20on%20IDS.pdf

Hacker's old bread:

http://www.phrack.org/issues.html?issue=54&id=10#article

MacOSx 0.3 ports as kernel module:

http://en.roolz.org/trafscrambler.html

Wireshark thread about Sj 0.3:

http://www.mail-archive.com/wireshark-dev@wireshark.org/msg13465.html

# Italian music support
http://www.youtube.com/watch?v=y2pZ8C7ODSs Uochi Toki - Il ladro
http://www.youtube.com/watch?v=T1-3q-vFsBY Uochi Toki - L'estetica

# GPG public keys
    X-2:~ X$ gpg --keyserver pgp.mit.edu --recv-key C6765430
    X-2:~ X$ gpg --fingerprint C6765430
    pub   1024D/C6765430 2009-08-25 [expires: 2011-08-25]
          Key fingerprint = 341F 1A8C E2B4 F4F4 174D  7C21 B842 093D C676 5430
    uid                  vecna <vecna@s0ftpj.org>
    uid                  vecna <vecna@delirandom.net>
    sub   3072g/E8157737 2009-08-25 [expires: 2011-08-25]

    X-2:~ X$ gpg --keyserver pgp.mit.edu --recv-key D9A950DE
    X-2:~ X$ gpg --fingerprint D9A950DE
    pub   1024D/D9A950DE 2009-05-10 [expires: 2014-05-09]
          Key fingerprint = C1ED 5C8F DB6A 1C74 A807  5695 91EC 9BB8 D9A9 50DE
    uid                  Giovanni Pellerano <giovanni.pellerano@evilaliv3.org>
    sub   4096g/50A7F150 2009-05-10 [expires: 2014-05-09]

    X-2:~ X$ gpg --keyserver pgp.mit.edu --recv-key 7D9E677D
    X-2:~ X$ gpg --fingerprint 7D9E677D
    pub   1024D/7D9E677D 2011-05-21
          Key fingerprint = F37C 2042 5052 27E2 2FD7  D511 947F 574B 7D9E 677D
    uid                  SniffJoke project (http://www.delirandom.net/sniffjoke)
