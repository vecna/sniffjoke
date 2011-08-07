# SniffJoke: transparent TCP connection scrambler 0.5-devel

SniffJoke is an application for Linux that handle transparently your TCP connection, delaying, modifyng and inject fake packets inside your transmission, make them almost impossible to be correctly readed by a passive wiretapping technology (IDS or sniffer)

# Requirements

    janus package: http://github.com/evilavliv3/janus the nighly release
    libevent installed (developed and tested with the 1.4.2 version)
    libpcap
    cmake (minimum version required: 2.8)
    gcc/g++ (4.2.4 version tested & developed)

Suggested

    gnupg



# TODO, for stabilize 0.5

    implement/fix the new scrambling tech
    verify libevent supports
    Janus stabilization and portability supports
    IP/TCP opt no more autotested
    Strong use of cache
    location self-recognition, location concept need to be linked with janus

# SniffJoke directory explaination

    dist/doc

documentation, txt, explanation and so on

    dist/generic

the base configuration, every location will start from the 'generic' location

    dist/sjA

sniffjoke autotest scripts, the web service used for test sniffjoke reialability since a location, and (TODO) analysis and stats

    src/service

the core of the project, C++ code that compiled give the sniffjoke binary

    src/client

sniffjoke will be controlled by command line at the startup, or via commands given by a client. In this times, also a windows client is under development, and the client should be remote from Sj (that should be remote from janus)

    src/plugins

the attack metodoloy to defeat sniffer will be improved, personally implemented and enable on requests. plugins contains the C++ classes compiled as shared library, loaded at the startup.

# Janus

SniffJoke since the release 0.5 works only in conjunction with a Janus instance. Janus is a "traffic diverter" and should run in the same host where Sj is running, or in a different hosts.

Since the 0.5 release, SniffJoke aim to became fully portable, and Janus provide network handling (and portability issue)

# How to compile/install
    mkdir build
    cd build
    cmake ..
    make 
    sudo -s
    make install

# How to use SniffJoke

you need to have installed Janus, stable release at http://github.com/evilaliv3/janus

# Suggested setup, for configure your network capabilities
    sniffjoke-autotest -l name_of_your_location 

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
    plugin.$PLUGIN_NAME.log
    ttlfocusmap.bin

# CONFIG FILES generated as location specific by sniffjoke-autotest
    iptcp-options.conf
    plugins-enabled.conf

## Installed files 

This is the 'generic' (act as a default) location. Remind: every network location you're using (your office, your home, etc), track different cache. using a cache collected in a different location will cause the total corruption of the connections, and therfore before use sniffjoke you have to create a sperate directory for every network places you are using. In the future, this selection will be automatized using the mac address+IP of the default gateway in order to detect a different location.

    /usr/local/var/sniffjoke/generic
    /usr/local/var/sniffjoke/generic/plugins-enabled.conf
    /usr/local/var/sniffjoke/generic/THIS_IS_GENERIC
    /usr/local/var/sniffjoke/generic/port-aggressivity.conf
    /usr/local/var/sniffjoke/generic/iptcp-options.conf
    /usr/local/var/sniffjoke/generic/sniffjoke-service.conf
    /usr/local/var/sniffjoke/generic/ipwhitelist.conf.example
    /usr/local/var/sniffjoke/generic/ipblacklist.conf.example

sjA script, nothing useful for an user:

    /usr/local/var/sniffjoke/sjA
    /usr/local/var/sniffjoke/sjA/pe.php
    /usr/local/var/sniffjoke/sjA/README.txt

man pages:

    /usr/local/share/man/man1/sniffjoke.1
    /usr/local/share/man/man1/sniffjokectl.1
    /usr/local/share/man/man1/sniffjoke-autotest.1

the binaries:

    /usr/local/bin/sniffjoke
    /usr/local/bin/sniffjokectl

the plugins:

    /usr/local/var/sniffjoke/plugins/fake_close_rst.so
    /usr/local/var/sniffjoke/plugins/fake_close_fin.so
    /usr/local/var/sniffjoke/plugins/valid_rst_fake_seq.so
    /usr/local/var/sniffjoke/plugins/fake_syn.so
    /usr/local/var/sniffjoke/plugins/[...].so

the scripts:

    /usr/local/bin/sniffjoke-autotest
    /usr/local/bin/sj-iptcpopt-probe
    /usr/local/bin/sj-commit-results

# External service

Sniffjoke in autotesting required to contact http://www.delirandom.net/sjA, this is not striclty required
and if an user want to perform himself the test, will install the "pe.php" script, present in this package.
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
