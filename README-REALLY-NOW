SniffJoke 0.4 BETA 4 - 25 January 2011

developed by vecna and evilaliv3

homepage: http://www.delirandom.net/sniffjoke
developing 0.4 beta: http://github.com/vecna/sniffjoke
developing 0.4 beta: http://github.com/evilaliv3/sniffjoke

HEADLINE:

This software is a single peer sniffer obfuscator. when you start sniffjoke
from your network privileges, the outgoing internet connections became 
scattered with fake data - without interfere with your sessions - and confusing
the sniffers in the network when their algorithms try to follow your stream.

REMIND:

1) sniffjoke obfuscates the passive data collection: a man in the middle using 
   a passive software like wireshark, dsniff, xplico, carnivore, ecc...
   ... so DOES NOT PROTECT about the data you, willing or not, send to evil third 
   party, like a phisher, facebook or a proxy service.
2) sniffjoke does not guarantee a protection from an uber network expert that collects
   your data BY HANDS (if you know what's a tcp reconstruction flow, you will figure that 
   is less expensive, for your enemy, to buy a whore payed for drug you), sniffjoke 
   if effective defense from a massive data collection, a threat well solved by
   cryptography but the lack of security culture in "the others" require some single
   peer solution.

SniffJoke is a free software, implemented in C++, and at the moment supports
only under Linux environment. Will be easy make the OSX+BSD mods, will became
in short.

HOW TO COMPILE/INSTALL:

./configure && make && make install
(sniffjoke is installed in /usr/local/bin, check your path when you do):

SniffJoke package is composed by three software:

sniffjoke
    the service, when started in background make the network coolnes 
sniffjokectl
    the client, manage the service configuration when sniffjoke is running
    (at the star time, is better used the command line options or the various
    configuration file)
sniffjoke-autotest
    script able to test your network environment and generate a "location", the
    options used in sniffjoke to describe a network environment with a specific
    configuration

# sniffjoke --help
# sniffjokectl --help

FEW TECHNICAL INFO:

1) If you start SniffJoke without the --location parameter sniffjoke will use
   the "generic" location. every location has a directory dedicated, the 
   directory where the configuration files are stored, sniffjoke service chroot
   himself and the logfile are written.
2) SniffJoke is a software that mangles kernel traffic in userspace. To satisfy
   this condition it requires some weird hack, like creation of a
   fake-tunnel interface and use of the same local IP address. SniffJoke tries
   to be verbose for the user. 
3) There are some KNOW BUGS, like duplicated ICMP REPLY when using ping with
   sniffjoke running.
4) Sniffjoke executes some commands on your box. the code is open, you should detect
   how the command line are created grepping for the popen() functions, in the 
   sniffjoke website you should find an exaustive documentation about how does Sj work.
5) sniffjoke conf (and ttl cache) are BINARY, should not be edited from the user, 
   and keep track about your ports setting. restaring Sniffjoke resume previously 
   configuration.
6) the TTL cache is tracked differenty for each network environment you use, and
   in some location will neither work. for this reason, when sniffjoke is 
   started in a new location, I suggest to run sniffjoke-autotest (a script
   testing each plugin and each scrambling technology, to detect automatically
   what kind of scrambling your network environment supports)

DOCUMENTATION, will be found in doc/* directory, and an intesive commentary
is spreaded in the code.
