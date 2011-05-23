SniffJoke 0.4.1

developed by vecna and evilaliv3

homepage: http://www.delirandom.net/sniffjoke

code repositories:
    http://github.com/vecna/sniffjoke
    http://github.com/evilaliv3/sniffjoke

HEADLINE:

This software is a single peer sniffer obfuscator. when you start SniffJoke
from your network privileges, the outgoing internet connections became 
scattered with fake data - without interfere with your sessions - and confusing
the sniffers in the network when their algorithms try to follow your stream.

REMIND:

1) SniffJoke obfuscates the passive data collection: a man in the middle using 
   a passive software like wireshark, dsniff, xplico, carnivore, ecc...
   ... so DOES NOT PROTECT about the data you, willing or not, send to evil third 
   party, like a phisher, facebook or a proxy service.
2) SniffJoke does not guarantee a protection from an uber network expert that collects
   your data BY HANDS (if you know what's a tcp reconstruction flow, you will figure that 
   is less expensive, for your enemy, to buy a whore payed for drug you), SniffJoke 
   if effective defense from a massive data collection, a threat well solved by
   cryptography but the lack of security culture in "the others" require some single
   peer solution.

SniffJoke is a free software, implemented in C++, and at the moment supports
only under Linux environment. Will be easy make the OSX+BSD mods, will became
in short.

Some dumps from the site: http://www.deliandom.net/sniffjoke

What's SniffJoke ?

    An internet client running SniffJoke injects in the transmission flow some packets 
able to seriously disturb passive analysis like sniffing, interception and low level information 
theft.  No server supports needed!

Why is this possible ?

    The internet protocols have been developed to allow two elements to communicate, not some 
third-parts to intercept their communication. This will happen, but the communication system 
has been not developed with this objective.
    SniffJoke uses the network protocol in a permitted way, exploiting the implicit difference 
of network stack present in an operating system respect the sniffers dissector.

Why has it been developed ?

    Because too many people believe that the only way to obtain self-security is through control, 
I don't want to tell them they are wrong, but controlling internet is impossibile, if you want not to 
be controlled. It is obvious that you should not trust a security control that could be bypassed, isn't it?

    When you understand this, remember that the progressive acceptance of the control measure has 
been treated like a "necessary sacrifice". when you realize that this security method don't bring security, 
but only possibile abuses, you will be ready to stop accepting this useless sacrifice.

What's SniffJoke don't protect from

    If you are using a nontrusted third part (facebook?) it doesn't matter how much your data is 
encrypted, scrambled or whatever: your data is in facebook store. Unprotected and presented. If you 
use a trojanized box, it's the same, it's like have an invisible and weightless watchers sit on your 
legs, transcribing everything you're doing. SniffJoke protects from: a sniffer in your network, a 
sniffer in the provider flow, a sniffer in the destination network.

Security and social GOALs

    Various goals SniffJoke aim to achieves. Information security, will not be control based, 
almost, not in traffic and data passive analysis, because Internet technology is not engineered 
with this capability. Passive wiretapping is not only used by law enforcement (they have a lot 
of other technology in their dispositions); Wiretapping technology is widespread and usable by every 
entities, not for your safety, but for the value derived from your data.

homepage updated 22/05/2011
