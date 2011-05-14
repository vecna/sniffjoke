This plugin is not intended to be used in the common sniffjoke daily activities,
when is loaded it take a command line options that specify which kind of
IP/TCP options will be used in your network.

This probe is required, because in some network an options will be discarded and 
another will be accepted, and in other networks opposite results can happen too.

Whenever an hacker/coder/whatever update the IPTCPoptImpl.cc
is needed updating sj-iptcp-probe script, the definition in hardcodedDefine.h and
make a lot of testing, because the IP/TCP options mangling is the most delicate
scrhackmbling ever made :P good luck!
