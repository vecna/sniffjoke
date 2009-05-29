#!/usr/local/bin/python

import sys
import time

if len(sys.argv) < 2:
    print "usage: swilltest port [test_name]"
    raise SystemExit

port = int(sys.argv[1])
from socket import *

# Send a large header with no discernible
def test_big_request(s):
    print "Testing a large request"
    x = 'x'*65536
    s.send(x)

def test_bad_request(s):
    print "Testing malformed request (too many fields)"
    s.send("GET /index.html HTTP/1.0 FOO BAR\n")

def test_bad_request1(s):
    print "Testing malformed request (bad method)"
    s.send("HTTP/1.0 /index.html GET\n\n")

def test_bad_request2(s):
    print "Testing malformed header (no termination)"
    s.send("""GET /index.html HTTP/1.0
Header1: value
Header2: value""")

def test_big_header(s):
    print "Testing large number of header fields"
    s.send("GET /index.html HTTP/1.0\n")
    for i in range(0,1000):
        s.send("Header%d: value%d\n" % (i,i))
        
def test_timeout(s):
    print "Testing timeout. Not sending any data"

def test_huge_query(s):
    print "Sending a large query string"
    s.send("""POST /index.html HTTP/1.0
Content-length: 1000000\n\n""")
    s.send("x"*1000000)

def test_trunc_query(s):
    print "Sending a truncated query string"
    s.send("""POST /index.html HTTP/1.0
Content-length: 10000\n\n""")
    s.send("Eek!")

def test_bad_query(s):
    print "Sending a malformed query string"
    s.send("GET /index.html?foo=bar&spam&grok=;;;&&? HTTP/1.0\n\n")

def test_aborted_connect(s):
    print "Closing connection on client"
    s.close()

def test_delayed_read(s):
    print "Testing write timeouts."    
    s.send("GET /swill.html HTTP/1.0\n\n")
    time.sleep(15)
    
funcs = [x for x in dir() if x[:5] == 'test_']
funcs.sort()

try:
    if sys.argv[2]:
        funcs = [ x for x in funcs if x == sys.argv[2]]
except:
    pass

for f in funcs:
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(("localhost",port))

    try:
        print"[%s]" % f,
        exec("%s(s)" % f)
        data = ""
        while (1):
            ndata = s.recv(8192)
            if not ndata: break
            data += ndata
        if not data:
            print "     Received no data"
        else:
            print "     Received: %s" % data.splitlines()[0]

    except error:
        print "     Connection closed"

    try:
        s.close()
    except error:
        pass
    


