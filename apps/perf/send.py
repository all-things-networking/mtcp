#! /usr/bin/env python

# Test network throughput.
#
# Usage:
# 1) on host_A: throughput -s [port]                    # start a server
# 2) on host_B: throughput -c  count host_A [port]      # start a client
#
# The server will service multiple clients until it is killed.

import sys, time
from socket import *

BUFSIZE = 8192

REPORT_INTERVAL = 0.5 # seconds

def bulk_send(conn, host, remoteport, send_time):
    bytes_sent = 0
    total_sent = 0
    start = time.time()
    last_report = time.time()
    i = 0

    # Create a buffer of data to send
    data = b'\xFF' * 1500  # Fill buffer with dummy data
    
    while time.time() - start < send_time:
        n = conn.send(data)
        bytes_sent += n
        total_sent += n

        now = time.time()
        elapsed = now - last_report
        if elapsed > REPORT_INTERVAL:
            thru_interval = ((bytes_sent / elapsed) * 8) / 1000000
            print "{} {:06.3f} Mbps".format((i * REPORT_INTERVAL), thru_interval)
            i += 1
            last_report = now
            bytes_sent = 0

    # Send an END signal to indicate completion
    conn.send(b'\x96')  # '\x96' as termination byte (similar to bulk_recv)
    print("Sent END to client")

    # Wait for acknowledgment from the client
    ack = conn.recv(BUFSIZE).decode('utf-8')
    if ack.strip() == "OK":
        print("Received acknowledgment from server")

    # Final throughput calculation
    end = time.time()
    thru = ((total_sent / (end - start)) * 8) / 1000000  # Mbps
    print("Done with {}:{}, bytes_sent: {}, time: {}, thru: {} Mbps".format(
        host, remoteport, bytes_sent, (end - start), thru))

def client(mode):
    ip = None
    port = None
    send_time = None

    if mode == "wait":
        port = eval(sys.argv[3])
        send_time = eval(sys.argv[4])
        s = socket(AF_INET, SOCK_STREAM)
        s.bind((sys.argv[2], port))
        s.listen(1)
        print 'Client ready...'
        while 1:
            conn, (host, remoteport) = s.accept()
            print 'Connected!'
            bulk_send(conn, host, remoteport, send_time)
    elif mode == "send":
        ip = sys.argv[2]
        port = eval(sys.argv[3])
        send_time = eval(sys.argv[4])
        s = socket(AF_INET, SOCK_STREAM)
        #s.setsockopt(SOL_SOCKET, SO_RCVBUF, 450000)
        s.connect((ip, port))
        print 'Connected'
        #while True:
        bulk_send(s, ip, port, send_time)
        


def usage():
    sys.stdout = sys.stderr
    print "usage: python send.py wait [port] [send time (seconds)]"
    print "usage: python send.py send [ip] [port] [send time (seconds)]"
    sys.exit(2)

def main():
    if len(sys.argv) < 5:
        usage()
    else:
        mode = sys.argv[1]
        if mode == "wait":
            if len(sys.argv) != 5:
                usage()
        elif mode == "send":
            if len(sys.argv) != 5:
                usage()
        else:
            print "Unknown mode", mode
        client(mode)

main()
