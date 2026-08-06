Throughput Measurement Application
==================================

As the name suggests, this application is an iperf-like application which
attempts to measure throughput with mTCP by measuring the time it takes to
complete a bulk transfer.

The server and client use mTCP sockets, while the receiver and sender are written
in Python using traditional sockets so that it can be run on a machine that 
does not have DPDK/mTCP installed.

The traffic always flows from client to receiver, or from sender to server, 
but there are two different modes that allow you to specify whether the client/server
or receiver/sender should initiate the connection:

1. mTCP client initiates the connection by calling the socket `connect` function (which corresponds to MTP `connect` function, which is not implemented; thus we need to implement `connect_ep` and `ack_con` event processors, which together make up the implementation of the MTP `connect` function). Meanwhile, the Python receiver listens on `port` and once the connection is established, the TCP client sends to `ip:port` for `length` seconds. __TODO: Make this work. Milestone 2 in the Google Doc.__.

- `python recv.py wait [ip] [port]`
- `./client send [ip] [port] [length (seconds)]`

2. Receiver initiates connection (mTCP client listens on `port`, receiver sends a
start message to `ip:port`, and then mTCP client sends back to receiver for `length`
seconds). __Is the only functional mode, and is thus best to use this mode to test__, since in our thinking, we usually
treat the DPDK mTCP backend (what we misleadingly call the "client" here) as the _server_,
and the "python" in the second command below are the _receivers_ which initiate connections.

- `./client wait [ip] [port] [length (seconds)]`
- `python recv.py send [ip] [port]  # initiates connection and then receives payload from the server (called "client" above)`

3. Sender initiates connection (mTCP server listens on `port` and sender sends to
`ip:port` for `length` seconds)  __TODO: Make this work. Milestone 1 in the Google Doc.__.

- `./server wait [ip] [port]  # opens socket and waits for the connection`
- `python send.py send [ip] [port] [length (seconds)]  # initiates the connection and then sends payload to the server`

_NOTES_:

- If using CCP with mTCP, you will need to ensure that `LD_LIBRARY_PATH`
includes the path to libccp:
- In steps 2 and 3 above, `./client` and `./server` both are considered the "server" in the
client-server paradigm. The only difference between these executables is that the `client` executable
is made to _receive_ payloads, while the `server` is made to _send_ payloads. The naming is misleading
and should be ignored.

`export LD_LIBRARY_PATH=/path/to/mtcp/src/libccp:$LD_LIBRARY_PATH`

Even once this is in your user's local environment, you will probably need to
make sure it persists when running with sudo:

`sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH ./client ...`

Setup Notes
===========

1. Ensure the ARP table and routing table are populated correctly and located inside ./config/

2. Build this application by simply running make in this directory (apps/perf)

3. Assuming sender and receiver are on the same network and/or have a very low
   delay between them, add a netem qdisc for ingress traffic at the receiver
   (who is not running mTCP/DPDK) to simulate a reasonable delay for the link.
   To add 20 ms delay to interface ETH, use the included script as follows:

        ./add-delay.sh IFACE 20

    (you can also easily remove the qdiscs later with ./rm-delay.sh ETH)

4. Start mTCP perf client in wait mode, listening on, e.g., port 9000 and
sending for 30 seconds:

`sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH ./client wait 10.1.1.5 9000 30`

4. Start python receiver in send mode, where client ip is e.g. 10.1.1.5

`sudo python recv.py send 10.1.1.5 9000`
