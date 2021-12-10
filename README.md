# Connection logger

## Overview

We aim to collect connection data at a router. For each
connection we want to collect 

 - the source IP and port,
 - the destination IP and port,
 - level 4 protocol,
 - number of packets sent and received,
 - number of kilobytes sent and received.

We will run the program on a host with Linux kernel equipped
with [PF_RING socket](http://www.ntop.org/products/packet-capture/pf_ring/),
and store logs locally for periodical retrieval. The data should
be stored in a space or comma-separated (CSV) log.
