flowparser
==========

Flowparser is a tool for parsing TCP/UDP flows from a live trace or a pcap file. It acts like NetFlow, but with the added ability to track specific header fields in flows.

Installation
------------

After cloning the repository you can compile by:

    ./autoreconf --install
    ./configure
    make

To run the tests do:

    make check
  
After compiling you should have a .so file that you can link agains. To do a system-wide install the library and all headers do:

    make install
