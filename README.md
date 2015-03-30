flowparser
==========

Flowparser is a tool for parsing TCP/UDP flows from a live trace or a pcap file. It acts like NetFlow, but runs on any Unix-like system and has the added ability to track specific header fields in flows and read .pcap files.

Requirements
------------

Flowparser is a C++ library, and a reasonalby modern c++11 compiler is needed to compile it. It also requires libpcap. Currently it should compile cleanly and work on Linux and OSX.

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

Usage
-----

Imagine you have a big .pcap file and you want to find out what flows are longer than 10sec and carry more than 100MB goodput (application-layer payload). Here is a short self-contained example to do this using Flowparser:

    #include <flowparser/flowparser.h>
    #include <iostream>
    #include <memory>
    #include <string>
    #include <thread>
    
    using flowparser::Flow;
    using flowparser::FlowParserConfig;
    using flowparser::FlowParser;
    using flowparser::FlowInfo;
    
    static uint64_t kTenSeconds = 10000000; // microseconds
    static uint64_t kTenMB = 100000000; // bytes
    
    int main(int argc, char *argv[]) {
      if (argc != 2) {
        std::cout << "Supply exactly one argument.\n";
        return -1;
      }
    
      std::string filename(argv[1]);
    
      FlowParserConfig fp_cfg;
      fp_cfg.OfflineTrace(filename);
    
      auto queue_ptr = std::make_shared<flowparser::Parser::FlowQueue>();
      fp_cfg.FlowQueue(queue_ptr);
    
      FlowParser fp(fp_cfg);
    
      std::thread th([&queue_ptr] {
        while (true) {
          std::unique_ptr<Flow> flow_ptr = queue_ptr->ConsumeOrBlock();
          if (!flow_ptr) {
            break;
          }
    
          FlowInfo info = flow_ptr->GetInfo();
          uint64_t duration = info.last_rx - info.first_rx;
          if (duration < kTenSeconds || info.total_payload_seen < kTenMB) {
            continue;
          }
    
          std::cout << flow_ptr->key().ToString() << "\n";
        }
      });
    
      fp.RunTrace();
      th.join();
      return 0;
    }

You can compile this (assuming it is saved in example_one.cc) with

    g++ -g -std=c++11 -Wall -Wextra -O2 -c -o example_one.o example_one.cc
    g++ example_one.o -o example_one -g -lflowparser -lpcap
    
