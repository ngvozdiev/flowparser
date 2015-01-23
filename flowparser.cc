#include "flowparser.h"

#include <netinet/in.h>
#include <pcap/bpf.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <sys/types.h>
#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

namespace flowparser {

void FlowParser::PcapOpen() {
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  bpf_u_int32 mask = 0;
  bpf_u_int32 net = 0;

  // A c-style string for the source.
  const char* source = config_.source_.c_str();

  if (config_.offline_) {
    pcap_handle_ = pcap_open_offline(source, errbuf);
  } else {
    pcap_handle_ = pcap_open_live(source, config_.snapshot_len_, 1, 1000,
                                  errbuf);
  }

  if (pcap_handle_ == nullptr) {
    throw std::logic_error(
        "Could not open source " + config_.source_ + ", pcap said: "
            + std::string(errbuf));
  }

  int datalink = pcap_datalink(pcap_handle_);
  if (datalink == DLT_EN10MB) {
    datalink_offset_ = pcap::kSizeEthernet;
  } else if (datalink == DLT_RAW) {
    datalink_offset_ = 0;
  } else {
    throw std::logic_error(
        "Unknown datalink " + std::string(pcap_datalink_val_to_name(datalink)));
  }

  if (!config_.offline_) {
    if (pcap_lookupnet(source, &net, &mask, errbuf) == -1) {
      throw std::logic_error(
          "Could not get netmask for device " + config_.source_
              + ", pcap said: " + std::string(errbuf));
    }

    if (pcap_setnonblock(pcap_handle_, 1, errbuf) == -1) {
      throw std::logic_error(
          "Could not set to non-blocking device " + config_.source_
              + ", pcap said: " + std::string(errbuf));
    }
  }

  if (pcap_compile(pcap_handle_, &fp, config_.bpf_filter_.c_str(), 0, net)
      == -1) {
    pcap_freecode(&fp);
    throw std::logic_error(
        "Could not parse filter " + config_.bpf_filter_ + ", pcap said: "
            + std::string(pcap_geterr(pcap_handle_)));

  }

  if (pcap_setfilter(pcap_handle_, &fp) == -1) {
    pcap_freecode(&fp);
    throw std::logic_error(
        "Could not install filter " + config_.bpf_filter_ + ", pcap said: "
            + std::string(pcap_geterr(pcap_handle_)));
  }

  pcap_freecode(&fp);
}

void FlowParser::HandleTcp(uint64_t timestamp, size_t size_ip,
                           const pcap::SniffIp& ip_header, const uint8_t* pkt) {
  const pcap::SniffTcp* tcp_header = reinterpret_cast<const pcap::SniffTcp*>(pkt
      + datalink_offset_ + size_ip);

  size_t size_tcp = tcp_header->th_off * 4;
  if (size_tcp < 20) {
    throw std::logic_error("TCP header too short");
  }

  parser_.TCPIpRx(ip_header, *tcp_header, timestamp);
}

void FlowParser::HandleUdp(const uint64_t timestamp, size_t size_ip,
                           const pcap::SniffIp& ip_header, const uint8_t* pkt) {
  const pcap::SniffUdp* udp_header = reinterpret_cast<const pcap::SniffUdp*>(pkt
      + datalink_offset_ + size_ip);

  parser_.UDPIpRx(ip_header, *udp_header, timestamp);
}

void FlowParser::HandleIcmp(const uint64_t timestamp, size_t size_ip,
                            const pcap::SniffIp& ip_header,
                            const uint8_t* pkt) {
  const pcap::SniffIcmp* icmp_header =
      reinterpret_cast<const pcap::SniffIcmp*>(pkt + datalink_offset_ + size_ip);

  parser_.ICMPIpRx(ip_header, *icmp_header, timestamp);
}

void FlowParser::HandleUnknown(const uint64_t timestamp,
                               const pcap::SniffIp& ip_header) {
  parser_.UnknownIpRx(ip_header, timestamp);
}

// Called to handle a single packet. Will dispatch it to HandleTcp or
// HandleUdp.This is in a free function because the pcap library expects an
// unbound function pointer
static void HandlePkt(u_char* flow_parser, const struct pcap_pkthdr* header,
                      const u_char* packet) {
  FlowParser* fparser = reinterpret_cast<FlowParser*>(flow_parser);

  uint64_t timestamp = static_cast<uint64_t>(header->ts.tv_sec) * kMillion
      + static_cast<uint64_t>(header->ts.tv_usec);

  const pcap::SniffIp* ip_header = reinterpret_cast<const pcap::SniffIp*>(packet
      + fparser->datalink_offset());

  try {
    size_t size_ip = ip_header->ip_hl * 4;
    if (size_ip < 20) {
      throw std::logic_error(
          "Invalid IP header length: " + std::to_string(size_ip)
              + " bytes, pcap header len: " + std::to_string(header->len));
    }

    switch (ip_header->ip_p) {
      case IPPROTO_TCP:
        fparser->HandleTcp(timestamp, size_ip, *ip_header, packet);
        break;
      case IPPROTO_UDP:
        fparser->HandleUdp(timestamp, size_ip, *ip_header, packet);
        break;
      case IPPROTO_ICMP:
        fparser->HandleIcmp(timestamp, size_ip, *ip_header, packet);
        break;
      default:
        fparser->HandleUnknown(timestamp, *ip_header);
    }
  } catch (std::exception& ex) {
    fparser->HandleException(ex);
  }
}

void FlowParser::PcapLoop() {
  int ret;

  int poll_result;
  pollfd pfd;
  try {
    if (config_.offline_) {
      config_.info_callback_("Will start reading from " + config_.source_);

      ret = pcap_loop(pcap_handle_, -1, HandlePkt,
                      reinterpret_cast<u_char*>(this));
      if (ret == 0) {
        config_.info_callback_("Done reading from " + config_.source_);
      } else {
        throw std::logic_error(
            "Error while reading from " + config_.source_ + ", pcap said: "
                + std::string(pcap_geterr(pcap_handle_)));
      }
    } else {
      config_.info_callback_("Will start listening on " + config_.source_);

      pfd.fd = pcap_fileno(pcap_handle_);
      pfd.events = POLLIN;

      while (true) {
        poll_result = poll(&pfd, 1, 1000);

        switch (poll_result) {
          case -1:  // error
            throw std::logic_error("Bad poll on pcap fd");

          case 0:  // timeout
            break;

          default:  // packet
            pcap_dispatch(pcap_handle_, -1, HandlePkt,
                          reinterpret_cast<u_char*>(this));
        }
      }
    }
  } catch (std::exception& ex) {
    config_.ex_callback_(ex);
  }
}

}
