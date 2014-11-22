#include <sys/poll.h>

#include "flowparser.h"

namespace flowparser {

Status FlowParser::PcapOpen() {
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
    return "Could not open source " + config_.source_ + ", pcap said: "
        + std::string(errbuf);
  }

  int datalink = pcap_datalink(pcap_handle_);
  if (datalink == DLT_EN10MB) {
    datalink_offset_ = pcap::kSizeEthernet;
  } else if (datalink == DLT_RAW) {
    datalink_offset_ = 0;
  } else {
    return "Unknown datalink "
        + std::string(pcap_datalink_val_to_name(datalink));
  }

  if (!config_.offline_) {
    if (pcap_lookupnet(source, &net, &mask, errbuf) == -1) {
      return "Could not get netmask for device " + config_.source_
          + ", pcap said: " + std::string(errbuf);
    }

    if (pcap_setnonblock(pcap_handle_, 1, errbuf) == -1) {
      return "Could not set to non-blocking device " + config_.source_
          + ", pcap said: " + std::string(errbuf);
    }
  }

  if (pcap_compile(pcap_handle_, &fp, config_.bpf_filter_.c_str(), 0, net)
      == -1) {
    pcap_freecode(&fp);
    return "Could not parse filter " + config_.bpf_filter_ + ", pcap said: "
        + std::string(pcap_geterr(pcap_handle_));

  }

  if (pcap_setfilter(pcap_handle_, &fp) == -1) {
    pcap_freecode(&fp);
    return "Could not install filter " + config_.bpf_filter_ + ", pcap said: "
        + std::string(pcap_geterr(pcap_handle_));
  }

  pcap_freecode(&fp);
  return Status::kStatusOK;
}

Status FlowParser::HandleTcp(uint64_t timestamp, size_t size_ip,
                             const pcap::SniffIp& ip_header,
                             const uint8_t* pkt) {
  const pcap::SniffTcp* tcp_header = reinterpret_cast<const pcap::SniffTcp*>(pkt
      + datalink_offset_ + size_ip);

  size_t size_tcp = tcp_header->th_off * 4;
  if (size_tcp < 20) {
    return "TCP header too short";
  }

  UpdateFirstLastRx(timestamp);
  return tcp_parser_.HandlePkt(ip_header, *tcp_header, timestamp);
}

Status FlowParser::HandleUdp(const uint64_t timestamp, size_t size_ip,
                             const pcap::SniffIp& ip_header,
                             const uint8_t* pkt) {
  const pcap::SniffUdp* udp_header = reinterpret_cast<const pcap::SniffUdp*>(pkt
      + datalink_offset_ + size_ip);

  UpdateFirstLastRx(timestamp);
  return udp_parser_.HandlePkt(ip_header, *udp_header, timestamp);
}

Status FlowParser::HandleIcmp(const uint64_t timestamp, size_t size_ip,
                              const pcap::SniffIp& ip_header,
                              const uint8_t* pkt) {
  const pcap::SniffIcmp* icmp_header =
      reinterpret_cast<const pcap::SniffIcmp*>(pkt + datalink_offset_ + size_ip);

  UpdateFirstLastRx(timestamp);
  return icmp_parser_.HandlePkt(ip_header, *icmp_header, timestamp);
}

Status FlowParser::HandleUnknown(const uint64_t timestamp, size_t size_ip,
                                 const pcap::SniffIp& ip_header) {
  static pcap::SniffUnknown dummy_header;

  UpdateFirstLastRx(timestamp);
  return unknown_parser_.HandlePkt(ip_header, dummy_header, timestamp);
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

  size_t size_ip = ip_header->ip_hl * 4;
  if (size_ip < 20) {
    fparser->HandleBadStatus(
        "Invalid IP header length: " + std::to_string(size_ip)
            + " bytes, pcap header len: " + std::to_string(header->len));
    return;
  }

  if (ip_header->ip_p == IPPROTO_TCP) {
    Status status = fparser->HandleTcp(timestamp, size_ip, *ip_header, packet);
    if (!status.ok()) {
      fparser->HandleBadStatus(status);
    }

    return;
  }

  if (ip_header->ip_p == IPPROTO_UDP) {
    Status status = fparser->HandleUdp(timestamp, size_ip, *ip_header, packet);
    if (!status.ok()) {
      fparser->HandleBadStatus(status);
    }

    return;
  }

  if (ip_header->ip_p == IPPROTO_ICMP) {
    Status status = fparser->HandleIcmp(timestamp, size_ip, *ip_header, packet);
    if (!status.ok()) {
      fparser->HandleBadStatus(status);
    }

    return;
  }

  // All other protocol go to unknown.
  Status status = fparser->HandleUnknown(timestamp, size_ip, *ip_header);
  if (!status.ok()) {
    fparser->HandleBadStatus(status);
  }
}

void FlowParser::PcapLoop() {
  int ret;

  int poll_result;
  pollfd pfd;

  if (config_.offline_) {
    config_.info_callback_("Will start reading from " + config_.source_);

    ret = pcap_loop(pcap_handle_, -1, HandlePkt,
                    reinterpret_cast<u_char*>(this));

    if (ret == 0) {
      config_.info_callback_("Done reading from " + config_.source_);
    } else {
      config_.bad_status_callback_(
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
          config_.bad_status_callback_("Bad poll on pcap fd");
          return;

        case 0:  // timeout
          break;

        default:  // packet
          pcap_dispatch(pcap_handle_, -1, HandlePkt,
                        reinterpret_cast<u_char*>(this));
      }
    }
  }
}

}
