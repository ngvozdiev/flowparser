import flow_dist_pb2

flow_dist_config = flow_dist_pb2.FlowDistConfig()
flow_dist_config.pcap_filename = '/home/nik/caida/uncompressed/out_5min.pcap'
flow_dist_config.bpf_filter = 'not udp'
#flow_dist_config.pcap_filename = '/Users/nik/tmp/synthetic.pcap'
flow_dist_config.undersample_skip_count = 100
#flow_dist_config.tcp_rate_estimator_max_period_width = 5000000

f = open('flow_dist_input.pb', 'wb')
f.write(flow_dist_config.SerializeToString())
f.close()
