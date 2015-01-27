import flow_dist_pb2

flow_dist_config = flow_dist_pb2.FlowDistConfig()
flow_dist_config.pcap_filename = '/home/nik/caida/uncompressed/equinix-chicago.dirA.20130529-125710.UTC.anon.pcap'
flow_dist_config.ewma_alpha = 0.9

f = open('flow_dist_input.pb', 'wb')
f.write(flow_dist_config.SerializeToString())
f.close()
