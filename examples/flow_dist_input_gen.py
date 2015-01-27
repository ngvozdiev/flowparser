import flow_dist_pb2

flow_dist_config = flow_dist_pb2.FlowDistConfig()
flow_dist_config.pcap_filename = '/Users/nik/out'
flow_dist_config.ewma_alpha = 1

f = open('flow_dist_input.pb', 'wb')
f.write(flow_dist_config.SerializeToString())
f.close()
