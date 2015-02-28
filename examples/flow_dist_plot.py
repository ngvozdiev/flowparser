import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

import flow_dist_pb2
import sys
import datetime
from matplotlib.ticker import FuncFormatter
from collections import defaultdict
import math
import numpy as np

def timestamp_to_string(x, pos):
    return datetime.datetime.fromtimestamp(x / 1000.0 / 1000.0).strftime('%M:%S.%f')

flow_dist = flow_dist_pb2.FlowDist()
f = open(sys.argv[1], "rb")
flow_dist.ParseFromString(f.read())
f.close()

cfg = flow_dist.original_config
cfg_string = 'skip_count: ' + str(cfg.undersample_skip_count)

#print [(d.timestamp, d.total_tcp_syn_pkts_seen, d.total_flow_misses) for d in flow_dist.datapoints]

# plt.figure()
x = []
# rate_percentiles = defaultdict(list)
for datapoint in flow_dist.datapoints:
    x.append(datapoint.timestamp)
#     print datapoint.rate_percentiles
    
#     for i in [10,25,50,75,90,100]:
#         if not datapoint.rate_percentiles:
#             rate_percentiles[i].append(0)
#         else:
#             rate_percentiles[i].append(datapoint.rate_percentiles[i - 1] * 8)
# print rate_percentiles
        
# for p, y in sorted(rate_percentiles.items()):
#     plt.plot(x, y, label=str(p) + 'th percentile')

# plt.plot(x, [d.rate_mean * 8 for d in flow_dist.datapoints], label='mean')
# plt.axes().xaxis.set_major_formatter(FuncFormatter(timestamp_to_string))

# plt.yscale('symlog')
# lim = plt.ylim()
# if lim[0] != 0:
#     plt.ylim([0, lim[1]])

# plt.title('Flow rate distribution ' + cfg_string)
# plt.xlabel('time')
# plt.ylabel('bps')
# plt.legend()

plt.figure()

plt.plot(x, [d.payload_per_sec * 8 for d in flow_dist.datapoints], label='Total payload')
plt.plot(x, [d.ip_len_per_sec * 8 for d in flow_dist.datapoints], label='Total ip_len')
plt.plot(x, [d.tcp_payload_per_sec * 8 for d in flow_dist.datapoints], label='Total TCP payload')
#plt.plot(x, [d.total_rate * 8 for d in flow_dist.datapoints], label='Total est TCP rate')

plt.axes().xaxis.set_major_formatter(FuncFormatter(timestamp_to_string))
plt.legend()

plt.title('Payloads per second ' + cfg_string)
plt.xlabel('time')
plt.ylabel('bps')

lim = plt.ylim()
if lim[0] != 0:
    plt.ylim([0, lim[1]])

plt.figure()
y_hits = []
y_misses = []
y_pkts = []
prev_hits = None
prev_misses = None
prev_pkts = None
for datapoint in flow_dist.datapoints:
    hits = datapoint.total_flow_hits if prev_hits == None else datapoint.total_flow_hits - prev_hits
    misses = datapoint.total_flow_misses if prev_misses == None else datapoint.total_flow_misses - prev_misses
    pkts = datapoint.total_pkts_seen if prev_pkts == None else datapoint.total_pkts_seen - prev_pkts
    
    y_hits.append(hits)
    y_misses.append(misses)
    y_pkts.append(pkts)

    prev_hits = datapoint.total_flow_hits
    prev_misses = datapoint.total_flow_misses
    prev_pkts = datapoint.total_pkts_seen

plt.plot(x, y_hits, label='flow hits')
plt.plot(x, y_misses, label='flow misses')
plt.plot(x, y_pkts, label='pkts')
plt.axes().xaxis.set_major_formatter(FuncFormatter(timestamp_to_string))

plt.title('Hits/Misses/Total pkts per second ' + cfg_string)
plt.xlabel('time')
plt.ylabel('count')
plt.legend()

plt.figure()
y_flows = [p.total_flows_in_mem for p in flow_dist.datapoints]
y_tcp_flows = [p.total_tcp_flows_in_mem for p in flow_dist.datapoints]
y_udp_flows = [p.total_udp_flows_in_mem for p in flow_dist.datapoints]
y_icmp_flows = [p.total_icmp_flows_in_mem for p in flow_dist.datapoints]
#y_total_flows_est = [p.est_total_num_flows for p in flow_dist.datapoints]
plt.plot(x, y_flows, label='total flows in mem')
plt.plot(x, y_tcp_flows, label='TCP flows in mem')
plt.plot(x, y_udp_flows, label='UDP flows in mem')
plt.plot(x, y_icmp_flows, label='ICMP flows in mem')
#plt.plot(x, y_total_flows_est, label='total flows estimate')
plt.axes().xaxis.set_major_formatter(FuncFormatter(timestamp_to_string))
plt.xlabel('time')
plt.ylabel('count')
plt.title('Number of flows ' + cfg_string)
plt.legend()

plt.figure()
y_mem = [p.total_mem_usage_bytes for p in flow_dist.datapoints]
plt.plot(x, y_mem, label='mem usage')
plt.axes().xaxis.set_major_formatter(FuncFormatter(timestamp_to_string))
plt.xlabel('time')
plt.ylabel('bytes')
plt.title('Total memory usage ' + cfg_string)
plt.legend()

plt.figure()
x_active_flows = [datapoint.timestamp for datapoint in flow_dist.active_flows]
y_active_flows = [datapoint.count for datapoint in flow_dist.active_flows]
plt.plot(x_active_flows, y_active_flows, label='active flows')
plt.axes().xaxis.set_major_formatter(FuncFormatter(timestamp_to_string))
plt.xlabel('time')
plt.ylabel('number of active flows')
plt.title('Active flows ' + cfg_string)
plt.legend()

# plt.figure()

# clustered_sizes = defaultdict(list)
# clusters = defaultdict(list)
# probs = defaultdict(list)
# totals = []

# for datapoint in flow_dist.datapoints:
#     total = 0
#     i = 0
#     for cluster in datapoint.active_flows:
#         adjusted_flow_count = cluster.flow_count / cluster.see_prob
#         clustered_sizes[i].append(cluster.flow_count)
#         clusters[i].append(cluster.mean_flow_pkt_count)
#         probs[i].append(cluster.see_prob)
#         total += cluster.flow_count
#         i += 1

#     totals.append(total)

# print clustered_sizes

# for cluster_index, flow_counts in sorted(clustered_sizes.items()):
#     flow_size_mean = np.mean(clusters[cluster_index])
#     flow_std_dev = np.std(clusters[cluster_index])
#     prob_mean = np.mean(probs[cluster_index])

#     plt.plot(x, flow_counts, label = 'Flow sizes ' +
#              "{0:.2f}".format(flow_size_mean) + '/' +
#              "{0:.2f}".format(flow_std_dev) + '/' + "{0:.4f}".format(prob_mean))

# plt.plot(x, totals, label = 'Total')
# plt.axes().xaxis.set_major_formatter(FuncFormatter(timestamp_to_string))

# plt.xlabel('time')
# plt.ylabel('# flows')

# sec = flow_dist.original_config.lookback_period / 1000.0 / 1000.0

# plt.title('Active flows over the last ' + str(sec) + ' seconds ' + cfg_string)
# plt.legend()


plt.show()
