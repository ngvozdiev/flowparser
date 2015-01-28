import matplotlib.pylab as plt
import flow_dist_pb2
import sys
import datetime
from matplotlib.ticker import FuncFormatter
from collections import defaultdict

def timestamp_to_string(x, pos):
    return datetime.datetime.fromtimestamp(x / 1000.0 / 1000.0).strftime('%M:%S.%f')

flow_dist = flow_dist_pb2.FlowDist()

f = open(sys.argv[1], "rb")
flow_dist.ParseFromString(f.read())
f.close()

x = []
percentiles = defaultdict(list)
for datapoint in flow_dist.datapoints:
    x.append(datapoint.timestamp)
    for i in range(1, 101):
        percentiles[i].append(datapoint.rate_percentiles[i - 1])

for p, y in sorted(percentiles.items()):
    plt.plot(x, y)

plt.yscale('log')
plt.legend()

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

plt.figure()
y_flows = [p.total_flows_in_mem for p in flow_dist.datapoints]
plt.plot(x, y_flows, label='flows in mem')
plt.legend()

plt.figure()
y_mem = [p.total_mem_usage_bytes for p in flow_dist.datapoints]
plt.plot(x, y_mem, label='mem usage')
plt.legend()


plt.show()
