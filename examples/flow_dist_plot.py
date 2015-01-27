import matplotlib.pylab as plt
import flow_dist_pb2
import sys
import datetime
import numpy as np
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
    for i in [10,25,50,75,90,100]:
        p = np.percentile(datapoint.flow_rates, i)
        percentiles[i].append(p)

for p, y in sorted(percentiles.items()):
    plt.plot(x, y, 'o', label = str(p) + 'th percentile')

plt.yscale('log')
plt.legend()
plt.show()
