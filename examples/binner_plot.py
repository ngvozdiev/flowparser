import matplotlib.pylab as plt
import binner_pb2
import sys

binned_flows = binner_pb2.BinnedFlows()

f = open(sys.argv[1], "rb")
binned_flows.ParseFromString(f.read())
f.close()

for bin_pack in binned_flows.bin_packs:
    plt.figure()
    
    start = bin_pack.bins_start
    x = [start + k * bin_pack.bin_width for k in range(bin_pack.num_bins)]

    #print '\tBP type', bin_pack.type
    #print '\tBP start', bin_pack.bins_start
    #print '\tBP bin width', bin_pack.bin_width
    #print '\tBP num bins', bin_pack.num_bins
    total_max = 0

    for binned_values in bin_pack.values:
        max_value = max(binned_values.bins)
        if max_value > total_max:
            total_max = max_value
        
    for binned_values in bin_pack.values:
        max_value = max(binned_values.bins)
        if max_value < float(total_max) * 0.02:
            continue

        label = binner_pb2.FlowType.Name(binned_values.type)
        plt.plot(x, binned_values.bins, label=label)
        #print '\t\tValues', binned_values.bins

        plt.legend()
plt.show()
